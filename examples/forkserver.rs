use core::time::Duration;
use std::path::PathBuf;

use clap::Parser;
use compiler_fuzzer_mutations::{CombyMutator, DEFAULT_COMBY_PORT, MutationTestingMutator};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{HasObservers, StdChildArgs, forkserver::ForkserverExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{TuneableScheduledMutator, havoc_mutations},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    HasLen, StdTargetArgs, Truncate, current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{Handled, Merge, tuple_list},
};
use nix::sys::signal::Signal;

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "forkserver",
    about = "Fuzzes an afl-cc instrumented compiler or interpreter with mutation-testing-style source mutations mixed into havoc."
)]
struct Opt {
    #[arg(
        help = "The instrumented binary we want to fuzz",
        name = "EXEC",
        required = true
    )]
    executable: String,

    #[arg(
        help = "The directory to read initial inputs from ('seeds')",
        name = "INPUT_DIR",
        required = true
    )]
    in_dir: PathBuf,

    #[arg(
        help = "Timeout for each individual execution, in milliseconds",
        short = 't',
        long = "timeout",
        default_value = "1200"
    )]
    timeout: u64,

    #[arg(
        help = "If not set, the child's stdout and stderror will be redirected to /dev/null",
        short = 'd',
        long = "debug-child",
        default_value = "false"
    )]
    debug_child: bool,

    #[arg(
        help = "Fraction of stacked havoc steps that apply a source-level mutation",
        short = 'p',
        long = "source-prob",
        default_value = "0.75"
    )]
    source_prob: f32,

    #[arg(
        help = "Fraction of stacked havoc steps that ask a comby-decomposer server for a new program (0: off)",
        short = 'c',
        long = "comby-prob",
        default_value = "0"
    )]
    comby_prob: f32,

    #[arg(
        help = "comby-decomposer server host",
        long = "comby-host",
        default_value = "127.0.0.1"
    )]
    comby_host: String,

    #[arg(help = "comby-decomposer server port", long = "comby-port", default_value_t = DEFAULT_COMBY_PORT)]
    comby_port: u16,

    #[arg(
        help = "Arguments passed to the target",
        name = "arguments",
        num_args(1..),
        allow_hyphen_values = true,
    )]
    arguments: Vec<String>,

    #[arg(
        help = "Signal used to stop child",
        short = 's',
        long = "signal",
        value_parser = str::parse::<Signal>,
        default_value = "SIGKILL"
    )]
    signal: Signal,
}

pub fn main() {
    env_logger::init();
    const MAP_SIZE: usize = 65536;

    let opt = Opt::parse();
    assert!(
        opt.source_prob >= 0.0 && opt.comby_prob >= 0.0 && opt.source_prob + opt.comby_prob <= 1.0,
        "--source-prob and --comby-prob must be at least 0, and add up to at most 1"
    );

    let corpus_dirs: Vec<PathBuf> = [opt.in_dir].to_vec();

    // The unix shmem provider supported by AFL++ for shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let the forkserver know the shmid
    unsafe {
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
    }
    let shmem_buf = &mut shmem[..];

    // Create an observation channel using the signals map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let mut objective = feedback_and_fast!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it only if trigger new coverage over crashes
        // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::<BytesInput>::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // If we should debug the child
    let debug_child = opt.debug_child;

    // Create the executor for the forkserver
    let args = opt.arguments;

    let observer_ref = edges_observer.handle();

    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable)
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(args)
        .coverage_map_size(MAP_SIZE)
        .timeout(Duration::from_millis(opt.timeout))
        .kill_signal(opt.signal)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    if let Some(dynamic_map_size) = executor.coverage_map_size() {
        executor.observers_mut()[&observer_ref]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!("Failed to load initial corpus at {corpus_dirs:?}: {err:?}")
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // The source-level operators, the comby server, and ordinary havoc, as in
    // afl-compiler-fuzzer: each stacked step is a source mutation with
    // probability `source_prob`, a request to the comby server with probability
    // `comby_prob`, and otherwise one of the havoc mutations, chosen uniformly.
    let comby = CombyMutator::new(&opt.comby_host, opt.comby_port).unwrap();
    let mutations = tuple_list!(MutationTestingMutator::new(), comby).merge(havoc_mutations());
    let havoc_count = mutations.len() - 2;
    let mutator = TuneableScheduledMutator::new(&mut state, mutations);
    let mut probabilities = vec![opt.source_prob, opt.comby_prob];
    probabilities.extend(std::iter::repeat_n(
        (1.0 - opt.source_prob - opt.comby_prob) / havoc_count as f32,
        havoc_count,
    ));
    mutator
        .set_mutation_probabilities(&mut state, probabilities)
        .unwrap();
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
