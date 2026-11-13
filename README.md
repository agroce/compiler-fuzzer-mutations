# compiler-fuzzer-mutations

Mutation-testing-style source mutations for [LibAFL](https://github.com/AFLplusplus/LibAFL),
for fuzzing compilers, interpreters, and other tools whose inputs are programs
in a C-like language (C, C++, Java, JavaScript, Rust, Solidity, Lua, ...).

This is a port of the mutations of
[afl-compiler-fuzzer](https://github.com/agroce/afl-compiler-fuzzer), described in
[Making No-Fuss Compiler Fuzzing Effective](https://agroce.github.io/cc22.pdf)
(Groce, van Tonder, Kalburgi, Le Goues; CC 2022). The same mutations are
available for AFL++ as the
[`compiler_fuzzer` custom mutator](https://github.com/AFLplusplus/AFLplusplus/tree/dev/custom_mutators/compiler_fuzzer).

The operators are the kind used in mutation testing: operator replacement,
statement deletion, argument and statement swaps, loop insertion, duplication
of lines and blocks, and so on. Mutants of valid programs tend to stay valid,
or nearly so, so the fuzzer spends its time past the target's parser without
needing a grammar.

## Usage

```toml
[dependencies]
compiler-fuzzer-mutations = "0.1"
```

`MutationTestingMutator` is an ordinary LibAFL `Mutator` for byte inputs. In
afl-compiler-fuzzer, about 75% of stacked havoc steps were source mutations and
the rest were ordinary havoc mutations. To get the same mix, schedule it
together with `havoc_mutations()` in a `TuneableScheduledMutator`:

```rust
use compiler_fuzzer_mutations::MutationTestingMutator;
use libafl::mutators::{TuneableScheduledMutator, havoc_mutations};
use libafl_bolts::{HasLen, tuples::{Merge, tuple_list}};

let mutations = tuple_list!(MutationTestingMutator::new()).merge(havoc_mutations());
let havoc_count = mutations.len() - 1;
let mutator = TuneableScheduledMutator::new(&mut state, mutations);
let mut probabilities = vec![0.75];
probabilities.extend(std::iter::repeat_n(0.25 / havoc_count as f32, havoc_count));
mutator.set_mutation_probabilities(&mut state, probabilities)?;
```

The crate adds no dependencies beyond LibAFL (and `log`, which LibAFL already
uses). `MutationTestingMutator` is `no_std` (it needs `alloc`); for a `no_std`
build, turn off the default `comby` feature:

```toml
compiler-fuzzer-mutations = { version = "0.1", default-features = false }
```

## comby-decomposer

`CombyMutator` (the `comby` feature, on by default) is afl-compiler-fuzzer's
other mode. It sends the input to a
[comby-decomposer](https://github.com/comby-tools/comby-decomposer) server,
which answers with a new program built from templates and fragments of a
corpus of valid programs, and replaces the input with it. If the server is
down or a request fails, the mutation is skipped and fuzzing goes on; the first
failure is logged as a warning.

Each request replaces the whole input, so the mutator makes at most one request
per execution. Requests are also far slower than executions, so give it a small
share of the stacked steps, as an extra entry in the `TuneableScheduledMutator`:

```rust
use compiler_fuzzer_mutations::{CombyMutator, DEFAULT_COMBY_PORT, MutationTestingMutator};

let comby = CombyMutator::new("127.0.0.1", DEFAULT_COMBY_PORT)?;
let mutations = tuple_list!(MutationTestingMutator::new(), comby).merge(havoc_mutations());
let havoc_count = mutations.len() - 2;
let mutator = TuneableScheduledMutator::new(&mut state, mutations);
let mut probabilities = vec![0.75, 0.003];
probabilities.extend(std::iter::repeat_n((1.0 - 0.753) / havoc_count as f32, havoc_count));
mutator.set_mutation_probabilities(&mut state, probabilities)?;
```

With LibAFL's default stacking (up to 128 steps, about 36 on average), a
per-step probability of 0.002 to 0.005 means roughly 7 to 17% of executions
ask the server for a program. On the Lua parser, with the server and the
fuzzer sharing two cores, the server answered about 140 requests per second
while the fuzzer alone ran about 2,000 executions per second.

To run the server, follow the comby-decomposer README (decompose your seeds,
then start `server.js --generate 1.0`), and give Node a larger stack, or many
requests fail with `Stack_overflow`:

```sh
ulimit -s unlimited
node --stack-size=60000 server.js --generate 1.0
```

## Example

`examples/forkserver.rs` fuzzes an `afl-cc` instrumented executable with that
setup. Build [AFL++](https://github.com/AFLplusplus/AFLplusplus) first, then:

```sh
/path/to/AFLplusplus/afl-cc -o program examples/program.c
cargo run --release --example forkserver -- ./program ./examples/corpus -t 1000 -- @@
```

`examples/program.c` stands in for a compiler: it crashes on programs with an
`if (x ... != 0` guard. Reaching that from `examples/corpus/seed.c`, which has
`while (x == 0)`, takes two source-level edits. With the default settings the
crash is usually found within seconds; with `-p 0` (havoc only) it usually is
not. `-p` (`--source-prob`) sets the fraction of stacked steps that are source
mutations, and `-c` (`--comby-prob`, default 0) the fraction that ask a
comby-decomposer server (`--comby-host`, `--comby-port`) for a new program.

For a real target, use valid programs as seeds, such as the target's test
suite. For example, for the Lua compiler (parse and compile only, so mutants
are never run):

```sh
curl -LO https://www.lua.org/ftp/lua-5.4.7.tar.gz && tar xzf lua-5.4.7.tar.gz
make -C lua-5.4.7 linux CC=/path/to/AFLplusplus/afl-cc
curl -LO https://www.lua.org/tests/lua-5.4.7-tests.tar.gz && tar xzf lua-5.4.7-tests.tar.gz
mkdir seeds && find lua-5.4.7-tests -name '*.lua' -size -10k -exec cp {} seeds/ \;

cargo run --release --example forkserver -- lua-5.4.7/src/luac ./seeds -t 1000 -- -p @@
```

Here the `-p` after `--` is `luac`'s parse-only flag. To add comby, with a
server running on the default port, put `-c 0.003` before the `--`.

## The mutations

On each call, a random position and one of 64 operators are chosen, and the
operator is applied at its first match at or after that position; up to 16
attempts are made.

* Replacements: `==`, `!=`, `<`, `>`, `=` swaps; arithmetic operator swaps
  among `+ - * / %`; `++`/`--`; `&&`/`||`; `0`/`1`; `if`/`while`; `(` to `(!`;
  deleting `!`.
* Insertions after a newline: `if (0==1)` (semantic deletion of the next
  statement), `while(1==1)`, `break;`, `continue;`.
* Deletions: a statement after `;` or `}`, a `{...}` block (or its contents),
  a line, a space-delimited token such as `const`.
* Swaps: adjacent statements, comma-separated arguments, space-separated
  tokens.
* Duplication of a line, or of a construct ending in `}` such as a loop.

Matching is textual: delimiters are not nesting-aware, and delimited spans are
limited to 1024 bytes. This version includes the fixes made to
afl-compiler-fuzzer after the CC 2022 paper (`while` to `if` was never applied,
and the two duplication operators were no-ops).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
