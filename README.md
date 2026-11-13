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

The crate is `no_std` (it needs `alloc`) and adds no dependencies beyond LibAFL.

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
mutations.

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

Here the `-p` after `--` is `luac`'s parse-only flag.

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
