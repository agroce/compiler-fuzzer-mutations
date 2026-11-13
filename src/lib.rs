//! Mutation-testing-style source mutations for [LibAFL](https://github.com/AFLplusplus/LibAFL),
//! for fuzzing compilers, interpreters, and other tools whose inputs are
//! programs in a C-like language.
//!
//! This is a port of the string mutations of
//! [afl-compiler-fuzzer](https://github.com/agroce/afl-compiler-fuzzer), from
//! "Making No-Fuss Compiler Fuzzing Effective" (Groce, van Tonder, Kalburgi,
//! Le Goues; CC 2022). The operators are the kind used in mutation testing:
//! operator replacement, statement deletion, argument and statement swaps,
//! loop insertion, duplication, and so on. Mutants of valid programs tend to
//! stay valid, or nearly so, which keeps the fuzzer past the target's parser
//! without a grammar.
//!
//! [`MutationTestingMutator`] applies one such operator per call. In
//! afl-compiler-fuzzer, about 75% of stacked havoc steps were source mutations
//! and the rest were ordinary havoc mutations. To get the same mix, put the
//! mutator in a [`libafl::mutators::TuneableScheduledMutator`] together with
//! [`libafl::mutators::havoc_mutations()`] and give it most of the probability
//! mass, as `examples/forkserver.rs` does:
//!
//! ```ignore
//! let mutations = tuple_list!(MutationTestingMutator::new()).merge(havoc_mutations());
//! let havoc_count = mutations.len() - 1;
//! let mutator = TuneableScheduledMutator::new(&mut state, mutations);
//! let mut probabilities = vec![0.75];
//! probabilities.extend(std::iter::repeat_n(0.25 / havoc_count as f32, havoc_count));
//! mutator.set_mutation_probabilities(&mut state, probabilities)?;
//! ```
//!
//! Matching is textual: delimiters are not nesting-aware, and delimited spans
//! are limited to [`MAX_MUTANT_CHANGE`] bytes.
//!
//! With the `comby` feature (on by default; it needs `std`), [`CombyMutator`]
//! adds afl-compiler-fuzzer's other mode: replacing the input with a program
//! from a [comby-decomposer](https://github.com/comby-tools/comby-decomposer)
//! server.

#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, vec::Vec};
use core::num::NonZero;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::{HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator},
    nonzero,
    state::{HasMaxSize, HasRand},
};
use libafl_bolts::{Named, rands::Rand};

#[cfg(feature = "comby")]
extern crate std;

#[cfg(feature = "comby")]
pub mod comby;
#[cfg(feature = "comby")]
pub use comby::{CombyMutator, DEFAULT_COMBY_PORT};

/// Maximum length, in bytes, of a span matched by a delimiter-based operator.
pub const MAX_MUTANT_CHANGE: usize = 1024;

/// How many (position, operator) pairs to try before giving up on an input.
const MAX_TRIES: usize = 16;

/// A single source-level operator.
#[derive(Debug, Clone, Copy)]
enum Rule {
    /// Replace the first occurrence of `.0` (at or after the position) with `.1`.
    Replace(&'static [u8], &'static [u8]),
    /// Replace the span from the delimiter `.0` to the next `.1`, inclusive, with `.2`.
    DelimReplace(u8, u8, &'static [u8]),
    /// Duplicate the span from the delimiter `.0` to the next `.1`, inclusive.
    DelimDup(u8, u8),
    /// `l A m B r` becomes `l B m A r`, for delimiters `(l, m, r)`.
    DelimSwap(u8, u8, u8),
}

use Rule::{DelimDup, DelimReplace, DelimSwap, Replace};

/// The operators of afl-compiler-fuzzer, in its order.
static RULES: [Rule; 64] = [
    Replace(b"\n", b"\nif (0==1)\n"), // semantic deletion of the next statement
    Replace(b"(", b"(!"),
    Replace(b"==", b"!="),
    Replace(b"!=", b"=="),
    Replace(b"==", b"<"),
    Replace(b"<", b"=="),
    Replace(b"==", b">"),
    Replace(b">", b"=="),
    Replace(b"=", b"<"),
    Replace(b"=", b">"),
    Replace(b"<", b">"),
    Replace(b">", b"<"),
    Replace(b"++", b"--"),
    Replace(b"--", b"++"),
    Replace(b"+", b"-"),
    Replace(b"+", b"*"),
    Replace(b"+", b"/"),
    Replace(b"+", b"%"),
    Replace(b"*", b"-"),
    Replace(b"*", b"+"),
    Replace(b"*", b"/"),
    Replace(b"*", b"%"),
    Replace(b"-", b"+"),
    Replace(b"-", b"*"),
    Replace(b"-", b"/"),
    Replace(b"-", b"%"),
    Replace(b"/", b"-"),
    Replace(b"/", b"*"),
    Replace(b"/", b"+"),
    Replace(b"/", b"%"),
    Replace(b"%", b"-"),
    Replace(b"%", b"*"),
    Replace(b"%", b"/"),
    Replace(b"%", b"+"),
    Replace(b"\n", b"\nbreak;\n"),
    Replace(b"\n", b"\ncontinue;\n"),
    Replace(b"0", b"1"),
    Replace(b"1", b"0"),
    Replace(b"if", b"while"),
    Replace(b"while", b"if"),
    Replace(b"\n", b"\nwhile(1==1)\n"),
    Replace(b"&&", b"||"),
    Replace(b"||", b"&&"),
    Replace(b"!", b""),
    DelimReplace(b';', b';', b";"), // remove a statement after a semicolon
    DelimReplace(b'}', b';', b"}"), // remove a statement after a right brace
    DelimReplace(b'{', b'}', b""),  // remove a (non-nested) brace construct
    DelimReplace(b'{', b'}', b"{}"), // empty a (non-nested) brace construct
    DelimSwap(b';', b';', b';'),    // swap adjacent statements
    DelimSwap(b'}', b';', b';'),
    DelimSwap(b'(', b',', b')'), // swap comma-delimited things
    DelimSwap(b'(', b',', b','),
    DelimSwap(b',', b',', b','),
    DelimSwap(b',', b',', b')'),
    DelimReplace(b'\n', b'\n', b""), // delete a line
    DelimReplace(b' ', b' ', b""),   // delete something like "const"
    DelimReplace(b'\n', b' ', b""),
    DelimReplace(b'(', b' ', b""),
    DelimSwap(b' ', b' ', b' '), // swap space-delimited things
    DelimSwap(b' ', b' ', b')'),
    DelimSwap(b'(', b' ', b' '),
    DelimSwap(b'(', b' ', b')'),
    DelimDup(b'\n', b'\n'), // duplicate a line
    DelimDup(b'\n', b'}'),  // duplicate a construct, e.g. a loop
];

/// Index of the first `c` in `buf[from..to]`.
fn find_byte(buf: &[u8], from: usize, to: usize, c: u8) -> Option<usize> {
    if from >= to {
        return None;
    }
    buf[from..to].iter().position(|&b| b == c).map(|i| from + i)
}

/// Index of the first occurrence of `needle` in `buf[from..]`.
fn find_bytes(buf: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from + needle.len() > buf.len() {
        return None;
    }
    buf[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| from + i)
}

/// Where and how `rule` applies to `buf` at or after `pos`: the byte range to
/// replace, and its replacement. `None` if the rule does not apply.
fn apply(rule: Rule, buf: &[u8], pos: usize) -> Option<(usize, usize, Vec<u8>)> {
    if let Replace(from, to) = rule {
        let at = find_bytes(buf, pos, from)?;
        return Some((at, at + from.len(), to.to_vec()));
    }

    let (left, mid, right) = match rule {
        DelimReplace(left, right, _) | DelimDup(left, right) => (left, None, right),
        DelimSwap(left, mid, right) => (left, Some(mid), right),
        Replace(..) => unreachable!(),
    };

    // Anchor on the first left delimiter at or after pos, then look for the
    // other delimiter(s) within MAX_MUTANT_CHANGE bytes.
    let open = find_byte(buf, pos, buf.len(), left)?;
    if open + 2 >= buf.len() {
        return None;
    }
    let limit = buf.len().min(open + MAX_MUTANT_CHANGE);

    if let Some(mid) = mid {
        let mid_at = find_byte(buf, open + 1, limit, mid)?;
        let close = find_byte(buf, mid_at + 1, limit, right)?;
        // buf[open+1 ..= close] is `A mid B right`; it becomes `B mid A right`.
        let mut rep = Vec::with_capacity(close - open);
        rep.extend_from_slice(&buf[mid_at + 1..close]);
        rep.push(mid);
        rep.extend_from_slice(&buf[open + 1..mid_at]);
        rep.push(right);
        return Some((open + 1, close + 1, rep));
    }

    let close = find_byte(buf, open + 1, limit, right)?;
    let span = &buf[open..=close];
    let rep = match rule {
        DelimReplace(_, _, with) => with.to_vec(),
        _ => [span, span].concat(),
    };
    Some((open, close + 1, rep))
}

/// Applies one mutation-testing-style source operator (from afl-compiler-fuzzer)
/// to the input, such as `==` to `!=`, deleting a statement, or swapping two
/// arguments. See the [module documentation](self).
#[derive(Debug, Default, Clone, Copy)]
pub struct MutationTestingMutator;

impl MutationTestingMutator {
    /// Creates a new [`MutationTestingMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<I, S> Mutator<I, S> for MutationTestingMutator
where
    S: HasRand + HasMaxSize,
    I: ResizableMutator<u8> + HasMutatorBytes,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let len = input.mutator_bytes().len();
        // len - 1 is nonzero for len >= 2.
        let Some(positions) = NonZero::new(len.saturating_sub(1)) else {
            return Ok(MutationResult::Skipped);
        };
        let max_size = state.max_size();

        for _ in 0..MAX_TRIES {
            let pos = state.rand_mut().below(positions);
            let rule = RULES[state.rand_mut().below(nonzero!(RULES.len()))];
            let Some((start, end, rep)) = apply(rule, input.mutator_bytes(), pos) else {
                continue;
            };
            let new_len = len - (end - start) + rep.len();
            if new_len == 0 || new_len > max_size {
                continue;
            }
            input.splice(start..end, rep);
            return Ok(MutationResult::Mutated);
        }

        Ok(MutationResult::Skipped)
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for MutationTestingMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("MutationTestingMutator");
        &NAME
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use libafl::{
        inputs::{BytesInput, HasMutatorBytes},
        mutators::{MutationResult, Mutator},
        state::NopState,
    };

    use super::{MAX_MUTANT_CHANGE, MutationTestingMutator, RULES, apply};

    /// Applies rule `idx` at `pos` and returns the whole mutated buffer.
    fn mutant(idx: usize, src: &str, pos: usize) -> Option<Vec<u8>> {
        let buf = src.as_bytes();
        let (s, e, rep) = apply(RULES[idx], buf, pos)?;
        Some([&buf[..s], &rep[..], &buf[e..]].concat())
    }

    #[test]
    fn test_replace() {
        // Rule 2 is `==` -> `!=`.
        assert_eq!(
            mutant(2, "if (a == b) x = 1;", 0).unwrap(),
            b"if (a != b) x = 1;"
        );
        // Only at or after the position.
        assert_eq!(mutant(2, "a == b", 3), None);
    }

    #[test]
    fn test_while_to_if() {
        // This one never applied in the original, because of a missing `break`.
        assert_eq!(
            mutant(39, "while (x) { y(); }", 0).unwrap(),
            b"if (x) { y(); }"
        );
    }

    #[test]
    fn test_delete_statement() {
        assert_eq!(mutant(44, "a(); b(); c();", 0).unwrap(), b"a(); c();");
    }

    #[test]
    fn test_remove_and_empty_block() {
        assert_eq!(
            mutant(46, "if (x) { y(); } z();", 0).unwrap(),
            b"if (x)  z();"
        );
        assert_eq!(
            mutant(47, "if (x) { y(); } z();", 0).unwrap(),
            b"if (x) {} z();"
        );
    }

    #[test]
    fn test_swap_arguments() {
        assert_eq!(mutant(50, "f(a, b);", 0).unwrap(), b"f( b,a);");
    }

    #[test]
    fn test_duplicate() {
        assert_eq!(mutant(62, "a\nb\nc", 0).unwrap(), b"a\nb\n\nb\nc");
        // In the original, both duplication operators were no-ops.
        assert_eq!(
            mutant(63, "x\nfor (;;) { y(); }\nz", 0).unwrap(),
            b"x\nfor (;;) { y(); }\nfor (;;) { y(); }\nz"
        );
    }

    #[test]
    fn test_span_limit() {
        let far = alloc::format!("{{{}}} x", " ".repeat(MAX_MUTANT_CHANGE));
        assert_eq!(mutant(46, &far, 0), None);
        let near = alloc::format!("{{{}}} x", " ".repeat(MAX_MUTANT_CHANGE - 2));
        assert_eq!(mutant(46, &near, 0).unwrap(), b" x");
    }

    #[test]
    fn test_all_rules_all_positions() {
        let src = "int f(int a, int b) {\n  if (a == b && a != 0) { a++; }\n  \
                   while (a < 10) a = a + b * 2 - 1 / 3 % 4;\n  if (b > 0 || a--) b--;\n  \
                   return g(a, b, !a);\n}\n";
        let buf = src.as_bytes();
        let mut applied = [false; RULES.len()];
        for (i, rule) in RULES.iter().enumerate() {
            for pos in 0..buf.len() {
                if let Some((s, e, _)) = apply(*rule, buf, pos) {
                    assert!(pos <= s && s <= e && e <= buf.len(), "{rule:?} at {pos}");
                    applied[i] = true;
                }
            }
        }
        // Every operator has a match somewhere in this program.
        for (i, a) in applied.iter().enumerate() {
            assert!(*a, "rule {i} ({:?}) never applied", RULES[i]);
        }
    }

    #[test]
    fn test_mutator() {
        let mut state = NopState::<BytesInput>::new();
        let mut mutator = MutationTestingMutator::new();
        let seed =
            b"int main(void) {\n  int x = 1;\n  while (x == 0) {\n    x++;\n  }\n  return x;\n}\n";

        let mut mutated = 0;
        for _ in 0..1000 {
            let mut input = BytesInput::new(seed.to_vec());
            if mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Mutated {
                mutated += 1;
                assert!(!input.mutator_bytes().is_empty());
                assert!(input.mutator_bytes().len() <= 16_384);
            }
        }
        assert!(mutated > 900, "only {mutated} of 1000 calls mutated");

        // Too short to mutate.
        let mut input = BytesInput::new(b"x".to_vec());
        assert_eq!(
            mutator.mutate(&mut state, &mut input).unwrap(),
            MutationResult::Skipped
        );
    }
}
