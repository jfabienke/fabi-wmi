//! Proptest strategies shared by the parsers' "never panics" properties.
//!
//! Every parser in the workspace reads bytes a server sent. The properties feed
//! them random bytes and mutated captures (byte flips, 32-bit length/count/offset
//! fields set to edge values, truncation) and only require that the parser
//! returns, with `Ok` or `Err`, instead of panicking or aborting.

use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::Config;

/// Values that tend to break length, count and offset handling.
const EDGE_U32: [u32; 6] = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];

/// Cases per property unless `PROPTEST_CASES` says otherwise.
const DEFAULT_CASES: u32 = 1000;

/// Proptest configuration for the parser properties: [`DEFAULT_CASES`] cases,
/// or `PROPTEST_CASES` when set (for longer local runs).
#[must_use]
pub fn config() -> Config {
    let mut config = Config::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = DEFAULT_CASES;
    }
    config
}

/// Random bytes, up to `max_len` long.
pub fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

/// One change to a fixture. Positions are reduced modulo the buffer length
/// when applied.
#[derive(Debug, Clone)]
enum Edit {
    Byte(usize, u8),
    /// Overwrite the 4-byte-aligned word at the position.
    Word(usize, u32),
    Truncate(usize),
}

fn edit() -> impl Strategy<Value = Edit> {
    let word = prop_oneof![prop::sample::select(&EDGE_U32[..]), any::<u32>()];
    prop_oneof![
        4 => (any::<usize>(), any::<u8>()).prop_map(|(at, b)| Edit::Byte(at, b)),
        3 => (any::<usize>(), word).prop_map(|(at, w)| Edit::Word(at, w)),
        1 => any::<usize>().prop_map(Edit::Truncate),
    ]
}

fn apply(mut buf: Vec<u8>, edits: Vec<Edit>) -> Vec<u8> {
    for edit in edits {
        let len = buf.len();
        match edit {
            Edit::Byte(at, b) if len > 0 => buf[at % len] = b,
            Edit::Word(at, w) if len >= 4 => {
                let at = (at % (len - 3)) & !3;
                buf[at..at + 4].copy_from_slice(&w.to_le_bytes());
            }
            Edit::Truncate(n) => buf.truncate(n % (len + 1)),
            _ => {}
        }
    }
    buf
}

/// `fixture` with 1 to 8 random edits.
pub fn mutated(fixture: impl Into<Arc<[u8]>>) -> impl Strategy<Value = Vec<u8>> {
    let fixture: Arc<[u8]> = fixture.into();
    prop::collection::vec(edit(), 1..=8).prop_map(move |edits| apply(fixture.to_vec(), edits))
}

/// One of `fixtures`, with 1 to 8 random edits.
pub fn mutated_any(fixtures: &'static [&'static [u8]]) -> impl Strategy<Value = Vec<u8>> {
    prop::sample::select(fixtures).prop_flat_map(mutated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_stay_in_bounds() {
        let buf = apply(
            vec![0; 10],
            vec![
                Edit::Byte(usize::MAX, 1),
                Edit::Word(usize::MAX, 0xffff_ffff),
                Edit::Truncate(5),
                Edit::Word(3, 7),
            ],
        );
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[0..4], &7u32.to_le_bytes());
        // Edits on an empty buffer are no-ops.
        assert!(apply(Vec::new(), vec![Edit::Byte(0, 1), Edit::Word(0, 1)]).is_empty());
    }
}
