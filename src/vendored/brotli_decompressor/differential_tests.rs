//! The vendored decoder against the unpatched upstream crate (`brotli-decompressor` 6.3.1, a
//! dev-dependency): on valid streams, on damaged ones and on the hostile meta-block streams the
//! patch is about, both must give the same verdict, the same output and use the same input, for
//! every way of feeding the input and draining the output. No difference is allowed.
//!
//! Second reference: the previous vendored version, `brotli-decompressor` 5.0.0 (unpatched). On valid
//! streams the vendored decoder must give the same output as 5.0.0 (no regression); on damaged and
//! random input 5.0.0 may differ (it lacks two upstream fixes), only the output of streams both accept
//! must be equal.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;

use spillgate_test_support::BitWriter;

use super::{BrotliDecompressStream, BrotliState, StandardAlloc};

/// Everything observable from outside: the verdict, the output and the input taken.
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    verdict: &'static str,
    output: Vec<u8>,
    consumed: usize,
}

macro_rules! drive {
    ($state:expr, $data:expr, $in_chunk:expr, $out_cap:expr, $Stream:path) => {{
        let mut output = Vec::new();
        let mut consumed = 0usize;
        let mut total_out = 0usize;
        let mut buf = vec![0u8; $out_cap];
        let verdict;
        'run: loop {
            let end = ($data.len()).min(consumed.saturating_add($in_chunk));
            let chunk = &$data[consumed..end];
            let mut available_in = chunk.len();
            let mut input_offset = 0usize;
            let mut available_out = buf.len();
            let mut output_offset = 0usize;
            let result = $Stream(
                &mut available_in,
                &mut input_offset,
                chunk,
                &mut available_out,
                &mut output_offset,
                &mut buf,
                &mut total_out,
                &mut $state,
            );
            consumed += input_offset;
            output.extend_from_slice(&buf[..output_offset]);
            match format!("{result:?}").as_str() {
                "ResultSuccess" => {
                    verdict = "success";
                    break 'run;
                }
                "ResultFailure" => {
                    verdict = "failure";
                    break 'run;
                }
                "NeedsMoreOutput" => {}
                _ => {
                    if end == $data.len() && input_offset == chunk.len() {
                        verdict = "needs-input";
                        break 'run;
                    }
                }
            }
        }
        Trace {
            verdict,
            output,
            consumed,
        }
    }};
}

fn vendored(data: &[u8], in_chunk: usize, out_cap: usize) -> Trace {
    vendored_code(data, in_chunk, out_cap).0
}

/// The trace and the decoder's error code (-15 PADDING_2, -10 BLOCK_LENGTH_2, -9 BLOCK_LENGTH_1).
fn vendored_code(data: &[u8], in_chunk: usize, out_cap: usize) -> (Trace, i32) {
    let mut state = BrotliState::new_strict(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let t = drive!(state, data, in_chunk, out_cap, BrotliDecompressStream);
    (t, state.error_code as i32)
}

fn upstream(data: &[u8], in_chunk: usize, out_cap: usize) -> Trace {
    use upstream_brotli_decompressor as up;
    let mut state = up::BrotliState::new_strict(
        up::StandardAlloc::default(),
        up::StandardAlloc::default(),
        up::StandardAlloc::default(),
    );
    drive!(state, data, in_chunk, out_cap, up::BrotliDecompressStream)
}

fn upstream5(data: &[u8], in_chunk: usize, out_cap: usize) -> Trace {
    use upstream_brotli_decompressor_5 as up;
    let mut state = up::BrotliState::new_strict(
        up::StandardAlloc::default(),
        up::StandardAlloc::default(),
        up::StandardAlloc::default(),
    );
    drive!(state, data, in_chunk, out_cap, up::BrotliDecompressStream)
}

/// Streams on which the vendored decoder and 5.0.0 disagreed on the verdict (diagnostic only).
static DIFF_VS_5: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `valid`: the stream is valid, so 5.0.0 must agree completely.
fn same(data: &[u8], what: &str, valid: bool) -> Trace {
    let mut first = None;
    for (in_chunk, out_cap) in [
        (usize::MAX / 2, 1 << 16),
        (1, 1 << 16),
        (4096, 1),
        (7, 3),
        (65_536, 100_000),
    ] {
        // a tiny output buffer on a large output is slow: use it for small streams only
        let out_cap = if out_cap < 16 && data.len() > 3000 { 4096 } else { out_cap };
        let a = vendored(data, in_chunk, out_cap);
        let b = upstream(data, in_chunk, out_cap);
        let ctx = format!("{what}: input chunk {in_chunk}, output buffer {out_cap}");
        assert_eq!(a, b, "{ctx}: vendored differs from unpatched 6.3.1");
        let c = upstream5(data, in_chunk, out_cap);
        if valid {
            assert_eq!(a, c, "{ctx}: vendored differs from 5.0.0 on a valid stream");
        } else if a != c {
            DIFF_VS_5.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if a.verdict == "success" && c.verdict == "success" {
                assert_eq!(a.output, c.output, "{ctx}: accepted by both, output differs");
            }
        }
        first.get_or_insert(a);
    }
    first.unwrap_or(Trace { verdict: "failure", output: Vec::new(), consumed: 0 })
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn payload(kind: usize, size: usize, rng: &mut Rng) -> Vec<u8> {
    match kind {
        0 => (0..size).map(|i| b"the quick brown fox "[i % 20]).collect(),
        1 => (0..size).map(|_| rng.next() as u8).collect(),
        2 => vec![0; size],
        _ => (0..size)
            .map(|i| if i % 9 < 5 { b'a' + (i / 9 % 23) as u8 } else { rng.next() as u8 })
            .collect(),
    }
}

fn encode(data: &[u8], quality: u32, lgwin: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, quality, lgwin);
        w.write_all(data).unwrap();
    }
    out
}

// -- the hostile meta-blocks (the construction of tests/br_hostile.rs, with free tree counts) --------

/// NTREES (1..=256) as the variable-length code of RFC 7932 section 9.2.
fn var_len(w: &mut BitWriter, n: u32) {
    if n == 1 {
        w.bits(0, 1);
        return;
    }
    let m = n - 1;
    let nbits = 31 - m.leading_zeros();
    w.bits(1, 1);
    w.bits(u64::from(nbits), 3);
    w.bits(u64::from(m - (1 << nbits)), nbits);
}

/// A simple prefix code with one symbol.
fn simple1(w: &mut BitWriter, alphabet: u32, symbol: u64) {
    let bits = 32 - (alphabet - 1).leading_zeros();
    w.bits(1, 2);
    w.bits(0, 2);
    w.bits(symbol, bits);
}

fn hostile_meta_block(w: &mut BitWriter, literal_trees: u32, distance_trees: u32, symbol: u64) {
    w.bits(0, 1); // ISLAST = 0
    w.bits(0, 2); // MNIBBLES = 4
    w.bits(0, 16); // MLEN - 1 = 0
    w.bits(0, 1); // not uncompressed
    w.bits(0, 3); // one block type of each kind
    w.bits(0, 2); // NPOSTFIX
    w.bits(0, 4); // NDIRECT
    w.bits(0, 2); // context mode
    var_len(w, literal_trees);
    if literal_trees > 1 {
        w.bits(0, 1); // no RLE in the context map
        simple1(w, literal_trees.max(2), 0);
        w.bits(0, 1); // no inverse move-to-front
    }
    var_len(w, distance_trees);
    if distance_trees > 1 {
        w.bits(0, 1);
        simple1(w, distance_trees.max(2), 0);
        w.bits(0, 1);
    }
    for i in 0..literal_trees {
        simple1(w, 256, (symbol + u64::from(i)) % 256);
    }
    simple1(w, 704, 8);
    for _ in 0..distance_trees {
        simple1(w, 64, 0);
    }
}

fn hostile_stream(shapes: &[(u32, u32)]) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.bits(0, 1); // window 16
    for (i, &(l, d)) in shapes.iter().enumerate() {
        hostile_meta_block(&mut w, l, d, 65 + i as u64);
    }
    w.bits(3, 2);
    w.finish()
}

#[test]
fn valid_streams_decode_identically() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut streams = 0;
    for kind in 0..4 {
        for size in [0usize, 1, 100, 5_000, 200_000] {
            let data = payload(kind, size, &mut rng);
            for quality in [0u32, 1, 5, 9, 11] {
                for lgwin in [10u32, 16, 22, 24] {
                    let stream = encode(&data, quality, lgwin);
                    let t = same(&stream, &format!("kind {kind} size {size} q{quality} w{lgwin}"), true);
                    assert_eq!(t.verdict, "success");
                    assert_eq!(t.output, data);
                    streams += 1;
                }
            }
        }
    }
    eprintln!("{streams} valid streams identical");
}

#[test]
fn a_multi_megabyte_stream_with_many_meta_blocks_decodes_identically() {
    let mut rng = Rng(7);
    let mut data = payload(0, 700_000, &mut rng);
    data.extend(payload(1, 300_000, &mut rng));
    data.extend(payload(3, 1_500_000, &mut rng));
    for quality in [5u32, 9, 11] {
        let stream = encode(&data, quality, 22);
        let a = vendored(&stream, usize::MAX / 2, 1 << 16);
        let b = upstream(&stream, usize::MAX / 2, 1 << 16);
        assert_eq!(a, b, "quality {quality}");
        assert_eq!(a.output, data);
        assert_eq!(a, upstream5(&stream, usize::MAX / 2, 1 << 16), "quality {quality}: vs 5.0.0");
        let a = vendored(&stream, 1000, 70_000);
        assert_eq!(a.output, data);
    }
}

#[test]
fn hostile_meta_block_streams_decode_identically() {
    let mut shapes_list: Vec<Vec<(u32, u32)>> = vec![
        vec![(256, 256); 1],
        vec![(256, 256); 20],
        vec![(1, 1); 5],
        // big tables first, then small ones: the table memory is reused with stale contents
        vec![(256, 256), (2, 3), (1, 1), (255, 17), (3, 2), (256, 1), (1, 256), (7, 7)],
        vec![(2, 2), (256, 256), (2, 2), (200, 100), (4, 4)],
    ];
    let mut rng = Rng(99);
    for _ in 0..30 {
        let n = 1 + rng.below(12) as usize;
        shapes_list.push(
            (0..n)
                .map(|_| (1 + rng.below(256) as u32, 1 + rng.below(256) as u32))
                .collect(),
        );
    }
    for shapes in &shapes_list {
        let stream = hostile_stream(shapes);
        let t = same(&stream, &format!("{shapes:?}"), true);
        assert_eq!(t.verdict, "success", "{shapes:?}");
        assert_eq!(t.output.len(), shapes.len());
    }
}

#[test]
fn damaged_streams_get_the_same_verdict_and_output() {
    let mut rng = Rng(0xdead_beef);
    let mut bases: Vec<Vec<u8>> = Vec::new();
    for (kind, size, quality, lgwin) in [
        (0usize, 3000usize, 5u32, 16u32),
        (3, 20_000, 9, 22),
        (1, 2000, 11, 18),
        (3, 60_000, 11, 22),
    ] {
        bases.push(encode(&payload(kind, size, &mut rng), quality, lgwin));
    }
    bases.push(hostile_stream(&[(256, 256), (2, 3), (255, 17), (256, 256), (9, 9)]));
    bases.push(hostile_stream(&[(100, 200); 6]));
    let mut verdicts = std::collections::BTreeMap::new();
    for (b, base) in bases.iter().enumerate() {
        for round in 0..400 {
            let mut data = base.clone();
            match round % 4 {
                0 => {
                    let at = rng.below(data.len() as u64) as usize;
                    data[at] ^= 1 << rng.below(8);
                }
                1 => {
                    for _ in 0..3 {
                        let at = rng.below(data.len() as u64) as usize;
                        data[at] = rng.next() as u8;
                    }
                }
                2 => data.truncate(1 + rng.below(data.len() as u64) as usize),
                _ => {
                    let at = rng.below(data.len() as u64) as usize;
                    data.insert(at, rng.next() as u8);
                }
            }
            let t = same(&data, &format!("base {b} round {round}"), false);
            *verdicts.entry(t.verdict).or_insert(0usize) += 1;
        }
    }
    eprintln!(
        "damaged streams: {verdicts:?}; runs where 5.0.0 differs: {}",
        DIFF_VS_5.load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(verdicts.get("failure").copied().unwrap_or(0) > 100);
}

#[test]
fn random_bytes_get_the_same_verdict() {
    let mut rng = Rng(5);
    for round in 0..600 {
        let n = 1 + rng.below(300) as usize;
        let data: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        same(&data, &format!("random {round}"), false);
    }
}
