//! Tests of the zstd decoder (SG-R-CDC-05), driven directly through the `Codec` trait and checked
//! against the reference implementation (the `zstd` crate, a dev-dependency only).
//!
//! Every test names the rules it covers in a `// Covers:` comment. The differential tests compress
//! with the reference encoder (levels 1..=22, strategies, windows, checksum and content size on and
//! off, long-distance matching) and compare the decoded output byte for byte; the damage tests
//! flip every bit, cut every prefix and mutate at random with a fixed seed, and require that
//! whatever we accept the reference accepts with identical output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{self, BufRead, Read};
use std::time::{Duration, Instant};

use zstd::bulk::Compressor;
use zstd::stream::raw::CParameter;
use zstd::zstd_safe::Strategy;

use super::bits::{BackwardBits, ForwardBits};
use super::block::{Frame, Window, BLOCK_MAX};
use super::fse::{build_table, read_table};
use super::huffman::read_huffman_table;
use super::reader::ZstdReader;
use super::xxhash64::Xxh64;
use super::{codec, ZstdOptions, DEFAULT_MAX_WINDOW};
use crate::codec::{Codec, CodecReader};
use crate::error::ErrorKind;

const MIB: usize = 1 << 20;

// -- helpers: data ---------------------------------------------------------------------

/// Deterministic pseudo random bytes (xorshift), the same for every run.
fn data(seed: u64, size: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn text() -> Vec<u8> {
    "the quick brown fox jumps over the lazy dog. "
        .repeat(3000)
        .into_bytes()
}

fn mixed() -> Vec<u8> {
    let text = text();
    let mut v = text[..20_000].to_vec();
    v.extend(data(5, 70_000));
    v.extend(vec![0u8; 100_000]);
    v.extend(&text);
    v
}

fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("one byte", b"a".to_vec()),
        ("text", text()),
        ("noise", data(5, 70_000)),
        ("zeros", vec![0u8; 300_000]),
        ("mixed", mixed()),
    ]
}

// -- helpers: the reference ------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Params {
    checksum: Option<bool>,
    content_size: Option<bool>,
    window_log: Option<u32>,
    strategy: Option<u32>,
    ldm: bool,
}

fn strategy(n: u32) -> Strategy {
    match n {
        1 => Strategy::ZSTD_fast,
        2 => Strategy::ZSTD_dfast,
        3 => Strategy::ZSTD_greedy,
        4 => Strategy::ZSTD_lazy,
        5 => Strategy::ZSTD_lazy2,
        6 => Strategy::ZSTD_btlazy2,
        7 => Strategy::ZSTD_btopt,
        8 => Strategy::ZSTD_btultra,
        _ => Strategy::ZSTD_btultra2,
    }
}

fn compress_with(payload: &[u8], level: i32, p: Params) -> Vec<u8> {
    let mut c = Compressor::new(level).unwrap();
    if let Some(on) = p.checksum {
        c.set_parameter(CParameter::ChecksumFlag(on)).unwrap();
    }
    if let Some(on) = p.content_size {
        c.set_parameter(CParameter::ContentSizeFlag(on)).unwrap();
    }
    if let Some(w) = p.window_log {
        c.set_parameter(CParameter::WindowLog(w)).unwrap();
    }
    if let Some(s) = p.strategy {
        c.set_parameter(CParameter::Strategy(strategy(s))).unwrap();
    }
    if p.ldm {
        c.set_parameter(CParameter::EnableLongDistanceMatching(true)).unwrap();
    }
    c.compress(payload).unwrap()
}

fn compress(payload: &[u8]) -> Vec<u8> {
    compress_with(payload, 3, Params::default())
}

fn checksummed(payload: &[u8], level: i32) -> Vec<u8> {
    compress_with(
        payload,
        level,
        Params {
            checksum: Some(true),
            ..Params::default()
        },
    )
}

/// What the reference decoder makes of a stream: its output, or `None` if it refuses.
fn oracle(stream: &[u8]) -> Option<Vec<u8>> {
    zstd::stream::decode_all(stream).ok()
}

// -- helpers: driving the codec --------------------------------------------------------

/// The result of decoding: `Ok(())` or the error kind, and the bytes delivered before it.
type Outcome = Result<(), ErrorKind>;

fn reader<'a>(input: Box<dyn BufRead + 'a>, cap: u64) -> ZstdReader<'a> {
    ZstdReader::new(input, cap)
}

/// Drain `r` with reads of `buf_size`, collecting everything (the output of tests is small).
fn drain(r: &mut dyn CodecReader, buf_size: usize) -> (Outcome, Vec<u8>) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; buf_size];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return (Ok(()), out),
            Ok(n) => {
                assert!(n <= buf.len(), "a codec must not return more than the buffer");
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) => return (Err(e.kind()), out),
        }
    }
}

fn run_cap(stream: &[u8], cap: u64) -> (Outcome, Vec<u8>) {
    let codec = codec(ZstdOptions { max_window_bytes: cap }).unwrap();
    let mut r = codec.new_reader(Box::new(stream));
    drain(&mut *r, 4096)
}

fn run(stream: &[u8]) -> (Outcome, Vec<u8>) {
    run_cap(stream, 1 << 27)
}

/// Decode and count the bytes without keeping them; returns the outcome, the count and the reader
/// (to inspect its memory).
fn count<'a>(input: Box<dyn BufRead + 'a>, cap: u64, limit: u64) -> (Outcome, u64, ZstdReader<'a>) {
    let mut r = reader(input, cap);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => return (Ok(()), total, r),
            Ok(n) => {
                total += n as u64;
                if total >= limit {
                    return (Ok(()), total, r);
                }
            }
            Err(e) => return (Err(e.kind()), total, r),
        }
    }
}

/// An input that hands out at most `step` bytes per `fill_buf` and counts what is consumed.
struct Chunked<'a> {
    data: &'a [u8],
    pos: usize,
    step: usize,
    consumed: std::rc::Rc<std::cell::Cell<usize>>,
}

impl<'a> Chunked<'a> {
    fn new(data: &'a [u8], step: usize) -> (Chunked<'a>, std::rc::Rc<std::cell::Cell<usize>>) {
        let consumed = std::rc::Rc::new(std::cell::Cell::new(0));
        (
            Chunked {
                data,
                pos: 0,
                step,
                consumed: consumed.clone(),
            },
            consumed,
        )
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Chunked<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let end = (self.pos + self.step).min(self.data.len());
        Ok(&self.data[self.pos..end])
    }
    fn consume(&mut self, amt: usize) {
        let end = (self.pos + self.step).min(self.data.len());
        assert!(amt <= end - self.pos, "consume of more than fill_buf returned");
        self.pos += amt;
        self.consumed.set(self.pos);
    }
}

/// An input that fails after `ok` bytes.
struct Failing {
    data: Vec<u8>,
    pos: usize,
    ok: usize,
}

impl BufRead for Failing {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.ok {
            return Err(io::Error::other("source failed"));
        }
        Ok(&self.data[self.pos..self.ok.min(self.data.len())])
    }
    fn consume(&mut self, amt: usize) {
        self.pos += amt;
    }
}

impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

// -- helpers: building frames by hand --------------------------------------------------

#[derive(Default, Clone, Copy)]
struct Header {
    window_log: Option<u32>,
    mantissa: u8,
    single_segment: bool,
    content_size: Option<u64>,
    dictionary_id: Option<u32>,
    checksum: bool,
    reserved_bit: bool,
}

fn header(h: Header) -> Vec<u8> {
    let mut out = vec![0x28, 0xb5, 0x2f, 0xfd];
    let (fcs_flag, fcs): (u8, Vec<u8>) = match h.content_size {
        None => (0, vec![]),
        Some(size) if h.single_segment && size <= 255 => (0, vec![size as u8]),
        Some(size) if (256..=65791).contains(&size) => (1, ((size - 256) as u16).to_le_bytes().to_vec()),
        Some(size) if size <= u64::from(u32::MAX) => (2, (size as u32).to_le_bytes().to_vec()),
        Some(size) => (3, size.to_le_bytes().to_vec()),
    };
    let (dict_flag, dict): (u8, Vec<u8>) = match h.dictionary_id {
        None => (0, vec![]),
        Some(id) => (3, id.to_le_bytes().to_vec()),
    };
    let mut descriptor = (fcs_flag << 6) | dict_flag;
    if h.single_segment {
        descriptor |= 1 << 5;
    }
    if h.checksum {
        descriptor |= 1 << 2;
    }
    if h.reserved_bit {
        descriptor |= 1 << 3;
    }
    out.push(descriptor);
    if !h.single_segment {
        out.push((((h.window_log.unwrap_or(10) - 10) as u8) << 3) | (h.mantissa & 7));
    }
    out.extend(dict);
    out.extend(fcs);
    out
}

fn window_header(window_log: u32) -> Vec<u8> {
    header(Header {
        window_log: Some(window_log),
        ..Header::default()
    })
}

fn block_header(last: bool, kind: u32, size: usize) -> Vec<u8> {
    let v = ((size as u32) << 3) | (kind << 1) | u32::from(last);
    v.to_le_bytes()[..3].to_vec()
}

/// Raw blocks of at most `block` bytes carrying `payload` (one empty block if it is empty).
fn raw_blocks(payload: &[u8], block: usize, last: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if payload.is_empty() {
        out.extend(block_header(last, 0, 0));
        return out;
    }
    let n = payload.len().div_ceil(block);
    for (i, chunk) in payload.chunks(block).enumerate() {
        out.extend(block_header(last && i + 1 == n, 0, chunk.len()));
        out.extend(chunk);
    }
    out
}

/// RLE blocks regenerating `total` bytes of `byte` in blocks of at most `block` bytes.
fn rle_blocks(total: u64, block: usize, byte: u8, last: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut left = total;
    loop {
        let size = left.min(block as u64) as usize;
        left -= size as u64;
        let is_last = left == 0;
        out.extend(block_header(last && is_last, 1, size));
        out.push(byte);
        if is_last {
            return out;
        }
    }
}

/// A frame of `size` zero bytes with window `2^window_log`, as RLE blocks (a bomb in a few bytes).
fn zeros(size: u64, window_log: u32) -> Vec<u8> {
    let block = (1usize << window_log).min(BLOCK_MAX);
    let mut f = window_header(window_log);
    f.extend(rle_blocks(size, block, 0, true));
    f
}

fn skippable(n: usize) -> Vec<u8> {
    let mut v = vec![0x50, 0x2a, 0x4d, 0x18];
    v.extend((n as u32).to_le_bytes());
    v.extend(vec![0xab; n]);
    v
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

// -- helpers: agreement with the reference ---------------------------------------------

const ALLOWED: [ErrorKind; 3] = [ErrorKind::Corrupt, ErrorKind::MemoryLimit, ErrorKind::OutputLimit];

/// Decode damaged input: whatever the outcome class, never a foreign error; what we accept the
/// reference must accept with identical output. Returns true if we accepted.
fn check_agrees(damaged: &[u8], what: &str) -> bool {
    let (outcome, out) = run_cap(damaged, 1 << 24);
    match outcome {
        Ok(()) => {
            let expected = oracle(damaged);
            assert!(
                expected.as_deref() == Some(out.as_slice()),
                "{what}: accepted a stream the reference refuses or decodes differently (ours {} bytes, reference {:?}, input {} bytes, tail {:02x?})",
                out.len(),
                expected.as_ref().map(Vec::len),
                damaged.len(),
                &damaged[damaged.len().saturating_sub(8)..]
            );
            true
        }
        Err(kind) => {
            assert!(ALLOWED.contains(&kind), "{what}: unexpected error kind {kind}");
            false
        }
    }
}

// =========================================================================================
// differential tests against the reference encoder
// =========================================================================================

#[test]
fn round_trip_every_level() {
    // Covers: SG-R-CDC-05 SG-R-RDR-01
    for (name, payload) in payloads() {
        let levels: Vec<i32> = if payload.len() > 100_000 {
            (1..=22).step_by(3).chain([19, 22]).collect()
        } else {
            (1..=22).collect()
        };
        for level in levels {
            for checksum in [false, true] {
                let stream = compress_with(
                    &payload,
                    level,
                    Params {
                        checksum: Some(checksum),
                        ..Params::default()
                    },
                );
                let (outcome, out) = run(&stream);
                assert_eq!(outcome, Ok(()), "{name} level {level} checksum {checksum}");
                assert!(out == payload, "{name} level {level} checksum {checksum}: wrong output");
            }
        }
    }
}

#[test]
fn round_trip_all_levels_on_mixed() {
    // Covers: SG-R-CDC-05
    let payload = mixed();
    for level in 1..=22 {
        let stream = compress_with(
            &payload,
            level,
            Params {
                checksum: Some(true),
                ..Params::default()
            },
        );
        let (outcome, out) = run_cap(&stream, 1 << 27);
        assert_eq!(outcome, Ok(()), "level {level}");
        assert!(out == payload, "level {level}");
    }
}

#[test]
fn round_trip_negative_and_fast_levels() {
    // Covers: SG-R-CDC-05
    let payload = mixed();
    for level in [-131072, -5, -1, 0] {
        let stream = compress_with(&payload, level, Params::default());
        let (outcome, out) = run(&stream);
        assert_eq!(outcome, Ok(()), "level {level}");
        assert!(out == payload, "level {level}");
    }
}

#[test]
fn every_strategy_and_window() {
    // Covers: SG-R-CDC-05
    let payload = mixed();
    for strategy in 1..=9 {
        for window_log in [10, 12, 15, 17, 20, 23] {
            let params = Params {
                strategy: Some(strategy),
                window_log: Some(window_log),
                ..Params::default()
            };
            let stream = compress_with(&payload, 6, params);
            let (outcome, out) = run_cap(&stream, 1 << 24);
            assert_eq!(outcome, Ok(()), "strategy {strategy} window {window_log}");
            assert!(out == payload, "strategy {strategy} window {window_log}");
        }
    }
}

#[test]
fn every_window_log_up_to_the_default_cap() {
    // Covers: SG-R-CDC-05
    let payload = mixed();
    for window_log in 10..=23 {
        let params = Params {
            window_log: Some(window_log),
            checksum: Some(true),
            ..Params::default()
        };
        let stream = compress_with(&payload, 9, params);
        let (outcome, out) = run_cap(&stream, DEFAULT_MAX_WINDOW);
        assert_eq!(outcome, Ok(()), "window {window_log}");
        assert!(out == payload, "window {window_log}");
    }
}

#[test]
fn content_size_on_off_and_long_distance_matching() {
    // Covers: SG-R-CDC-05
    let payload = mixed();
    let all = [
        Params {
            content_size: Some(false),
            ..Params::default()
        },
        Params {
            content_size: Some(true),
            ..Params::default()
        },
        Params {
            ldm: true,
            window_log: Some(23),
            ..Params::default()
        },
        Params {
            ldm: true,
            window_log: Some(23),
            checksum: Some(true),
            content_size: Some(false),
            ..Params::default()
        },
    ];
    for (i, params) in all.iter().enumerate() {
        let stream = compress_with(&payload, 5, *params);
        let (outcome, out) = run_cap(&stream, 1 << 24);
        assert_eq!(outcome, Ok(()), "variant {i}");
        assert!(out == payload, "variant {i}");
    }
}

#[test]
fn single_segment_frames_from_the_reference() {
    // Covers: SG-R-CDC-05 SG-R-CDC-07
    // small payloads with a known content size make the reference emit single-segment frames
    for size in [0usize, 1, 100, 255, 256, 257, 1000, 65_791, 65_792, 70_000] {
        let payload = data(size as u64, size);
        let stream = compress_with(
            &payload,
            3,
            Params {
                content_size: Some(true),
                ..Params::default()
            },
        );
        let (outcome, out) = run_cap(&stream, 1 << 20);
        assert_eq!(outcome, Ok(()), "size {size}");
        assert!(out == payload, "size {size}");
    }
}

#[test]
fn checksum_hash_agrees_with_the_reference_for_many_sizes() {
    // Covers: SG-R-CDC-05
    assert_eq!(Xxh64::new().digest32(), 0x51d8_e999); // XXH64("") = 0xEF46DB3751D8E999, the low 32 bits
    for size in [
        0usize, 1, 3, 4, 7, 8, 9, 31, 32, 33, 63, 64, 65, 100, 1000, 4097, 131_072, 131_073, 300_000,
    ] {
        let payload = data(size as u64, size);
        let stream = checksummed(&payload, 3);
        let (outcome, out) = run(&stream);
        assert_eq!(outcome, Ok(()), "size {size}");
        assert!(out == payload, "size {size}");
    }
}

#[test]
fn xxh64_known_vectors_and_split_updates() {
    // Covers: SG-R-CDC-05
    let mut h = Xxh64::new();
    h.update(b"");
    assert_eq!(h.digest(), 0xef46_db37_51d8_e999);
    let mut h = Xxh64::new();
    h.update(b"a");
    assert_eq!(h.digest(), 0xd24e_c4f1_a98c_6e5b);
    let mut h = Xxh64::new();
    h.update(b"abc");
    assert_eq!(h.digest(), 0x44bc_2cf5_ad77_0999);
    // any split of the input gives the same digest as one update
    let bytes = data(77, 300);
    let mut whole = Xxh64::new();
    whole.update(&bytes);
    for a in 0..bytes.len() {
        for b in [a, (a + 1).min(bytes.len()), (a + 33).min(bytes.len()), bytes.len()] {
            let mut parts = Xxh64::new();
            parts.update(&bytes[..a]);
            parts.update(&bytes[a..b]);
            parts.update(&bytes[b..]);
            assert_eq!(parts.digest(), whole.digest(), "split at {a}/{b}");
        }
    }
}

#[test]
fn damaged_content_checksum_is_corrupt_after_the_data() {
    // Covers: SG-R-CDC-05 SG-R-LAY-07
    // The deferred-error rule: the bytes of the last block are delivered, then the error.
    let payload = text();
    let mut stream = checksummed(&payload, 3);
    let last = stream.len() - 1;
    stream[last] ^= 1;
    let (outcome, out) = run(&stream);
    assert_eq!(outcome, Err(ErrorKind::Corrupt));
    assert!(
        out == payload,
        "all bytes of the last block are delivered before the checksum error"
    );
}

#[test]
fn window_cap_is_exact_at_every_power_of_two() {
    // Covers: SG-R-CDC-05 SG-R-CDC-07
    for window_log in 10..=27u32 {
        let cap = 1u64 << window_log;
        let frame = zeros(1000, window_log);
        assert_eq!(run_cap(&frame, cap).0, Ok(()), "window 2^{window_log}");
        if window_log > 10 {
            assert_eq!(
                run_cap(&frame, cap - 1).0,
                Err(ErrorKind::MemoryLimit),
                "window 2^{window_log} against {}",
                cap - 1
            );
        }
    }
}

#[test]
fn windows_with_a_mantissa_are_checked_too() {
    // Covers: SG-R-CDC-05
    let frame = concat(&[
        &header(Header {
            window_log: Some(20),
            mantissa: 3,
            ..Header::default()
        }),
        &raw_blocks(b"abc", 3, true),
    ]);
    let window = (1u64 << 20) + ((1u64 << 20) / 8) * 3;
    assert_eq!(run_cap(&frame, window).0, Ok(()));
    assert_eq!(run_cap(&frame, window - 1).0, Err(ErrorKind::MemoryLimit));
    // every mantissa of one exponent
    for m in 0..8u8 {
        let f = concat(&[
            &header(Header {
                window_log: Some(12),
                mantissa: m,
                ..Header::default()
            }),
            &raw_blocks(b"x", 1, true),
        ]);
        let w = 4096 + 512 * u64::from(m);
        assert_eq!(run_cap(&f, w).0, Ok(()), "mantissa {m}");
        if w > 1024 {
            assert_eq!(run_cap(&f, w - 1).0, Err(ErrorKind::MemoryLimit), "mantissa {m}");
        }
    }
}

#[test]
fn single_segment_window_is_the_declared_content_size_in_every_size_form() {
    // Covers: SG-R-CDC-05 SG-R-CDC-07 SG-I-04
    for size in [
        0u64,
        1,
        255,
        256,
        300,
        65_791,
        65_792,
        70_000,
        (1 << 32) - 1,
        1 << 32,
        1 << 40,
    ] {
        let frame = concat(&[
            &header(Header {
                single_segment: true,
                content_size: Some(size),
                ..Header::default()
            }),
            &raw_blocks(b"x", 1, true),
        ]);
        let cap = size.clamp(1024, 1 << 30);
        let (outcome, _) = run_cap(&frame, cap);
        assert!(
            matches!(outcome, Ok(()) | Err(ErrorKind::Corrupt) | Err(ErrorKind::MemoryLimit)),
            "{size}"
        );
        if size > DEFAULT_MAX_WINDOW {
            assert_eq!(
                run_cap(&frame, DEFAULT_MAX_WINDOW).0,
                Err(ErrorKind::MemoryLimit),
                "{size}"
            );
        }
        if (2048..=1 << 30).contains(&size) {
            assert_eq!(run_cap(&frame, size - 1).0, Err(ErrorKind::MemoryLimit), "{size}");
        }
    }
}

#[test]
fn hostile_headers_allocate_nothing_before_they_are_refused() {
    // Covers: SG-R-CDC-05 SG-I-04 SG-R-MEM-01
    let frame = concat(&[
        &header(Header {
            single_segment: true,
            content_size: Some(1 << 40),
            ..Header::default()
        }),
        &[0u8; 20],
    ]);
    let (outcome, _, r) = count(Box::new(&frame[..]), DEFAULT_MAX_WINDOW, u64::MAX);
    assert_eq!(outcome, Err(ErrorKind::MemoryLimit));
    assert_eq!(r.heap_bytes(), 0);
    // the same for a declared window of 2^41 + mantissa and for the largest cap
    let huge = concat(&[
        &header(Header {
            window_log: Some(41),
            mantissa: 7,
            ..Header::default()
        }),
        &[0u8; 20],
    ]);
    let (outcome, _, r) = count(Box::new(&huge[..]), 1 << 30, u64::MAX);
    assert_eq!(outcome, Err(ErrorKind::MemoryLimit));
    assert_eq!(r.heap_bytes(), 0);
    // a frame within the cap but declaring a 1 GiB window and a tiny block allocates a tiny window
    let f = concat(&[&window_header(30), &raw_blocks(b"hello", 5, true)]);
    let (outcome, total, r) = count(Box::new(&f[..]), 1 << 30, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 5));
    assert!(r.heap_bytes() < 1 << 20, "lazy window: {} bytes held", r.heap_bytes());
}

#[test]
fn the_memory_limit_error_carries_the_cap() {
    // Covers: SG-R-CDC-05
    let frame = zeros(10, 20);
    let codec = codec(ZstdOptions {
        max_window_bytes: 1 << 19,
    })
    .unwrap();
    let mut r = codec.new_reader(Box::new(&frame[..]));
    let err = r.read(&mut [0u8; 16]).unwrap_err();
    assert_eq!((err.kind(), err.limit()), (ErrorKind::MemoryLimit, 1 << 19));
}

#[test]
fn dictionaries_reserved_bit_reserved_and_oversized_blocks_are_corrupt() {
    // Covers: SG-R-CDC-05
    let body = raw_blocks(b"abc", 3, true);
    let frame = |h: Header| {
        concat(&[
            &header(Header {
                window_log: Some(17),
                ..h
            }),
            &body,
        ])
    };
    assert_eq!(
        run(&frame(Header {
            dictionary_id: Some(1),
            ..Header::default()
        }))
        .0,
        Err(ErrorKind::Corrupt)
    );
    assert_eq!(
        run(&frame(Header {
            dictionary_id: Some(0x0100_0000),
            ..Header::default()
        }))
        .0,
        Err(ErrorKind::Corrupt)
    );
    assert_eq!(
        run(&frame(Header {
            dictionary_id: Some(0),
            ..Header::default()
        }))
        .0,
        Ok(())
    );
    assert_eq!(
        run(&frame(Header {
            reserved_bit: true,
            ..Header::default()
        }))
        .0,
        Err(ErrorKind::Corrupt)
    );
    // reserved block type 3
    assert_eq!(
        run(&concat(&[&window_header(17), &[0b0000_0111, 0, 0]])).0,
        Err(ErrorKind::Corrupt)
    );
    // 129 KiB block
    let big = concat(&[
        &window_header(17),
        &block_header(true, 0, 129 * 1024),
        &vec![0u8; 129 * 1024],
    ]);
    assert_eq!(run(&big).0, Err(ErrorKind::Corrupt));
    // a block larger than the window (window 1 KiB, block 2 KiB)
    let over = concat(&[&window_header(10), &raw_blocks(&[0u8; 2048], 2048, true)]);
    assert_eq!(run(&over).0, Err(ErrorKind::Corrupt));
    // a block exactly as large as the window is fine
    let exact = concat(&[&window_header(10), &raw_blocks(&[7u8; 1024], 1024, true)]);
    assert_eq!(run(&exact), (Ok(()), vec![7u8; 1024]));
}

#[test]
fn a_one_gib_bomb_of_zeros_runs_in_constant_memory() {
    // Covers: SG-R-LAY-02 SG-R-MEM-02 SG-I-08
    let bomb = zeros(1 << 30, 23); // 1 GiB of zeros in about 32 KiB
    assert!(bomb.len() < 40_000);
    let (outcome, total, r) = count(Box::new(&bomb[..]), DEFAULT_MAX_WINDOW, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 1 << 30));
    // the window (8 MiB at most) plus three block buffers
    let bound = (8 * MIB) + 3 * 2 * BLOCK_MAX;
    assert!(r.heap_bytes() <= bound, "{} bytes held after 1 GiB", r.heap_bytes());
    // the same, stopped after 64 MiB as a limiter would: constant memory at every point
    let (outcome, total, r) = count(Box::new(&bomb[..]), DEFAULT_MAX_WINDOW, 64 * MIB as u64);
    assert_eq!(outcome, Ok(()));
    assert!(total >= 64 * MIB as u64);
    assert!(r.heap_bytes() <= bound);
}

#[test]
fn bombs_with_big_windows_stay_within_window_plus_blocks() {
    // Covers: SG-R-MEM-02 SG-R-CDC-05
    let bomb = zeros(256 * MIB as u64, 26);
    let (outcome, total, r) = count(Box::new(&bomb[..]), 1 << 26, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 256 * MIB as u64));
    assert!(
        r.heap_bytes() <= (1 << 26) + 3 * 2 * BLOCK_MAX + (1 << 20),
        "{}",
        r.heap_bytes()
    );
}

#[test]
fn every_truncation_is_corrupt() {
    // Covers: SG-R-CDC-06
    let mixed_small = {
        let mut v = text()[..4000].to_vec();
        v.extend(data(5, 4000));
        v
    };
    let streams = vec![
        checksummed(&mixed_small, 3),
        compress_with(
            &mixed_small,
            3,
            Params {
                content_size: Some(true),
                ..Params::default()
            },
        ),
        concat(&[&window_header(17), &raw_blocks(&data(1, 600), 600, true)]),
        concat(&[&window_header(17), &rle_blocks(500, 200, 9, true)]),
        concat(&[&skippable(20), &compress(b"tail tail tail tail")]),
    ];
    for stream in streams {
        for cut in 0..stream.len() {
            // a cut that falls on a frame boundary after a complete frame is a valid stream
            let (outcome, _) = run(&stream[..cut]);
            if stream.starts_with(&skippable(20)) && cut == 28 {
                assert_eq!(outcome, Ok(()), "a skippable frame alone is a stream");
                continue;
            }
            assert_eq!(outcome, Err(ErrorKind::Corrupt), "cut at {cut} of {}", stream.len());
        }
    }
}

#[test]
fn every_bit_flip_never_panics_and_never_yields_data_the_reference_would_not() {
    // Covers: SG-I-05 SG-R-CDC-08
    let repeated = "flip every bit of this zstd frame, with repeats, repeats, repeats. "
        .repeat(5)
        .into_bytes();
    // varied statistics so that Huffman literals and FSE sequence tables are present
    let mut varied = text()[..900].to_vec();
    varied.extend(data(3, 300).iter().map(|b| b & 0x0f));
    varied.extend(text()[..900].iter().rev());
    let streams = [
        checksummed(&repeated, 5),
        compress_with(
            &repeated,
            3,
            Params {
                content_size: Some(true),
                ..Params::default()
            },
        ),
        checksummed(&varied, 9),
        compress_with(
            &varied,
            19,
            Params {
                content_size: Some(false),
                ..Params::default()
            },
        ),
        concat(&[
            &window_header(12),
            &rle_blocks(3000, 1024, 7, false),
            &raw_blocks(b"end", 3, true),
        ]),
    ];
    let mut accepted = 0usize;
    let mut total = 0usize;
    for (index, stream) in streams.iter().enumerate() {
        for position in 0..stream.len() {
            for bit in 0..8 {
                let mut damaged = stream.clone();
                damaged[position] ^= 1 << bit;
                total += 1;
                if check_agrees(&damaged, &format!("stream {index} {position}:{bit}")) {
                    accepted += 1;
                }
            }
        }
    }
    assert!(total > 3000);
    // flips in literal bytes of raw blocks and similar are legitimately accepted, but not all of them
    assert!(accepted < total);
}

#[test]
fn bit_flips_inside_huffman_and_fse_tables_are_covered() {
    // Covers: SG-I-05 SG-R-CDC-08
    // a payload large enough for four-stream Huffman literals and several sequence blocks
    let payload: Vec<u8> = (0..20_000u32)
        .map(|i| b"abcdefghij"[((i * i) / 7 % 10) as usize])
        .collect();
    let stream = checksummed(&payload, 7);
    assert!(stream.len() < 4000, "{}", stream.len());
    let mut total = 0;
    for position in 0..stream.len() {
        for bit in 0..8 {
            let mut damaged = stream.clone();
            damaged[position] ^= 1 << bit;
            total += 1;
            check_agrees(&damaged, &format!("{position}:{bit}"));
        }
    }
    assert!(total > 100);
}

#[test]
fn random_mutations_agree_with_the_reference() {
    // Covers: SG-I-05 SG-R-CDC-08
    let mut seed = 12345u64;
    let mut next = move || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) as f64 / (1u64 << 31) as f64
    };
    let rounds: usize = std::env::var("SPILLGATE_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let text = text();
    let mixed = mixed();
    let bases: [Vec<u8>; 4] = [
        text[..3000].to_vec(),
        mixed[..8000].to_vec(),
        data(5, 2000),
        vec![0u8; 5000],
    ];
    let mut accepted = 0usize;
    for i in 0..rounds {
        let base = &bases[i % 4];
        let params = Params {
            checksum: Some(i % 2 == 1),
            content_size: Some(i % 3 != 0),
            ..Params::default()
        };
        let mut stream = compress_with(base, 1 + (i % 12) as i32, params);
        let flips = 1 + (next() * 4.0) as usize;
        for _ in 0..flips {
            let at = (next() * stream.len() as f64) as usize;
            let last = stream.len() - 1;
            stream[at.min(last)] = (next() * 256.0) as u8;
        }
        let damaged = if next() < 0.2 {
            &stream[..(next() * stream.len() as f64) as usize]
        } else {
            &stream[..]
        };
        if check_agrees(damaged, &format!("round {i}")) {
            accepted += 1;
        }
    }
    let _ = accepted;
}

// =========================================================================================
// framing
// =========================================================================================

#[test]
fn concatenated_and_skippable_frames() {
    // Covers: SG-R-CDC-05
    let a = compress(b"first ");
    let b = compress(b"second");
    assert_eq!(run(&concat(&[&a, &b])), (Ok(()), b"first second".to_vec()));
    let skip = skippable(5);
    assert_eq!(
        run(&concat(&[&skip, &a, &skip, &b, &skip])),
        (Ok(()), b"first second".to_vec())
    );
    // every skippable magic 0x184D2A50..=0x184D2A5F
    for low in 0..16u8 {
        let mut s = skippable(3);
        s[0] = 0x50 + low;
        assert_eq!(run(&concat(&[&s, &a])), (Ok(()), b"first ".to_vec()), "magic {low}");
    }
    // a skippable frame alone is a stream with no output
    assert_eq!(run(&skip), (Ok(()), Vec::new()));
    // a frame of an empty payload
    assert_eq!(run(&compress(b"")), (Ok(()), Vec::new()));
    // many frames, one budget
    let many = (0..50).flat_map(|_| a.clone()).collect::<Vec<u8>>();
    assert_eq!(run(&many).1.len(), 6 * 50);
}

#[test]
fn skippable_frames_with_big_declared_sizes_are_truncation() {
    // Covers: SG-R-CDC-05 SG-R-CDC-06 SG-R-CDC-07
    let mut s = vec![0x50, 0x2a, 0x4d, 0x18];
    s.extend(u32::MAX.to_le_bytes());
    s.extend(vec![0u8; 100]);
    assert_eq!(run(&s).0, Err(ErrorKind::Corrupt));
    // a skippable frame of 3 MiB is skipped without holding it
    let big = skippable(3 * MIB);
    let both = concat(&[&big, &compress(b"after")]);
    assert_eq!(run(&both), (Ok(()), b"after".to_vec()));
}

#[test]
fn skippable_frames_are_metered_in_small_steps() {
    // Covers: SG-R-CDC-05 SG-R-RAT-02
    // the codec never asks for more than 4 KiB of a skippable frame at once and consumes only what it skips
    let big = skippable(100_000);
    let stream = concat(&[&big, &compress(b"end")]);
    let (src, consumed) = Chunked::new(&stream, 1 << 20);
    let codec = codec(ZstdOptions::default()).unwrap();
    let mut r = codec.new_reader(Box::new(src));
    let mut buf = [0u8; 16];
    let mut seen = Vec::new();
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
    }
    assert_eq!(seen, b"end");
    assert_eq!(consumed.get(), stream.len());
}

#[test]
fn many_skippable_frames_are_cheap() {
    // Covers: SG-R-CDC-05 SG-R-RAT-02
    let one = skippable(0);
    let mut stream: Vec<u8> = (0..30_000).flat_map(|_| one.clone()).collect();
    stream.extend(compress(b"end"));
    let started = Instant::now();
    assert_eq!(run(&stream), (Ok(()), b"end".to_vec()));
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
}

#[test]
fn data_after_the_last_frame_is_corrupt_and_so_is_an_empty_input() {
    // Covers: SG-R-CDC-05 SG-R-CDC-06
    let stream = compress(&text());
    let tails: Vec<Vec<u8>> = vec![
        vec![0],
        vec![1, 2, 3],
        vec![0x28, 0xb5, 0x2f],
        vec![0x50, 0x2a, 0x4d, 0x18],
        vec![0; 100],
        vec![0x28, 0xb5, 0x2f, 0xfc],
    ];
    for tail in tails {
        let (outcome, out) = run(&concat(&[&stream, &tail]));
        assert_eq!(outcome, Err(ErrorKind::Corrupt), "{tail:?}");
        assert_eq!(out, text(), "the data of the valid frame is delivered first");
    }
    assert_eq!(run(&[]).0, Err(ErrorKind::Corrupt));
    assert_eq!(run(&[0u8; 4]).0, Err(ErrorKind::Corrupt));
    // garbage before the first frame
    assert_eq!(run(&concat(&[&[1, 2, 3, 4], &stream])).0, Err(ErrorKind::Corrupt));
}

#[test]
fn a_lying_content_size_never_raises_an_allowance_and_is_checked_at_the_end() {
    // Covers: SG-R-CDC-07 SG-I-04
    let real = vec![120u8; 1000];
    let big = concat(&[
        &header(Header {
            window_log: Some(17),
            content_size: Some(1 << 40),
            ..Header::default()
        }),
        &raw_blocks(&real, 1000, true),
    ]);
    let (outcome, out) = run(&big);
    assert_eq!(outcome, Err(ErrorKind::Corrupt)); // 1000 produced, 2^40 declared
    assert_eq!(out, real, "the bytes were produced and delivered first");
    let small = concat(&[
        &header(Header {
            single_segment: true,
            content_size: Some(10),
            ..Header::default()
        }),
        &raw_blocks(&real, 1000, true),
    ]);
    assert_eq!(run(&small).0, Err(ErrorKind::Corrupt));
    // a content size that is right
    let right = concat(&[
        &header(Header {
            single_segment: true,
            content_size: Some(1000),
            ..Header::default()
        }),
        &raw_blocks(&real, 1000, true),
    ]);
    assert_eq!(run(&right), (Ok(()), real));
}

#[test]
fn an_empty_last_block_cannot_hide_a_content_size_mismatch() {
    // Covers: SG-R-CDC-05
    let frame = concat(&[
        &header(Header {
            single_segment: true,
            content_size: Some(128),
            ..Header::default()
        }),
        &[0x01, 0x00, 0x00],
    ]);
    assert_eq!(run(&frame).0, Err(ErrorKind::Corrupt));
}

#[test]
fn raw_rle_and_empty_compressed_blocks() {
    // Covers: SG-R-CDC-05
    let frame = concat(&[
        &window_header(17),
        &rle_blocks(200_000, 131_072, 7, false),
        &raw_blocks(b"tail", 131_072, true),
    ]);
    let (outcome, out) = run(&frame);
    assert_eq!(outcome, Ok(()));
    assert_eq!(out.len(), 200_004);
    assert!(out[..200_000].iter().all(|&b| b == 7) && &out[200_000..] == b"tail");
    // type 2, size 0, last: a compressed block without a literals section
    assert_eq!(
        run(&concat(&[&window_header(17), &[0x05, 0x00, 0x00]])).0,
        Err(ErrorKind::Corrupt)
    );
    // a stream of empty raw blocks
    let empties = concat(&[
        &window_header(17),
        &block_header(false, 0, 0),
        &block_header(false, 0, 0),
        &block_header(true, 0, 0),
    ]);
    assert_eq!(run(&empties), (Ok(()), Vec::new()));
}

#[test]
fn the_codec_consumes_exactly_the_input_it_uses() {
    // Covers: SG-R-CDC-01 SG-R-RAT-02
    let a = checksummed(&text(), 3);
    let b = compress(b"b");
    let stream = concat(&[&skippable(10), &a, &b]);
    for step in [1usize, 5, 4096, 1 << 20] {
        let (src, consumed) = Chunked::new(&stream, step);
        let codec = codec(ZstdOptions::default()).unwrap();
        let mut r = codec.new_reader(Box::new(src));
        let (outcome, out) = drain(&mut *r, 1000);
        assert_eq!(outcome, Ok(()));
        assert_eq!(out.len(), text().len() + 1);
        assert_eq!(consumed.get(), stream.len(), "step {step}");
    }
    // with trailing garbage the codec stops at the first byte that is not a frame: it has consumed the frames
    let with_tail = concat(&[&a, &[0u8; 3]]);
    let (src, consumed) = Chunked::new(&with_tail, 1 << 20);
    let codec = codec(ZstdOptions::default()).unwrap();
    let mut r = codec.new_reader(Box::new(src));
    let (outcome, _) = drain(&mut *r, 1000);
    assert_eq!(outcome, Err(ErrorKind::Corrupt));
    assert!(consumed.get() >= a.len() && consumed.get() <= with_tail.len());
}

#[test]
fn read_sizes_and_input_chunking_do_not_change_the_result() {
    // Covers: SG-R-RDR-01 SG-I-09
    let payload = mixed();
    let stream = compress_with(
        &payload,
        6,
        Params {
            checksum: Some(true),
            ..Params::default()
        },
    );
    let codec = codec(ZstdOptions {
        max_window_bytes: 1 << 24,
    })
    .unwrap();
    for size in [1usize, 7, 4096, 1 << 20] {
        let mut r = codec.new_reader(Box::new(&stream[..]));
        let mut out = Vec::new();
        let mut buf = vec![0u8; size];
        // one byte reads of the whole payload would take long: stop after a prefix there
        let limit = if size == 1 { 5000 } else { usize::MAX };
        while out.len() < limit {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert!(payload.starts_with(&out), "read size {size}");
        if size != 1 {
            assert_eq!(out.len(), payload.len(), "read size {size}");
        }
    }
    for step in [1usize, 3, 100, 4096] {
        let (src, _) = Chunked::new(&stream, step);
        let mut r = codec.new_reader(Box::new(src));
        let (outcome, out) = drain(&mut *r, 8192);
        assert_eq!(outcome, Ok(()), "step {step}");
        assert!(out == payload, "step {step}");
    }
}

#[test]
fn a_failing_source_is_a_source_error_and_errors_are_sticky() {
    // Covers: SG-R-RDR-05
    let stream = checksummed(&text(), 3);
    for ok in [0usize, 2, 6, 10, stream.len() - 2] {
        let src = Failing {
            data: stream.clone(),
            pos: 0,
            ok,
        };
        let codec = codec(ZstdOptions::default()).unwrap();
        let mut r = codec.new_reader(Box::new(src));
        let (outcome, _) = drain(&mut *r, 4096);
        assert_eq!(outcome, Err(ErrorKind::SourceError), "fails after {ok}");
        // sticky: the same kind again
        assert_eq!(r.read(&mut [0u8; 8]).unwrap_err().kind(), ErrorKind::SourceError);
    }
    let mut corrupt = ZstdReader::new(Box::new(&[1u8, 2, 3, 4][..]), 1 << 20);
    for _ in 0..3 {
        assert_eq!(corrupt.read(&mut [0u8; 8]).unwrap_err().kind(), ErrorKind::Corrupt);
    }
    // a clean end stays a clean end
    let one = compress(b"x");
    let mut done = ZstdReader::new(Box::new(&one[..]), 1 << 20);
    let (outcome, out) = drain(&mut done, 8);
    assert_eq!((outcome, out), (Ok(()), b"x".to_vec()));
    assert_eq!(done.read(&mut [0u8; 8]).unwrap(), 0);
    assert_eq!(done.read(&mut [0u8; 8]).unwrap(), 0);
    // an empty buffer is not an end
    let mut again = ZstdReader::new(Box::new(&one[..]), 1 << 20);
    assert_eq!(again.read(&mut []).unwrap(), 0);
    assert_eq!(again.read(&mut [0u8; 8]).unwrap(), 1);
}

#[test]
fn cap_settings_are_validated() {
    // Covers: SG-R-CDC-09
    for bad in [0u64, 1, 1023, (1 << 30) + 1, u64::MAX] {
        let err = codec(ZstdOptions { max_window_bytes: bad }).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidOption, "{bad}");
    }
    for good in [1024u64, 1025, DEFAULT_MAX_WINDOW, 1 << 30] {
        assert!(codec(ZstdOptions { max_window_bytes: good }).is_ok(), "{good}");
    }
    assert_eq!(ZstdOptions::default().max_window_bytes, 8 * 1024 * 1024);
    assert_eq!(
        codec(ZstdOptions::default()).unwrap().max_window_bytes(),
        DEFAULT_MAX_WINDOW
    );
}

#[test]
fn frames_without_output_cost_bounded_cpu_and_no_window() {
    // Covers: SG-R-RAT-02 SG-R-MEM-02
    let frame = concat(&[&window_header(23), &raw_blocks(&[], 1024, true)]);
    let stream: Vec<u8> = (0..30_000).flat_map(|_| frame.clone()).collect();
    let started = Instant::now();
    let (outcome, total, r) = count(Box::new(&stream[..]), DEFAULT_MAX_WINDOW, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 0));
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(r.heap_bytes() < 1 << 20, "{}", r.heap_bytes());
}

#[test]
fn thirty_thousand_tiny_compressed_blocks_cost_bounded_time() {
    // Covers: SG-R-RAT-02 SG-R-MEM-02
    let payload = b"hello hello hello hello hello hello hello hello hello hello hello world ".repeat(4);
    let single = compress_with(
        &payload,
        3,
        Params {
            content_size: Some(false),
            ..Params::default()
        },
    );
    assert_eq!(single[4], 0, "expected a plain frame header without content size");
    let block = &single[6..];
    assert_eq!((block[0] >> 1) & 3, 2, "expected a compressed block");
    // one frame per block (30000 frames) ...
    let frames: Vec<u8> = (0..30_000).flat_map(|_| single.clone()).collect();
    let started = Instant::now();
    let (outcome, total, r) = count(Box::new(&frames[..]), DEFAULT_MAX_WINDOW, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 30_000 * payload.len() as u64));
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(r.heap_bytes() < 1 << 20, "{}", r.heap_bytes());
    // ... and 30000 compressed blocks in one frame
    let mut one = single[..6].to_vec();
    for _ in 0..29_999 {
        let mut b = block.to_vec();
        b[0] &= !1; // not the last block
        one.extend(b);
    }
    one.extend(block);
    let started = Instant::now();
    let (outcome, total, r) = count(Box::new(&one[..]), DEFAULT_MAX_WINDOW, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 30_000 * payload.len() as u64));
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(r.heap_bytes() < 1 << 20, "{}", r.heap_bytes());
}

#[test]
fn chains_with_other_codecs_still_see_a_plain_stream() {
    // Covers: SG-R-LAY-01
    // zstd inside zstd: the output of one is the input of the other
    let inner = compress(&text());
    let outer = compress(&inner);
    let (outcome, middle) = run(&outer);
    assert_eq!(outcome, Ok(()));
    assert_eq!(run(&middle), (Ok(()), text()));
}

// =========================================================================================
// the window ring: regressions of the review of the TypeScript port
// =========================================================================================

#[test]
fn a_block_as_large_as_the_window_keeps_the_ring_consistent_for_later_matches() {
    // Covers: SG-R-CDC-05
    // Found by the independent review of the TypeScript port: after a block of exactly the window
    // size the write position must be 0.
    let big: Vec<u8> = (0..1024u32).map(|i| ((i * 13 + 7) & 255) as u8).collect();
    let sequence = [0x00, 0x01, 0x00, 0, 0, 2];
    let frame = concat(&[
        &[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00],
        &block_header(false, 0, 3),
        b"XYZ",
        &block_header(false, 0, 1024),
        &big,
        &block_header(true, 2, sequence.len()),
        &sequence,
    ]);
    let (outcome, out) = run(&frame);
    assert_eq!(outcome, Ok(()));
    assert_eq!(Some(out), oracle(&frame));
}

#[test]
fn the_window_ring_position_stays_modulo_the_declared_window() {
    // Covers: SG-R-CDC-05
    let mut w = Window::new(1024);
    w.push(&[1u8; 1024]).unwrap();
    assert_eq!(
        w.pos_for_test(),
        0,
        "a block exactly as large as the window leaves the position at 0"
    );
    w.push(&[2u8; 1024]).unwrap();
    assert_eq!(w.pos_for_test(), 0);
    w.push(&[3u8; 5000]).unwrap(); // larger than the window: only the newest 1024 bytes matter
    assert_eq!(w.pos_for_test(), 0);
    w.push(&[4u8; 10]).unwrap();
    assert_eq!(w.pos_for_test(), 10);
    w.push(&[5u8; 1020]).unwrap();
    assert_eq!(w.pos_for_test(), 6, "positions wrap at the declared window");
    assert_eq!(w.total(), 1024 + 1024 + 5000 + 10 + 1020);
}

#[test]
fn the_window_agrees_with_a_naive_history_for_random_pushes() {
    // Covers: SG-R-CDC-05
    let mut seed = 99u64;
    let mut next = move |n: usize| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((seed >> 33) as usize) % n
    };
    for ring in [1usize, 2, 3, 16, 100, 1024, 4096] {
        let mut w = Window::new(ring);
        let mut naive: Vec<u8> = Vec::new();
        for _ in 0..200 {
            let len = match next(4) {
                0 => 0,
                1 => next(ring + 1),
                2 => ring,
                _ => next(3 * ring + 1),
            };
            let bytes = data(next(1000) as u64, len);
            w.push(&bytes).unwrap();
            naive.extend(&bytes);
            // the last min(ring, total) bytes are readable at every distance
            let d_max = naive.len().min(ring);
            if d_max == 0 {
                continue;
            }
            for _ in 0..4 {
                let d = 1 + next(d_max);
                let n = 1 + next(d);
                let mut got = Vec::new();
                w.copy_history_for_test(d, n, &mut got).unwrap();
                let start = naive.len() - d;
                assert_eq!(got, &naive[start..start + n], "ring {ring} distance {d} length {n}");
            }
        }
    }
}

#[test]
fn the_window_is_not_allocated_eagerly_at_the_declared_size() {
    // Covers: SG-R-CDC-05 SG-R-RAT-02 SG-R-MEM-01
    let mut w = Window::new(1 << 30);
    assert_eq!(w.capacity(), 0, "a new window holds nothing");
    w.push(b"hello").unwrap();
    assert!(w.capacity() < 1 << 20, "{}", w.capacity());
    // growth follows the output, at most doubling
    let mut pushed = 5usize;
    for _ in 0..20 {
        w.push(&vec![1u8; 100_000]).unwrap();
        pushed += 100_000;
        assert!(
            w.capacity() <= pushed * 2 + 1024,
            "capacity {} for {pushed} bytes",
            w.capacity()
        );
    }
    let frame = Frame::new(1 << 30);
    assert_eq!(frame.window_capacity(), 0);
}

#[test]
fn no_block_sized_zero_fill_for_a_tiny_block() {
    // Covers: SG-R-RAT-02 SG-R-MEM-02
    // one scratch buffer per reader: tiny blocks must not grow the buffers to the block maximum
    let mut stream = window_header(23);
    for i in 0..1000 {
        stream.extend(block_header(false, 0, 3));
        stream.extend([i as u8, 1, 2]);
    }
    stream.extend(raw_blocks(b"z", 1, true));
    let (outcome, total, r) = count(Box::new(&stream[..]), DEFAULT_MAX_WINDOW, u64::MAX);
    assert_eq!((outcome, total), (Ok(()), 3001));
    assert!(r.heap_bytes() < 64 * 1024, "{}", r.heap_bytes());
}

#[test]
fn matches_across_the_ring_boundary_agree_with_the_reference() {
    // Covers: SG-R-CDC-05
    // small windows force every match to straddle the ring end many times
    let payload: Vec<u8> = (0..200_000u32)
        .map(|i| (((i % 701) * 31 + (i / 701) % 5) & 0xff) as u8)
        .collect();
    for window_log in 10..=14 {
        for level in [1, 3, 9, 19] {
            let params = Params {
                window_log: Some(window_log),
                checksum: Some(true),
                ..Params::default()
            };
            let stream = compress_with(&payload, level, params);
            let (outcome, out) = run_cap(&stream, 1 << 20);
            assert_eq!(outcome, Ok(()), "window {window_log} level {level}");
            assert!(out == payload, "window {window_log} level {level}");
        }
    }
}

// =========================================================================================
// the parts
// =========================================================================================

#[test]
fn backward_bits_read_from_the_end_and_zero_fill_past_the_start() {
    // Covers: SG-I-05
    assert!(BackwardBits::new(&[]).is_err());
    assert!(BackwardBits::new(&[0x12, 0x00]).is_err());
    // 0b0000_0101 -> the sentinel is bit 2, so two data bits (01) remain
    let mut b = BackwardBits::new(&[0x05]).unwrap();
    assert_eq!(b.remaining, 2);
    assert_eq!(b.read(2), 0b01);
    assert_eq!(b.remaining, 0);
    // reading past the start gives zeros and a negative count
    assert_eq!(b.read(3), 0);
    assert_eq!(b.remaining, -3);
    let mut c = BackwardBits::new(&[0xff, 0x01]).unwrap();
    assert_eq!(c.remaining, 8);
    assert_eq!(c.peek(4), 0xf);
    assert_eq!(c.remaining, 8);
    assert_eq!(
        c.read(12),
        0xff0,
        "four bits before the start read as zeros at the low end"
    );
    // forward bits
    let mut f = ForwardBits::new(&[0b1010_0101, 0xff]);
    assert_eq!(f.read(4), 0b0101);
    assert_eq!(f.read(4), 0b1010);
    assert_eq!(f.bytes_used(), 1);
    assert!(!f.overrun());
    f.read(9);
    assert!(f.overrun());
    f.unread(9);
    assert!(!f.overrun());
}

#[test]
fn fse_tables_reject_bad_distributions() {
    // Covers: SG-I-05
    // a distribution that does not add up to the table size
    assert!(build_table(&[1, 1], 2).is_err());
    assert!(build_table(&[2, 2, 1], 2).is_err());
    assert!(build_table(&[2, 2], 2).is_ok());
    assert!(build_table(&[4], 2).is_ok());
    assert!(build_table(&[-1, -1, 2], 2).is_ok());
    // accuracy beyond 9 is never needed
    assert!(build_table(&[1024], 10).is_err());
    // descriptions: every length of truncated and zero input errors or is bounded, never panics
    for len in 0..8 {
        for fill in [0x00u8, 0xff, 0x55, 0xaa] {
            let _ = read_table(&vec![fill; len], 9, 35);
        }
    }
    assert!(read_table(&[0xf0], 6, 15).is_err(), "accuracy log above the maximum");
}

#[test]
fn huffman_descriptions_reject_what_is_not_a_tree() {
    // Covers: SG-I-05
    assert!(read_huffman_table(&[]).is_err());
    assert!(read_huffman_table(&[0]).is_err(), "an FSE description of size zero");
    assert!(read_huffman_table(&[5, 1, 2]).is_err(), "shorter than announced");
    assert!(read_huffman_table(&[128, 0x00]).is_err(), "no codes");
    // two weights of 1 and an implied one of 1... 1 + 1 -> total 2, power 4, rest 2: a valid three symbol tree
    let (table, used) = read_huffman_table(&[129, 0x11]).unwrap();
    assert_eq!(used, 2);
    drop(table);
    // weights 3 and 1: total 5, power 8, rest 3 is not a power of two
    assert!(read_huffman_table(&[129, 0x31]).is_err());
    // every one-byte header and a few fill patterns never panic
    for header in 0..=255u8 {
        for fill in [0x00u8, 0xff, 0x13, 0xa7] {
            let mut bytes = vec![header];
            bytes.extend(vec![fill; 40]);
            let _ = read_huffman_table(&bytes);
        }
    }
}

#[test]
fn the_decoder_never_panics_on_short_garbage_after_a_valid_header() {
    // Covers: SG-I-05 SG-R-CDC-08
    // compressed blocks of every small size with every fill byte after a valid header
    for size in 0..40usize {
        for fill in [0x00u8, 0x01, 0x02, 0x55, 0x80, 0xfe, 0xff] {
            let mut stream = window_header(17);
            stream.extend(block_header(true, 2, size));
            stream.extend(vec![fill; size]);
            let (outcome, _) = run(&stream);
            assert!(
                outcome.is_ok() || outcome == Err(ErrorKind::Corrupt),
                "size {size} fill {fill:#x}"
            );
        }
    }
    // the same with random content
    for seed in 0..300u64 {
        let size = 1 + (seed as usize % 200);
        let mut stream = window_header(17);
        stream.extend(block_header(true, 2, size));
        stream.extend(data(seed, size));
        let (outcome, _) = run(&stream);
        assert!(outcome.is_ok() || outcome == Err(ErrorKind::Corrupt), "seed {seed}");
    }
}

#[test]
fn a_panic_free_decoder_on_every_two_byte_prefix_of_a_frame_header() {
    // Covers: SG-I-05 SG-R-CDC-08
    for descriptor in 0..=255u8 {
        for second in [0u8, 1, 0x7f, 0x80, 0xff] {
            let mut stream = vec![0x28, 0xb5, 0x2f, 0xfd, descriptor, second];
            stream.extend([0u8; 12]);
            let (outcome, _) = run_cap(&stream, 1 << 20);
            assert!(outcome.is_ok() || ALLOWED.contains(&outcome.unwrap_err()));
        }
    }
}

// -- speed (not a pass or fail test: run with `cargo test --release -- --ignored --nocapture`) --

#[test]
#[ignore = "benchmark"]
fn decode_speed_against_the_reference() {
    // word salad: compressible about 3:1 with plenty of short matches and literals, like real text
    let words: Vec<Vec<u8>> = (0..2000u64)
        .map(|i| data(i, 2 + (i as usize % 9)).iter().map(|b| b'a' + b % 26).collect())
        .collect();
    let payload = {
        let picks = data(42, 3_000_000);
        let mut v = Vec::new();
        for pair in picks.chunks_exact(2) {
            v.extend(&words[(usize::from(pair[0]) * 8 + usize::from(pair[1]) % 8) % words.len()]);
            v.push(b' ');
        }
        v
    };
    for level in [1, 3, 9, 19] {
        let stream = compress_with(
            &payload,
            level,
            Params {
                checksum: Some(true),
                ..Params::default()
            },
        );
        let started = Instant::now();
        let reps = 5;
        for _ in 0..reps {
            let (outcome, total, _) = count(Box::new(&stream[..]), 1 << 27, u64::MAX);
            assert_eq!((outcome, total), (Ok(()), payload.len() as u64));
        }
        let ours = started.elapsed() / reps;
        let started = Instant::now();
        for _ in 0..reps {
            assert_eq!(zstd::stream::decode_all(&stream[..]).unwrap().len(), payload.len());
        }
        let theirs = started.elapsed() / reps;
        let mb = payload.len() as f64 / 1e6;
        println!(
            "level {level}: {} KB compressed, ours {:.0} MB/s, reference {:.0} MB/s",
            stream.len() / 1000,
            mb / ours.as_secs_f64(),
            mb / theirs.as_secs_f64()
        );
    }
}

#[test]
fn bytes_after_a_zero_sequence_count_are_corrupt() {
    // Covers: SG-R-CDC-05
    // Found by the bit flip differential test: with no sequences the block must end at the count.
    let block = |tail: &[u8]| {
        let mut content = vec![0x18, b'a', b'b', b'c', 0x00]; // raw literals "abc", zero sequences
        content.extend(tail);
        concat(&[&window_header(17), &block_header(true, 2, content.len()), &content])
    };
    assert_eq!(run(&block(&[])), (Ok(()), b"abc".to_vec()));
    assert_eq!(oracle(&block(&[])), Some(b"abc".to_vec()));
    assert_eq!(run(&block(&[0x04])).0, Err(ErrorKind::Corrupt));
    assert_eq!(run(&block(&[0x00, 0x00])).0, Err(ErrorKind::Corrupt));
    assert_eq!(oracle(&block(&[0x04])), None);
}
