//! Helpers shared by the brotli integration tests (`tests/br_*.rs`).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::io::{self, BufRead, Read};
use std::rc::Rc;

use spillgate::br::{self, BrotliOptions};
use spillgate::{Decoder, Error, ErrorKind, Limits};

/// Loose limits: 1 GiB output, no ratio check.
pub fn loose() -> Limits {
    Limits::new(1 << 30).disable_ratio_limit()
}

/// A decoder with the brotli codec registered under `br`, window cap `cap` bits.
pub fn decoder(limits: Limits, cap: u32) -> Decoder {
    Decoder::builder(limits)
        .codec("br", br::codec(BrotliOptions { max_window_bits: cap }).unwrap())
        .build()
        .unwrap()
}

pub fn loose_decoder() -> Decoder {
    decoder(loose(), 24)
}

/// The typed kind inside an io error returned by a spillgate reader.
pub fn kind_of(error: &io::Error) -> ErrorKind {
    Error::from_io(error)
        .unwrap_or_else(|| panic!("not a spillgate error: {error:?}"))
        .kind()
}

/// What a run delivered before its end: the bytes and the error kind (None = clean end).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Outcome {
    pub bytes: Vec<u8>,
    pub kind: Option<ErrorKind>,
}

/// Read `reader` to the end with reads of `read_size`; no single read may return more than 64 KiB
/// (the output step of the codec) or more than `read_size`.
pub fn drain<R: Read>(reader: &mut R, read_size: usize) -> Outcome {
    let mut bytes = Vec::new();
    let mut buf = vec![0u8; read_size];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Outcome { bytes, kind: None },
            Ok(n) => {
                assert!(n <= read_size, "a read returned more than it was asked for");
                assert!(
                    n <= 64 * 1024,
                    "a single read returned {n} bytes, more than the 64 KiB step"
                );
                bytes.extend_from_slice(&buf[..n]);
            }
            Err(e) => {
                return Outcome {
                    bytes,
                    kind: Some(kind_of(&e)),
                }
            }
        }
    }
}

/// Decode `data` through `header` with a source that hands out `chunk` bytes per read.
pub fn run_with(decoder: &Decoder, data: &[u8], header: &[&str], read_size: usize, chunk: usize) -> Outcome {
    match decoder.reader(Src::new(data, chunk), header) {
        Err(e) => Outcome {
            bytes: Vec::new(),
            kind: Some(e.kind()),
        },
        Ok(mut reader) => {
            let out = drain(&mut reader, read_size);
            reader.close();
            out
        }
    }
}

/// Decode `data` as brotli under `limits` (cap 24), reads of 4096, one chunk source.
pub fn run(data: &[u8], limits: Limits) -> Outcome {
    run_with(&decoder(limits, 24), data, &["br"], 4096, usize::MAX)
}

pub fn run_cap(data: &[u8], cap: u32) -> Outcome {
    run_with(&decoder(loose(), cap), data, &["br"], 4096, usize::MAX)
}

/// A source that counts what is asked of it.
#[derive(Clone, Default)]
pub struct Counters {
    pub reads: Rc<Cell<usize>>,
    pub bytes: Rc<Cell<usize>>,
}

pub struct Src {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    pub counters: Counters,
}

impl Src {
    pub fn new(data: &[u8], chunk: usize) -> Src {
        Src {
            data: data.to_vec(),
            pos: 0,
            chunk: chunk.max(1),
            counters: Counters::default(),
        }
    }
}

impl Read for Src {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.counters.reads.set(self.counters.reads.get() + 1);
        let n = buf.len().min(self.chunk).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.counters.bytes.set(self.counters.bytes.get() + n);
        Ok(n)
    }
}

/// A BufRead that records how much a codec consumes and whether it ever consumes more than it was shown.
pub struct Recording {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    shown: usize,
    pub stats: Rc<Stats>,
}

#[derive(Default)]
pub struct Stats {
    pub consumed: Cell<usize>,
    pub fills: Cell<usize>,
    pub violations: Cell<usize>,
}

impl Recording {
    pub fn new(data: &[u8], chunk: usize) -> Recording {
        Recording {
            data: data.to_vec(),
            pos: 0,
            chunk: chunk.max(1),
            shown: 0,
            stats: Rc::default(),
        }
    }
}

impl Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = {
            let view = self.fill_buf()?;
            let n = view.len().min(buf.len());
            buf[..n].copy_from_slice(&view[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Recording {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.stats.fills.set(self.stats.fills.get() + 1);
        let end = (self.pos + self.chunk).min(self.data.len());
        self.shown = end - self.pos;
        Ok(&self.data[self.pos..end])
    }
    fn consume(&mut self, amt: usize) {
        if amt > self.shown {
            self.stats.violations.set(self.stats.violations.get() + 1);
        }
        let amt = amt.min(self.shown);
        self.shown -= amt;
        self.pos += amt;
        self.stats.consumed.set(self.stats.consumed.get() + amt);
    }
}

// -- compressing ---------------------------------------------------------------------------------

/// Compress with the reference encoder.
pub fn compress(payload: &[u8], quality: i32, lgwin: i32) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams {
        quality,
        lgwin,
        ..Default::default()
    };
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut &payload[..], &mut out, &params).expect("the encoder failed");
    out
}

/// Compress with the large-window extension on.
pub fn compress_large_window(payload: &[u8], quality: i32, lgwin: i32) -> Vec<u8> {
    let params = brotli::enc::BrotliEncoderParams {
        quality,
        lgwin,
        large_window: true,
        ..Default::default()
    };
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut &payload[..], &mut out, &params).expect("the encoder failed");
    out
}

/// The reference decoder: the `brotli` crate's decompressor, read at most `cap` bytes. `None` if it
/// fails or reaches the cap.
pub fn reference_decode(stream: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut reader = brotli::Decompressor::new(stream, 4096).take(cap as u64);
    let mut out = Vec::new();
    match reader.read_to_end(&mut out) {
        Ok(_) if out.len() < cap => Some(out),
        _ => None,
    }
}

// -- payloads ------------------------------------------------------------------------------------

pub fn text(n: usize) -> Vec<u8> {
    let line = b"The quick brown fox jumps over the lazy dog; pack my box with five dozen liquor jugs. ";
    line.iter().copied().cycle().take(n).collect()
}

pub fn noise(seed: u64, n: usize) -> Vec<u8> {
    spillgate_test_support::data(seed, n)
}

pub fn mixed(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut seed = 1;
    while out.len() < n {
        out.extend(text(2000));
        out.extend(noise(seed, 1500));
        out.extend(vec![0u8; 3000]);
        out.extend((0..=255u8).cycle().take(700));
        seed += 1;
    }
    out.truncate(n);
    out
}

/// The small payloads of the round-trip matrix.
pub fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("one byte", vec![b'a']),
        ("text", text(3000)),
        ("noise", noise(7, 2000)),
        ("zeros", vec![0u8; 100_000]),
        ("mixed", mixed(20_000)),
    ]
}

/// Deterministic xorshift generator.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}
