//! Tests of the DEFLATE decoder, the gzip and the deflate (zlib) codecs. The reference is flate2
//! (a dev-dependency only) where it applies; the expectations of the hand-built streams are our
//! reading of RFC 1951 and are compared with flate2 in addition.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::Cell;
use std::io::{self, BufRead, Read, Write};
use std::rc::Rc;

use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::Compression;

use super::*;
use crate::codec::Codec;
use crate::deflate::{adler32, is_zlib_header, DeflateCodec};
use crate::error::ErrorKind;
use crate::gzip::{crc32, GzipCodec};

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

/// A `BufRead` that hands out at most `chunk` bytes per `fill_buf`, counts what is consumed and
/// fails the test if more is consumed than was offered.
struct Chunked<'a> {
    data: &'a [u8],
    pos: Rc<Cell<usize>>,
    chunk: usize,
    avail: usize,
}

impl<'a> Chunked<'a> {
    fn new(data: &'a [u8], chunk: usize) -> (Chunked<'a>, Rc<Cell<usize>>) {
        let pos = Rc::new(Cell::new(0));
        (
            Chunked {
                data,
                pos: pos.clone(),
                chunk: chunk.max(1),
                avail: 0,
            },
            pos,
        )
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = {
            let rest = self.fill_buf()?;
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Chunked<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let start = self.pos.get();
        let end = start.saturating_add(self.chunk).min(self.data.len());
        self.avail = end - start;
        Ok(&self.data[start..end])
    }

    fn consume(&mut self, amount: usize) {
        assert!(
            amount <= self.avail,
            "consumed {amount} but only {} were offered",
            self.avail
        );
        self.avail -= amount;
        self.pos.set(self.pos.get() + amount);
    }
}

const NO_CHUNKING: usize = usize::MAX;
const BIG_READ: usize = 65536;
const OUTPUT_CAP: usize = 256 << 20;

/// Read a codec to the end with read buffers of `read_size`. Returns the outcome and the number
/// of input bytes consumed.
fn run_codec(codec: &dyn Codec, data: &[u8], chunk: usize, read_size: usize) -> (Result<Vec<u8>, Error>, usize) {
    let (input, pos) = Chunked::new(data, chunk);
    let mut reader = codec.new_reader(Box::new(input));
    let mut out = Vec::new();
    let mut buf = vec![0u8; read_size];
    let result = loop {
        match reader.read(&mut buf) {
            Ok(0) => break Ok(out),
            Ok(n) => {
                assert!(n <= buf.len(), "a codec returned more than the buffer");
                out.extend_from_slice(&buf[..n]);
                assert!(out.len() <= OUTPUT_CAP, "runaway output");
            }
            Err(e) => break Err(e),
        }
    };
    if result.is_err() {
        // errors are stable: the next read fails too and never panics
        assert!(
            reader.read(&mut buf).is_err(),
            "a codec that failed read again without failing"
        );
    } else {
        assert_eq!(reader.read(&mut buf).unwrap(), 0, "the clean end is stable");
    }
    drop(reader);
    (result, pos.get())
}

fn run_inflater(data: &[u8], chunk: usize, read_size: usize) -> (Result<Vec<u8>, Error>, usize) {
    let (mut input, pos) = Chunked::new(data, chunk);
    let mut inflater = Inflater::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; read_size];
    let result = loop {
        match inflater.read(&mut input, &mut buf) {
            Ok(0) => break Ok(out),
            Ok(n) => {
                assert!(n <= buf.len());
                out.extend_from_slice(&buf[..n]);
                assert!(out.len() <= OUTPUT_CAP, "runaway output");
            }
            Err(e) => break Err(e),
        }
    };
    if result.is_ok() {
        assert!(inflater.finished());
        assert_eq!(inflater.read(&mut input, &mut buf).unwrap(), 0);
    }
    (result, pos.get())
}

fn gzip_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    run_codec(&GzipCodec, data, NO_CHUNKING, BIG_READ).0
}

fn deflate_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    run_codec(&DeflateCodec::new(false), data, NO_CHUNKING, BIG_READ).0
}

fn raw_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    run_inflater(data, NO_CHUNKING, BIG_READ).0
}

fn assert_corrupt<T: std::fmt::Debug>(result: Result<T, Error>, what: &str) {
    match result {
        Err(e) => assert_eq!(e.kind(), ErrorKind::Corrupt, "{what}: {e}"),
        Ok(v) => panic!("{what}: expected corrupt, decoded {v:?}"),
    }
}

/// A small deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64).max(1)) as usize
    }
}

const WORDS: [&str; 16] = [
    "the ",
    "quick ",
    "brown ",
    "fox ",
    "jumps ",
    "over ",
    "lazy ",
    "dog ",
    "content-encoding ",
    "gzip ",
    "deflate ",
    "window ",
    "huffman ",
    "\n",
    "spillgate ",
    "bomb ",
];

const KINDS: usize = 8;

fn kind_name(kind: usize) -> &'static str {
    [
        "zeros",
        "random",
        "text",
        "runs",
        "alphabet4",
        "counter",
        "repeat-block",
        "mixed",
    ][kind % KINDS]
}

/// `n` bytes of data of the given kind.
fn gen(kind: usize, n: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed.wrapping_add(kind as u64 * 7919));
    let mut v = Vec::with_capacity(n);
    match kind % KINDS {
        0 => v.resize(n, 0),
        1 => {
            while v.len() < n {
                v.push(rng.next() as u8);
            }
        }
        2 => {
            while v.len() < n {
                v.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes());
            }
        }
        3 => {
            while v.len() < n {
                let b = rng.next() as u8;
                let run = 1 + rng.below(300);
                v.resize(v.len() + run, b);
            }
        }
        4 => {
            while v.len() < n {
                v.push(b"ACGT"[rng.below(4)]);
            }
        }
        5 => {
            for i in 0..n {
                v.push(i as u8);
            }
        }
        6 => {
            // a random block repeated: distances equal to the block length, up to and past the window
            let block_len = [100, 4000, 32767, 32768, 32769, 40000][rng.below(6)];
            let block: Vec<u8> = (0..block_len).map(|_| rng.next() as u8).collect();
            while v.len() < n {
                v.extend_from_slice(&block);
            }
        }
        _ => {
            while v.len() < n {
                let piece = gen(rng.below(7), 1 + rng.below(3000), rng.next());
                v.extend_from_slice(&piece);
            }
        }
    }
    v.truncate(n);
    v
}

fn enc_raw(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn enc_zlib(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn enc_gzip(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Raw DEFLATE written in pieces with a sync flush after each: empty stored blocks, byte aligned
/// block boundaries.
fn enc_raw_flushed(data: &[u8], level: u32, piece: usize) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    for part in data.chunks(piece.max(1)) {
        e.write_all(part).unwrap();
        e.flush().unwrap();
    }
    e.finish().unwrap()
}

/// What flate2 makes of a raw stream: the output and the bytes it consumed, or `None`.
fn ref_raw(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut d = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok()?;
    Some((out, d.total_in() as usize))
}

fn ref_zlib(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data).read_to_end(&mut out).ok()?;
    Some(out)
}

fn ref_gzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data).read_to_end(&mut out).ok()?;
    Some(out)
}

/// A bit writer for hand-built streams.
#[derive(Default, Clone)]
struct Bits {
    bits: Vec<u8>,
}

impl Bits {
    fn new() -> Bits {
        Bits::default()
    }
    /// A field: least significant bit first.
    fn put(&mut self, value: u32, n: u32) -> &mut Bits {
        for i in 0..n {
            self.bits.push(((value >> i) & 1) as u8);
        }
        self
    }
    /// A Huffman code: most significant bit first.
    fn code(&mut self, value: u32, n: u32) -> &mut Bits {
        for i in (0..n).rev() {
            self.bits.push(((value >> i) & 1) as u8);
        }
        self
    }
    fn align(&mut self) -> &mut Bits {
        while self.bits.len() % 8 != 0 {
            self.bits.push(0);
        }
        self
    }
    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.bits.len().div_ceil(8)];
        for (i, bit) in self.bits.iter().enumerate() {
            out[i >> 3] |= bit << (i & 7);
        }
        out
    }
}

#[derive(Clone, Copy, Debug)]
enum Tok {
    Lit(u8),
    Match { len: usize, dist: usize },
}

fn fixed_lit_code(w: &mut Bits, sym: u32) {
    match sym {
        0..=143 => w.code(0x30 + sym, 8),
        144..=255 => w.code(0x190 + sym - 144, 9),
        256..=279 => w.code(sym - 256, 7),
        _ => w.code(0xc0 + sym - 280, 8),
    };
}

fn length_symbol(len: usize) -> (u32, u32, u32) {
    for sym in (0..29).rev() {
        if usize::from(LENGTH_BASE[sym]) <= len {
            let extra_bits = u32::from(LENGTH_EXTRA_BITS[sym]);
            return (
                257 + sym as u32,
                extra_bits,
                (len - usize::from(LENGTH_BASE[sym])) as u32,
            );
        }
    }
    unreachable!()
}

fn distance_symbol(dist: usize) -> (u32, u32, u32) {
    for sym in (0..30).rev() {
        if usize::from(DISTANCE_BASE[sym]) <= dist {
            let extra_bits = u32::from(DISTANCE_EXTRA_BITS[sym]);
            return (sym as u32, extra_bits, (dist - usize::from(DISTANCE_BASE[sym])) as u32);
        }
    }
    unreachable!()
}

/// A fixed Huffman block.
fn fixed_block(w: &mut Bits, toks: &[Tok], last: bool) {
    w.put(u32::from(last), 1).put(1, 2);
    for &t in toks {
        match t {
            Tok::Lit(b) => fixed_lit_code(w, u32::from(b)),
            Tok::Match { len, dist } => {
                let (ls, lb, lv) = length_symbol(len);
                fixed_lit_code(w, ls);
                w.put(lv, lb);
                let (ds, db, dv) = distance_symbol(dist);
                w.code(ds, 5);
                w.put(dv, db);
            }
        }
    }
    fixed_lit_code(w, 256);
}

fn stored_block(w: &mut Bits, data: &[u8], last: bool) {
    w.put(u32::from(last), 1).put(0, 2).align();
    w.put(data.len() as u32, 16).put(!(data.len() as u32) & 0xffff, 16);
    for &b in data {
        w.put(u32::from(b), 8);
    }
}

/// Tokens that reproduce `data` with matches where they are cheap to find (a naive search over
/// the last 300 bytes plus run detection).
fn tokenize(data: &[u8]) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut best = (0usize, 0usize);
        let lo = i.saturating_sub(300);
        for start in lo..i {
            let mut l = 0;
            while i + l < data.len() && l < 258 && data[start + l] == data[i + l] {
                l += 1;
            }
            if l > best.0 {
                best = (l, i - start);
            }
        }
        if best.0 >= 3 {
            toks.push(Tok::Match {
                len: best.0,
                dist: best.1,
            });
            i += best.0;
        } else {
            toks.push(Tok::Lit(data[i]));
            i += 1;
        }
    }
    toks
}

fn zlib_wrap(raw: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x78, 0x9c];
    v.extend_from_slice(raw);
    v.extend_from_slice(&adler32(payload, 1).to_be_bytes());
    v
}

fn gzip_member(raw: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    v.extend_from_slice(raw);
    v.extend_from_slice(&crc32(payload, 0).to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}

fn stored_stream(payload: &[u8]) -> Vec<u8> {
    let mut w = Bits::new();
    if payload.is_empty() {
        stored_block(&mut w, &[], true);
    }
    let pieces: Vec<&[u8]> = payload.chunks(65535).collect();
    for (i, p) in pieces.iter().enumerate() {
        stored_block(&mut w, p, i + 1 == pieces.len());
    }
    w.bytes()
}

// ---------------------------------------------------------------------------------------------
// checksums
// ---------------------------------------------------------------------------------------------

#[test]
fn checksum_known_values() {
    // Covers: SG-R-CDC-02
    assert_eq!(crc32(b"", 0), 0);
    assert_eq!(crc32(b"123456789", 0), 0xcbf4_3926);
    assert_eq!(crc32(b"a", 0), 0xe8b7_be43);
    // Covers: SG-R-CDC-03
    assert_eq!(adler32(b"", 1), 1);
    assert_eq!(adler32(b"Wikipedia", 1), 0x11e6_0398);
    assert_eq!(adler32(&[0xff; 100_000], 1), naive_adler(&[0xff; 100_000]));
}

fn naive_adler(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u64, 0u64);
    for &x in data {
        a = (a + u64::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    ((b << 16) | a) as u32
}

#[test]
fn checksums_match_references_for_every_length_and_split() {
    // Covers: SG-R-CDC-02 SG-R-CDC-03
    let mut rng = Rng::new(1);
    for len in (0..300usize).chain([1000, 5551, 5552, 5553, 11104, 70_000]) {
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let mut reference = flate2::Crc::new();
        reference.update(&data);
        assert_eq!(crc32(&data, 0), reference.sum(), "crc32 length {len}");
        assert_eq!(adler32(&data, 1), naive_adler(&data), "adler32 length {len}");
        for split in [0, 1, 7, 8, 9, len / 2, len.saturating_sub(1), len] {
            let split = split.min(len);
            let (a, b) = data.split_at(split);
            assert_eq!(crc32(b, crc32(a, 0)), crc32(&data, 0), "crc32 split {split}/{len}");
            assert_eq!(
                adler32(b, adler32(a, 1)),
                adler32(&data, 1),
                "adler32 split {split}/{len}"
            );
        }
    }
    // all-0xff data is the worst case for the adler sums
    for len in [5551, 5552, 5553, 100_000] {
        let data = vec![0xffu8; len];
        assert_eq!(adler32(&data, 1), naive_adler(&data));
    }
}

// ---------------------------------------------------------------------------------------------
// round trips against flate2
// ---------------------------------------------------------------------------------------------

#[test]
fn round_trip_matrix_all_levels_and_formats() {
    // Covers: SG-R-CDC-02 SG-R-CDC-03 SG-R-RDR-01
    let sizes = [
        0, 1, 2, 3, 10, 100, 1000, 4095, 4096, 4097, 32767, 32768, 32769, 65536, 100_000, 300_000,
    ];
    let gz = GzipCodec;
    let zl = DeflateCodec::new(true);
    for (si, &size) in sizes.iter().enumerate() {
        for kind in 0..KINDS {
            let data = gen(kind, size, si as u64);
            for level in [0, 1, 3, 6, 9] {
                if size > 100_000 && level != 6 && level != 0 {
                    continue;
                }
                let name = format!("size {size} kind {} level {level}", kind_name(kind));
                let raw = enc_raw(&data, level);
                let (out, used) = run_inflater(&raw, NO_CHUNKING, BIG_READ);
                assert_eq!(out.unwrap(), data, "raw {name}");
                assert_eq!(used, raw.len(), "raw accounting {name}");
                if !is_zlib_header(raw.first().copied().unwrap_or(0), raw.get(1).copied().unwrap_or(0)) {
                    // the HTTP deflate codec with the raw fallback
                    let (out, used) = run_codec(&DeflateCodec::new(false), &raw, 4096, BIG_READ);
                    assert_eq!(out.unwrap(), data, "raw via deflate codec {name}");
                    assert_eq!(used, raw.len());
                }
                let z = enc_zlib(&data, level);
                let (out, used) = run_codec(&zl, &z, NO_CHUNKING, BIG_READ);
                assert_eq!(out.unwrap(), data, "zlib {name}");
                assert_eq!(used, z.len(), "zlib accounting {name}");
                let g = enc_gzip(&data, level);
                let (out, used) = run_codec(&gz, &g, NO_CHUNKING, BIG_READ);
                assert_eq!(out.unwrap(), data, "gzip {name}");
                assert_eq!(used, g.len(), "gzip accounting {name}");
            }
        }
    }
}

#[test]
fn round_trip_with_flush_points() {
    // Covers: SG-R-CDC-03 SG-R-RDR-01
    for kind in 0..KINDS {
        for piece in [1usize, 7, 100, 1000, 40000] {
            let data = gen(kind, 20_000, piece as u64);
            for level in [0, 1, 6] {
                let raw = enc_raw_flushed(&data, level, piece);
                let (out, used) = run_inflater(&raw, 100, 777);
                assert_eq!(out.unwrap(), data, "{} piece {piece} level {level}", kind_name(kind));
                assert_eq!(used, raw.len());
                assert_eq!(ref_raw(&raw).unwrap().0, data);
            }
        }
    }
}

#[test]
fn every_chunking_and_read_size_gives_the_same_output_and_accounting() {
    // Covers: SG-R-RDR-01 SG-R-CDC-01 SG-R-RAT-02
    let chunks = [1, 2, 3, 5, 7, 13, 64, 1000, 4096, NO_CHUNKING];
    let reads = [1, 2, 3, 7, 100, 4096, BIG_READ];
    for (size, kinds) in [(0usize, 1usize), (1, 2), (300, 8), (3000, 8), (40_000, 8)] {
        for kind in 0..kinds {
            let data = gen(kind, size, 99);
            let raw = enc_raw(&data, 6);
            let z = enc_zlib(&data, 6);
            let g = enc_gzip(&data, 6);
            for &chunk in &chunks {
                for &read in &reads {
                    if size > 3000 && (read < 7 || (chunk < 7 && read < 100)) {
                        continue; // too slow in a debug build; the small sizes cover these
                    }
                    let tag = format!("size {size} kind {} chunk {chunk} read {read}", kind_name(kind));
                    let (out, used) = run_inflater(&raw, chunk, read);
                    assert_eq!(out.unwrap(), data, "raw {tag}");
                    assert_eq!(used, raw.len(), "raw accounting {tag}");
                    let (out, used) = run_codec(&DeflateCodec::new(true), &z, chunk, read);
                    assert_eq!(out.unwrap(), data, "zlib {tag}");
                    assert_eq!(used, z.len(), "zlib accounting {tag}");
                    let (out, used) = run_codec(&GzipCodec, &g, chunk, read);
                    assert_eq!(out.unwrap(), data, "gzip {tag}");
                    assert_eq!(used, g.len(), "gzip accounting {tag}");
                }
            }
        }
    }
}

#[test]
fn hand_built_streams_with_every_chunking() {
    // Covers: SG-R-RDR-01 SG-R-CDC-08
    let data = gen(2, 5000, 5);
    let mut w = Bits::new();
    stored_block(&mut w, &data[..1000], false);
    fixed_block(&mut w, &tokenize(&data[1000..3000]), false);
    stored_block(&mut w, &[], false);
    fixed_block(&mut w, &tokenize(&data[3000..]), true);
    let raw = w.bytes();
    assert_eq!(ref_raw(&raw).unwrap().0, data);
    for chunk in [1, 2, 3, 4, 5, 8, 9, 100, NO_CHUNKING] {
        for read in [1, 2, 3, 258, 259, 1000, BIG_READ] {
            let (out, used) = run_inflater(&raw, chunk, read);
            assert_eq!(out.unwrap(), data, "chunk {chunk} read {read}");
            assert_eq!(used, raw.len());
        }
    }
}

#[test]
fn stored_blocks_of_every_size_class() {
    // Covers: SG-R-CDC-08 SG-R-RDR-01
    for size in [0usize, 1, 2, 255, 256, 65534, 65535, 65536, 65537, 131_070, 200_000] {
        let data = gen(1, size, 3);
        let raw = stored_stream(&data);
        for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1000), (3, 70_000), (65536, 1), (999, 4096)] {
            if size > 1000 && (read < 100) {
                continue;
            }
            let (out, used) = run_inflater(&raw, chunk, read);
            assert_eq!(out.unwrap(), data, "size {size} chunk {chunk} read {read}");
            assert_eq!(used, raw.len());
        }
        assert_eq!(ref_raw(&raw).unwrap().0, data);
    }
}

#[test]
fn many_consecutive_empty_blocks() {
    // Covers: SG-R-CDC-08
    let mut w = Bits::new();
    for _ in 0..1000 {
        stored_block(&mut w, &[], false);
        fixed_block(&mut w, &[], false);
    }
    fixed_block(&mut w, &[Tok::Lit(b'x')], true);
    let raw = w.bytes();
    assert_eq!(raw_decode(&raw).unwrap(), b"x");
    assert_eq!(run_inflater(&raw, 1, 1).0.unwrap(), b"x");
    assert_eq!(ref_raw(&raw).unwrap().0, b"x");
}

#[test]
fn window_distances_up_to_32768_are_valid() {
    // Covers: SG-R-CDC-08
    let head = gen(1, 40_000, 11);
    for dist in [1usize, 2, 15, 16, 17, 258, 259, 4096, 32767, 32768] {
        let mut w = Bits::new();
        stored_block(&mut w, &head, false);
        let toks = [
            Tok::Match { len: 258, dist },
            Tok::Match { len: 3, dist },
            Tok::Lit(7),
            Tok::Match { len: 100, dist },
        ];
        fixed_block(&mut w, &toks, true);
        let raw = w.bytes();
        let mut expect = head.clone();
        for t in toks {
            match t {
                Tok::Lit(b) => expect.push(b),
                Tok::Match { len, dist } => {
                    for _ in 0..len {
                        expect.push(expect[expect.len() - dist]);
                    }
                }
            }
        }
        assert_eq!(raw_decode(&raw).unwrap(), expect, "dist {dist}");
        assert_eq!(ref_raw(&raw).unwrap().0, expect);
        for (chunk, read) in [(1, 1), (7, 5), (NO_CHUNKING, 100)] {
            assert_eq!(
                run_inflater(&raw, chunk, read).0.unwrap(),
                expect,
                "dist {dist} chunk {chunk} read {read}"
            );
        }
    }
}

#[test]
fn distance_before_the_start_is_corrupt_at_every_position() {
    // Covers: SG-R-CDC-08 SG-I-05
    for have in [0usize, 1, 2, 5, 100, 257] {
        for dist in [1usize, 2, 3, 100, 101, 258, 259] {
            let mut w = Bits::new();
            let mut toks: Vec<Tok> = (0..have).map(|i| Tok::Lit(i as u8)).collect();
            toks.push(Tok::Match { len: 3, dist });
            fixed_block(&mut w, &toks, true);
            let raw = w.bytes();
            let ours = raw_decode(&raw);
            if dist <= have {
                assert_eq!(ours.unwrap().len(), have + 3, "have {have} dist {dist}");
                assert!(ref_raw(&raw).is_some());
            } else {
                // (flate2's miniz_oxide reads zeros here; zlib and the specification refuse)
                assert_corrupt(ours, &format!("have {have} dist {dist}"));
            }
        }
    }
}

#[test]
fn a_gzip_member_cannot_reach_back_into_the_previous_member() {
    // Covers: SG-R-CDC-02 SG-R-CDC-08
    let mut w = Bits::new();
    fixed_block(&mut w, &[Tok::Lit(b'a'), Tok::Lit(b'b')], true);
    let first = gzip_member(&w.bytes(), b"ab");
    let mut w = Bits::new();
    fixed_block(&mut w, &[Tok::Match { len: 3, dist: 2 }], true);
    let second = gzip_member(&w.bytes(), b"ababa");
    let mut both = first.clone();
    both.extend_from_slice(&second);
    assert_corrupt(gzip_decode(&both), "member 2 refers into member 1");
    assert_eq!(gzip_decode(&first).unwrap(), b"ab");
}

#[test]
fn reserved_symbols_in_fixed_blocks_are_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    for lit_sym in [286u32, 287] {
        let mut w = Bits::new();
        w.put(1, 1).put(1, 2);
        fixed_lit_code(&mut w, u32::from(b'a'));
        fixed_lit_code(&mut w, lit_sym);
        w.put(0, 5).put(0, 20);
        assert_corrupt(raw_decode(&w.bytes()), &format!("symbol {lit_sym}"));
        assert!(ref_raw(&w.bytes()).is_none());
    }
    for dist_sym in [30u32, 31] {
        let mut w = Bits::new();
        w.put(1, 1).put(1, 2);
        fixed_lit_code(&mut w, u32::from(b'a'));
        fixed_lit_code(&mut w, 257);
        w.code(dist_sym, 5).put(0, 20);
        assert_corrupt(raw_decode(&w.bytes()), &format!("distance {dist_sym}"));
        assert!(ref_raw(&w.bytes()).is_none());
    }
}

#[test]
fn block_type_three_and_bad_stored_lengths_are_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    let mut w = Bits::new();
    w.put(1, 1).put(3, 2);
    assert_corrupt(raw_decode(&w.bytes()), "type 3");
    assert!(ref_raw(&w.bytes()).is_none());
    assert_corrupt(raw_decode(&[0x01, 0x05, 0x00, 0x00, 0x00]), "stored length mismatch");
    assert!(ref_raw(&[0x01, 0x05, 0x00, 0x00, 0x00]).is_none());
    // LEN and NLEN that are off by one bit
    for flip in 0..32 {
        let mut w = Bits::new();
        w.put(1, 1).put(0, 2).align();
        let len = 3u32;
        let nlen = !len & 0xffff;
        let word = (len | (nlen << 16)) ^ (1 << flip);
        w.put(word, 32);
        for b in b"abc" {
            w.put(u32::from(*b), 8);
        }
        assert_corrupt(raw_decode(&w.bytes()), &format!("flip {flip}"));
    }
}

// ---------------------------------------------------------------------------------------------
// hand-built dynamic headers (ported from inflate_headers.test.ts)
// ---------------------------------------------------------------------------------------------

/// Canonical codes (RFC 1951 3.2.2) for a list of code lengths.
fn canonical(lengths: &[u32]) -> Vec<(u32, u32)> {
    let mut count = [0u32; 16];
    for &l in lengths {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0;
    for l in 1..16 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    lengths
        .iter()
        .map(|&len| {
            if len == 0 {
                (0, 0)
            } else {
                next[len as usize] += 1;
                (next[len as usize] - 1, len)
            }
        })
        .collect()
}

const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

struct Dynamic {
    hlit: u32,
    hdist: u32,
    clen: Vec<u32>,
    symbols: Vec<(usize, u32)>,
    tail: fn(&mut Bits),
}

impl Dynamic {
    fn build(&self) -> Vec<u8> {
        let mut w = Bits::new();
        w.put(1, 1).put(2, 2).put(self.hlit, 5).put(self.hdist, 5).put(15, 4);
        for &symbol in &ORDER {
            w.put(self.clen[symbol], 3);
        }
        let codes = canonical(&self.clen);
        for &(symbol, extra) in &self.symbols {
            let (code, len) = codes[symbol];
            w.code(code, len);
            match symbol {
                16 => w.put(extra, 2),
                17 => w.put(extra, 3),
                18 => w.put(extra, 7),
                _ => &mut w,
            };
        }
        (self.tail)(&mut w);
        w.bytes()
    }
}

fn no_tail(_: &mut Bits) {}
fn end_of_block(w: &mut Bits) {
    w.code(0, 1);
}

fn flat_clen() -> Vec<u32> {
    let mut v = vec![4u32; 16];
    v.extend([0, 0, 0]);
    v
}

fn mixed_clen() -> Vec<u32> {
    let mut v = vec![2u32, 2];
    v.extend(std::iter::repeat_n(0, 14));
    v.extend([2, 3, 3]);
    v
}

#[derive(Debug, PartialEq)]
enum Expect {
    Ok(Vec<u8>),
    Corrupt,
}

fn outcome_of(result: Result<Vec<u8>, Error>) -> Expect {
    match result {
        Ok(v) => Expect::Ok(v),
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::Corrupt, "{e}");
            Expect::Corrupt
        }
    }
}

/// Our verdict equals `expect` for whole input and for every chunking; flate2 agrees.
fn check_case(name: &str, data: &[u8], expect: Expect) {
    for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (2, 3), (3, 1000), (7, 1)] {
        assert_eq!(
            outcome_of(run_inflater(data, chunk, read).0),
            expect,
            "{name} chunk {chunk} read {read}"
        );
    }
    let reference = match ref_raw(data) {
        Some((v, _)) => Expect::Ok(v),
        None => Expect::Corrupt,
    };
    assert_eq!(reference, expect, "{name}: flate2 disagrees with the expectation");
}

fn eob_symbols() -> Vec<(usize, u32)> {
    // 256 zeros, a one, one distance length of 0
    let mut s: Vec<(usize, u32)> = (0..256).map(|_| (0, 0)).collect();
    s.push((1, 0));
    s.push((0, 0));
    s
}

#[test]
fn dynamic_block_with_only_an_end_of_block_code_is_valid() {
    // Covers: SG-R-CDC-08 SG-I-05 SG-R-CDC-03
    let mut clen = vec![1u32, 1];
    clen.extend(std::iter::repeat_n(0, 17));
    let data = Dynamic {
        hlit: 0,
        hdist: 0,
        clen,
        symbols: eob_symbols(),
        tail: end_of_block,
    }
    .build();
    check_case("eob only", &data, Expect::Ok(vec![]));
}

#[test]
fn oversubscribed_and_incomplete_code_length_codes_are_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    let mut clen = vec![1u32, 1, 1];
    clen.extend(std::iter::repeat_n(0, 16));
    check_case(
        "oversubscribed clen",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen,
            symbols: vec![(0, 0)],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
    let mut clen = vec![1u32];
    clen.extend(std::iter::repeat_n(0, 18));
    check_case(
        "incomplete clen",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen,
            symbols: vec![(0, 0)],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
    // no code at all
    let clen = vec![0u32; 19];
    check_case(
        "empty clen",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen,
            symbols: vec![],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
}

#[test]
fn missing_end_of_block_code_is_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    // two literals of length 1 form a complete code, but symbol 256 has none
    let data = dynamic_with_lengths(&[(97, 1), (98, 1)], &[0], |w| {
        w.code(0, 1).code(1, 1);
    });
    check_case("no end-of-block", &data, Expect::Corrupt);
    let mut clen = vec![0u32; 8];
    clen.extend([1, 1]);
    clen.extend(std::iter::repeat_n(0, 9));
    check_case(
        "truncated header",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen,
            symbols: vec![],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
}

#[test]
fn repeat_codes_without_a_previous_length_or_past_the_table_are_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    let mut with_repeat = vec![0u32; 16];
    with_repeat.extend([1, 0, 1]);
    check_case(
        "repeat 16 first",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen: with_repeat,
            symbols: vec![(16, 0)],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
    let mut zeros = vec![1u32];
    zeros.extend(std::iter::repeat_n(0, 15));
    zeros.extend([0, 0, 1]);
    let overrun = vec![(18, 127); 3];
    check_case(
        "repeat overrun",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen: zeros,
            symbols: overrun,
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
}

#[test]
fn too_many_length_or_distance_symbols_are_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    check_case(
        "hlit 287",
        &Dynamic {
            hlit: 30,
            hdist: 0,
            clen: flat_clen(),
            symbols: vec![],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
    check_case(
        "hdist 31",
        &Dynamic {
            hlit: 0,
            hdist: 30,
            clen: flat_clen(),
            symbols: vec![],
            tail: no_tail,
        }
        .build(),
        Expect::Corrupt,
    );
    // 286 / 30 are the maximum: the header is accepted (the stream then ends, so it is corrupt for another reason)
    let data = Dynamic {
        hlit: 29,
        hdist: 29,
        clen: flat_clen(),
        symbols: vec![],
        tail: no_tail,
    }
    .build();
    check_case("hlit 286 is the maximum", &data, Expect::Corrupt);
    assert!(ref_raw(&data).is_none());
    // HLIT 287 even though the rest would decode
    let symbols = vec![(18, 127), (18, 107), (1, 0), (18, 19), (0, 0)];
    let data = Dynamic {
        hlit: 30,
        hdist: 0,
        clen: mixed_clen(),
        symbols,
        tail: end_of_block,
    }
    .build();
    check_case("hlit 287 decodable", &data, Expect::Corrupt);
}

#[test]
fn repeat_that_overruns_the_table_by_one_is_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    let symbols = vec![(18, 127), (18, 107), (1, 0), (17, 0)];
    let data = Dynamic {
        hlit: 0,
        hdist: 1,
        clen: mixed_clen(),
        symbols,
        tail: end_of_block,
    }
    .build();
    check_case("overrun by one", &data, Expect::Corrupt);
    let symbols = vec![(16, 0), (18, 127), (18, 104), (1, 0), (0, 0)];
    let data = Dynamic {
        hlit: 0,
        hdist: 0,
        clen: mixed_clen(),
        symbols,
        tail: end_of_block,
    }
    .build();
    check_case("repeat of the previous length first", &data, Expect::Corrupt);
    let symbols = vec![(18, 127), (18, 107), (1, 0), (0, 0)];
    let data = Dynamic {
        hlit: 0,
        hdist: 0,
        clen: mixed_clen(),
        symbols,
        tail: end_of_block,
    }
    .build();
    check_case("the same tables without the fault", &data, Expect::Ok(vec![]));
}

#[test]
fn oversubscribed_literal_length_code_is_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    let mut clen = vec![1u32, 1];
    clen.extend(std::iter::repeat_n(0, 17));
    let mut symbols: Vec<(usize, u32)> = (0..256)
        .map(|i| (usize::from(i == 65 || i == 66 || i == 67), 0))
        .collect();
    symbols.push((1, 0));
    symbols.push((0, 0));
    fn tail(w: &mut Bits) {
        w.code(1, 1);
    }
    check_case(
        "oversubscribed lit/len",
        &Dynamic {
            hlit: 0,
            hdist: 0,
            clen,
            symbols,
            tail,
        }
        .build(),
        Expect::Corrupt,
    );
}

/// Dynamic block with the code length code `mixed_clen`: literal/length lengths given as a
/// sparse list, distance lengths as another, everything else zero.
fn dynamic_with_lengths(lit: &[(usize, u32)], dist: &[u32], tail: fn(&mut Bits)) -> Vec<u8> {
    // clen: symbols 0..=3 get length 2 (complete: 4 codes of length 2)
    let mut clen = vec![0u32; 19];
    for c in clen.iter_mut().take(4) {
        *c = 2;
    }
    let mut lengths = vec![0u32; 257];
    for &(s, l) in lit {
        if s >= lengths.len() {
            lengths.resize(s + 1, 0);
        }
        lengths[s] = l;
    }
    let hlit = lengths.len() as u32 - 257;
    let mut symbols: Vec<(usize, u32)> = lengths.iter().map(|&l| (l as usize, 0)).collect();
    symbols.extend(dist.iter().map(|&l| (l as usize, 0)));
    Dynamic {
        hlit,
        hdist: dist.len() as u32 - 1,
        clen,
        symbols,
        tail,
    }
    .build()
}

#[test]
fn single_code_and_incomplete_distance_tables() {
    // Covers: SG-R-CDC-08 SG-I-05 SG-R-CDC-03
    // literal 'a' (97) length 2, end of block length 2, 'b' (98) length 2, 'c' length 2: complete
    fn tail_ok(w: &mut Bits) {
        // codes by symbol order: 97 -> 00, 98 -> 01, 99 -> 10, 256 -> 11
        w.code(0, 2).code(1, 2).code(2, 2).code(3, 2);
    }
    let lit = [(97, 2), (98, 2), (99, 2), (256, 2)];
    let data = dynamic_with_lengths(&lit, &[0], tail_ok);
    check_case("no distance codes", &data, Expect::Ok(b"abc".to_vec()));
    let data = dynamic_with_lengths(&lit, &[1], tail_ok);
    check_case("a single distance code of length 1", &data, Expect::Ok(b"abc".to_vec()));
    let data = dynamic_with_lengths(&lit, &[2], tail_ok);
    check_case(
        "a single distance code of length 2 is incomplete",
        &data,
        Expect::Corrupt,
    );
    let data = dynamic_with_lengths(&lit, &[1, 1], tail_ok);
    check_case("two distance codes of length 1", &data, Expect::Ok(b"abc".to_vec()));
    let data = dynamic_with_lengths(&lit, &[1, 1, 1], tail_ok);
    check_case("three distance codes of length 1", &data, Expect::Corrupt);
    // an incomplete literal/length code (three codes of length 2)
    let lit = [(97, 2), (98, 2), (256, 2)];
    fn tail_inc(w: &mut Bits) {
        w.code(0, 2).code(2, 2);
    }
    let data = dynamic_with_lengths(&lit, &[1, 1], tail_inc);
    check_case("incomplete lit/len", &data, Expect::Corrupt);
}

#[test]
fn a_distance_code_that_is_used_but_does_not_exist_is_corrupt() {
    // Covers: SG-R-CDC-08 SG-I-05
    // lit/len: 'a' = 0 (len 1)... use lengths: 97 -> 1 bit, 257 -> 2, 256 -> 2 : codes 97=0, 256=10, 257=11
    let lit = [(97, 1), (256, 2), (257, 2)];
    fn tail(w: &mut Bits) {
        w.code(0, 1).code(3, 2); // 'a', length 3, then a distance code that is not there
        w.put(0, 8);
    }
    let data = dynamic_with_lengths(&lit, &[0], tail);
    check_case("length symbol with no distance table", &data, Expect::Corrupt);
    // the single distance code of length 1 is code 0, the code 1 is unassigned
    fn tail2(w: &mut Bits) {
        w.code(0, 1).code(3, 2).code(1, 1);
        w.put(0, 8);
    }
    let data = dynamic_with_lengths(&lit, &[1], tail2);
    check_case("unassigned distance code", &data, Expect::Corrupt);
    fn tail3(w: &mut Bits) {
        w.code(0, 1).code(3, 2).code(0, 1).code(2, 2);
    }
    let data = dynamic_with_lengths(&lit, &[1], tail3);
    check_case("single distance code distance 1", &data, Expect::Ok(b"aaaa".to_vec()));
}

#[test]
fn one_literal_length_code_of_length_one() {
    // Covers: SG-R-CDC-08 SG-I-05
    // only the end-of-block symbol has a code (length 1); the other code of length 1 is unassigned
    fn eob(w: &mut Bits) {
        w.code(0, 1);
    }
    fn bad(w: &mut Bits) {
        w.code(1, 1);
    }
    let lit = [(256, 1)];
    check_case("eob only", &dynamic_with_lengths(&lit, &[0], eob), Expect::Ok(vec![]));
    check_case(
        "unassigned code used",
        &dynamic_with_lengths(&lit, &[0], bad),
        Expect::Corrupt,
    );
}

// ---------------------------------------------------------------------------------------------
// truncation and damage
// ---------------------------------------------------------------------------------------------

/// A few small streams: (name, payload, raw, zlib, gzip).
fn small_streams() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut v = Vec::new();
    let text = gen(2, 300, 1);
    let rnd = gen(1, 120, 2);
    let runs = gen(3, 500, 3);
    let mixed = gen(7, 700, 4);
    for (name, data) in [
        ("text", text),
        ("random", rnd),
        ("runs", runs),
        ("mixed", mixed),
        ("empty", vec![]),
    ] {
        for level in [0, 1, 9] {
            v.push((format!("{name} level {level}"), data.clone(), enc_raw(&data, level)));
        }
    }
    // hand-built: stored + fixed + empty stored, then fixed
    let data = gen(2, 400, 5);
    let mut w = Bits::new();
    stored_block(&mut w, &data[..50], false);
    fixed_block(&mut w, &tokenize(&data[50..300]), false);
    stored_block(&mut w, &[], false);
    fixed_block(&mut w, &tokenize(&data[300..]), true);
    v.push(("hand built".into(), data, w.bytes()));
    v
}

#[test]
fn every_truncation_is_corrupt() {
    // Covers: SG-R-CDC-06 SG-R-CDC-02 SG-R-CDC-03
    for (name, payload, raw) in small_streams() {
        let z = zlib_wrap(&raw, &payload);
        let g = gzip_member(&raw, &payload);
        let mut g2 = g.clone();
        g2.extend_from_slice(&g);
        for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (3, 100)] {
            for cut in 0..raw.len() {
                assert_corrupt(
                    run_inflater(&raw[..cut], chunk, read).0,
                    &format!("raw {name} cut {cut}"),
                );
            }
            for cut in 0..z.len() {
                assert_corrupt(
                    run_codec(&DeflateCodec::new(true), &z[..cut], chunk, read).0,
                    &format!("zlib {name} cut {cut}"),
                );
            }
            for cut in 0..g.len() {
                assert_corrupt(
                    run_codec(&GzipCodec, &g[..cut], chunk, read).0,
                    &format!("gzip {name} cut {cut}"),
                );
            }
            // two members: a cut inside the second member is corrupt, a cut at the boundary is a clean end
            for cut in g.len() + 1..g2.len() {
                assert_corrupt(
                    run_codec(&GzipCodec, &g2[..cut], chunk, read).0,
                    &format!("gzip2 {name} cut {cut}"),
                );
            }
        }
        assert_eq!(gzip_decode(&g2[..g.len()]).unwrap(), payload);
        // raw fallback of the deflate codec: a cut stream is corrupt too (unless the cut leaves a zlib-looking
        // header, in which case it is a truncated zlib stream and just as corrupt)
        for cut in 0..raw.len() {
            assert_corrupt(deflate_decode(&raw[..cut]), &format!("deflate raw {name} cut {cut}"));
        }
    }
}

/// Property for a damaged stream: our verdict is `corrupt`, or output and consumed input equal to
/// the reference's, which must accept too. One difference is known and wanted: flate2's
/// miniz_oxide accepts a distance that reaches before the start of the data (it reads zeros);
/// zlib, Go and the specification here refuse it ("distance too far back"). Returns whether we
/// accepted and whether the reference accepted something we refused for another reason (a bug).
fn check_damaged_raw(name: &str, data: &[u8], chunk: usize, read: usize) -> (bool, bool) {
    let (ours, used) = run_inflater(data, chunk, read);
    let reference = ref_raw(data);
    let mut unexplained = false;
    match (&ours, &reference) {
        (Ok(a), Some((b, ref_used))) => {
            assert_eq!(a, b, "{name}: output differs from the reference");
            assert_eq!(used, *ref_used, "{name}: input accounting differs from the reference");
        }
        (Ok(_), None) => panic!("{name}: we accept what the reference refuses"),
        (Err(e), reference) => {
            assert_eq!(e.kind(), ErrorKind::Corrupt, "{name}: {e}");
            unexplained = reference.is_some() && !e.message().contains("too far back");
        }
    }
    (ours.is_ok(), unexplained)
}

#[test]
fn every_single_bit_flip_of_raw_streams() {
    // Covers: SG-I-05 SG-R-CDC-08 SG-R-CDC-06
    let (mut accepted, mut ref_only) = (0, 0);
    for (name, _payload, raw) in small_streams() {
        for bit in 0..raw.len() * 8 {
            let mut d = raw.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            let (chunk, read) = [(NO_CHUNKING, BIG_READ), (1, 1), (5, 17)][bit % 3];
            let (ours, theirs) = check_damaged_raw(&format!("{name} bit {bit}"), &d, chunk, read);
            accepted += usize::from(ours);
            ref_only += usize::from(theirs);
        }
    }
    assert!(accepted > 0, "some flips are harmless");
    assert_eq!(
        ref_only, 0,
        "streams the reference accepts and we refuse for no known reason"
    );
}

#[test]
fn every_single_bit_flip_of_gzip_and_zlib_streams() {
    // Covers: SG-I-05 SG-R-CDC-02 SG-R-CDC-03 SG-R-CDC-08
    let mut harmless = 0;
    for (name, payload, raw) in small_streams().into_iter().step_by(2) {
        let g = gzip_member(&raw, &payload);
        for bit in 0..g.len() * 8 {
            let mut d = g.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            let (chunk, read) = [(NO_CHUNKING, BIG_READ), (1, 1), (5, 17)][bit % 3];
            match run_codec(&GzipCodec, &d, chunk, read).0 {
                Ok(out) => {
                    assert_eq!(
                        out, payload,
                        "{name} gzip bit {bit}: data the original does not produce"
                    );
                    assert_eq!(ref_gzip(&d).as_deref(), Some(&payload[..]), "{name} gzip bit {bit}");
                    harmless += 1;
                }
                Err(e) => assert_eq!(e.kind(), ErrorKind::Corrupt),
            }
        }
        let z = zlib_wrap(&raw, &payload);
        for bit in 0..z.len() * 8 {
            let mut d = z.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            let (chunk, read) = [(NO_CHUNKING, BIG_READ), (1, 1), (5, 17)][bit % 3];
            match run_codec(&DeflateCodec::new(true), &d, chunk, read).0 {
                Ok(out) => {
                    assert_eq!(out, payload, "{name} zlib bit {bit}");
                    assert_eq!(ref_zlib(&d).as_deref(), Some(&payload[..]));
                    harmless += 1;
                }
                Err(e) => assert_eq!(e.kind(), ErrorKind::Corrupt),
            }
            // with the raw fallback a damaged header makes the whole input a raw stream
            match run_codec(&DeflateCodec::new(false), &d, chunk, read).0 {
                Ok(out) if is_zlib_header(d[0], d[1]) => assert_eq!(out, payload, "{name} zlib bit {bit}"),
                Ok(out) => {
                    let (reference, used) = ref_raw(&d).expect("the reference refuses a raw stream we accept");
                    assert_eq!((out, d.len()), (reference, used), "{name} raw fallback bit {bit}");
                }
                Err(e) => assert_eq!(e.kind(), ErrorKind::Corrupt),
            }
        }
    }
    assert!(harmless > 0);
}

#[test]
fn random_and_mutated_streams_never_panic_and_never_beat_the_reference() {
    // Covers: SG-I-05 SG-R-CDC-08 SG-I-01
    let mut rng = Rng::new(7);
    for _ in 0..30_000 {
        let n = rng.below(200);
        let data: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        check_damaged_raw("random", &data, 1 + rng.below(20), 1 + rng.below(300));
        // as gzip / zlib with a plausible header: must not panic
        let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        g.extend_from_slice(&data);
        let _ = run_codec(&GzipCodec, &g, 1 + rng.below(9), 1 + rng.below(100)).0;
        let mut z = vec![0x78, 0x9c];
        z.extend_from_slice(&data);
        let _ = run_codec(&DeflateCodec::new(false), &z, 1 + rng.below(9), 1 + rng.below(100)).0;
    }
    let streams = small_streams();
    let mut accepted = 0;
    for i in 0..60_000 {
        let (name, _payload, raw) = &streams[rng.below(streams.len())];
        let mut d = raw.clone();
        for _ in 0..1 + rng.below(3) {
            match rng.below(5) {
                0 if !d.is_empty() => {
                    let p = rng.below(d.len());
                    d[p] = rng.next() as u8;
                }
                1 if !d.is_empty() => {
                    let p = rng.below(d.len());
                    d.remove(p);
                }
                2 => {
                    let p = rng.below(d.len() + 1);
                    d.insert(p, rng.next() as u8);
                }
                3 => d.truncate(rng.below(d.len() + 1)),
                _ if !d.is_empty() => {
                    let p = rng.below(d.len());
                    d[p] ^= 1 << rng.below(8);
                }
                _ => {}
            }
        }
        let (ours, theirs) = check_damaged_raw(
            &format!("{name} mutation {i}"),
            &d,
            1 + rng.below(30),
            1 + rng.below(500),
        );
        assert!(!theirs, "{name} mutation {i}: the reference accepts, we do not");
        accepted += usize::from(ours);
    }
    assert!(accepted > 0);
}

// ---------------------------------------------------------------------------------------------
// exact input accounting
// ---------------------------------------------------------------------------------------------

#[test]
fn bytes_after_the_stream_are_never_consumed() {
    // Covers: SG-R-RAT-02 SG-R-CDC-03 SG-R-CDC-02
    for (name, payload, raw) in small_streams() {
        for extra in [1usize, 2, 7, 8, 9, 100] {
            let mut data = raw.clone();
            data.extend((0..extra).map(|i| (i * 31 + 5) as u8));
            for (chunk, read) in [
                (NO_CHUNKING, BIG_READ),
                (1, 1),
                (2, 3),
                (5, 1000),
                (raw.len(), 10),
                (raw.len() + 1, 10),
            ] {
                let (out, used) = run_inflater(&data, chunk, read);
                assert_eq!(out.unwrap(), payload, "{name} extra {extra} chunk {chunk} read {read}");
                assert_eq!(used, raw.len(), "{name} extra {extra} chunk {chunk} read {read}");
            }
            // the deflate codec: trailing bytes are corrupt, and still not consumed
            let z = zlib_wrap(&raw, &payload);
            let mut data = z.clone();
            data.extend((0..extra).map(|i| (i * 31 + 5) as u8));
            for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (z.len(), 10), (z.len() + 1, 10)] {
                let (res, used) = run_codec(&DeflateCodec::new(true), &data, chunk, read);
                assert_corrupt(res, &format!("{name} zlib + {extra}"));
                assert_eq!(used, z.len(), "{name} zlib + {extra} chunk {chunk}");
            }
            // gzip: trailing bytes that do not start a member are corrupt
            let g = gzip_member(&raw, &payload);
            let mut data = g.clone();
            data.extend((0..extra).map(|i| (i * 31 + 5) as u8));
            for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (g.len(), 10)] {
                let (res, used) = run_codec(&GzipCodec, &data, chunk, read);
                assert_corrupt(res, &format!("{name} gzip + {extra}"));
                assert!(
                    used >= g.len() && used <= g.len() + 10.min(extra),
                    "{name}: consumed {used}"
                );
            }
        }
    }
}

#[test]
fn the_decoder_agrees_with_the_reference_on_consumed_bytes() {
    // Covers: SG-R-RAT-02
    for kind in 0..KINDS {
        for size in [0usize, 5, 1000, 70_000] {
            let data = gen(kind, size, 8);
            for level in [0, 1, 6, 9] {
                let mut raw = enc_raw(&data, level);
                let len = raw.len();
                raw.extend_from_slice(b"trailing bytes");
                let (_, ref_used) = ref_raw(&raw).unwrap();
                let (out, used) = run_inflater(&raw, 4096, BIG_READ);
                assert_eq!(out.unwrap(), data);
                assert_eq!(used, len);
                assert_eq!(
                    ref_used, len,
                    "the reference consumed {ref_used} of a {len} byte stream"
                );
            }
        }
    }
}

#[test]
fn an_inflater_can_be_reused_for_the_next_stream() {
    // Covers: SG-R-CDC-02 SG-R-MEM-01
    let mut inflater = Inflater::new();
    let mut rng = Rng::new(3);
    for round in 0..40 {
        let data = gen(round % KINDS, 1 + rng.below(50_000), round as u64);
        let raw = enc_raw(&data, (round % 10) as u32);
        let mut input: &[u8] = &raw;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 + rng.below(5000)];
        loop {
            let n = inflater.read(&mut input, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, data, "round {round}");
        assert!(input.is_empty());
        inflater.reset();
    }
    // a failed stream is sticky until reset
    let mut input: &[u8] = &[0x07];
    let mut buf = [0u8; 10];
    assert_corrupt(inflater.read(&mut input, &mut buf), "type 3");
    let mut input: &[u8] = &[0x03, 0x00];
    assert_corrupt(inflater.read(&mut input, &mut buf), "sticky");
    inflater.reset();
    assert_eq!(inflater.read(&mut input, &mut buf).unwrap(), 0);
    assert!(inflater.finished());
}

#[test]
fn an_empty_input_is_corrupt_for_every_codec() {
    // Covers: SG-R-CDC-06
    assert_corrupt(raw_decode(&[]), "raw");
    assert_corrupt(gzip_decode(&[]), "gzip");
    assert_corrupt(deflate_decode(&[]), "deflate");
    assert_corrupt(run_codec(&DeflateCodec::new(true), &[], 1, 1).0, "strict deflate");
    assert_corrupt(deflate_decode(&[0x78]), "one byte");
}

// ---------------------------------------------------------------------------------------------
// bombs
// ---------------------------------------------------------------------------------------------

/// A raw DEFLATE stream of `n` zero bytes: one literal then matches of 258 at distance 1.
fn zeros_stream(n: usize) -> Vec<u8> {
    let mut w = Bits::new();
    let mut toks = vec![Tok::Lit(0)];
    let mut left = n - 1;
    while left >= 258 {
        toks.push(Tok::Match { len: 258, dist: 1 });
        left -= 258;
    }
    if left >= 3 {
        toks.push(Tok::Match { len: left, dist: 1 });
    } else {
        toks.extend((0..left).map(|_| Tok::Lit(0)));
    }
    fixed_block(&mut w, &toks, true);
    w.bytes()
}

#[test]
fn a_bomb_decodes_in_bounded_steps() {
    // Covers: SG-R-RAT-02 SG-R-MEM-01 SG-R-CDC-07 SG-I-04
    let n = 20_000_000;
    let raw = zeros_stream(n);
    assert!(raw.len() < n / 100);
    for (chunk, read) in [(NO_CHUNKING, 4096), (7, 100), (NO_CHUNKING, 1), (4096, 65536)] {
        let n = if read == 1 { 200_000 } else { n };
        let raw = if read == 1 { zeros_stream(n) } else { raw.clone() };
        let (mut input, pos) = Chunked::new(&raw, chunk);
        let mut inflater = Inflater::new();
        let mut buf = vec![0u8; read];
        let mut total = 0usize;
        let mut calls = 0usize;
        loop {
            let k = inflater.read(&mut input, &mut buf).unwrap();
            if k == 0 {
                break;
            }
            assert!(k <= buf.len());
            assert!(buf[..k].iter().all(|&b| b == 0));
            total += k;
            calls += 1;
        }
        assert_eq!(total, n);
        assert_eq!(pos.get(), raw.len());
        assert!(calls >= n / read.max(1) / 2, "a step must be bounded by the buffer");
    }
    // as gzip through the codec with a 1000 byte buffer: constant memory, exact size and CRC checked
    let payload_crc = {
        let mut crc = 0;
        let block = vec![0u8; 1 << 16];
        let mut left = n;
        while left > 0 {
            let k = left.min(block.len());
            crc = crc32(&block[..k], crc);
            left -= k;
        }
        crc
    };
    let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    g.extend_from_slice(&raw);
    g.extend_from_slice(&payload_crc.to_le_bytes());
    g.extend_from_slice(&(n as u32).to_le_bytes());
    let (input, _) = Chunked::new(&g, 4096);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    let mut buf = vec![0u8; 1000];
    let mut total = 0;
    loop {
        let k = reader.read(&mut buf).unwrap();
        if k == 0 {
            break;
        }
        total += k;
    }
    assert_eq!(total, n);
}

#[test]
fn a_bomb_is_cut_off_by_reading_less() {
    // Covers: SG-R-LAY-01 SG-R-CDC-07
    // The codec never decodes ahead of what it is asked for: reading 10 bytes of a 1 GB stream
    // consumes at most a few bytes of input.
    let raw = zeros_stream(100_000_000);
    let g = gzip_member(&raw, b"");
    let (input, pos) = Chunked::new(&g, 100_000);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    let mut buf = [0u8; 10];
    assert_eq!(reader.read(&mut buf).unwrap(), 10);
    assert!(pos.get() < 100, "consumed {}", pos.get());
}

// ---------------------------------------------------------------------------------------------
// gzip framing
// ---------------------------------------------------------------------------------------------

struct Member<'a> {
    payload: &'a [u8],
    flags: u8,
    extra: Option<Vec<u8>>,
    name: Option<Vec<u8>>,
    comment: Option<Vec<u8>>,
    hcrc: Option<Option<u16>>,
    crc: Option<u32>,
    isize: Option<u32>,
}

impl<'a> Member<'a> {
    fn new(payload: &'a [u8]) -> Member<'a> {
        Member {
            payload,
            flags: 0,
            extra: None,
            name: None,
            comment: None,
            hcrc: None,
            crc: None,
            isize: None,
        }
    }
    fn build(&self) -> Vec<u8> {
        let mut head = vec![0x1f, 0x8b, 8, self.flags, 1, 2, 3, 4, 0, 3];
        if let Some(e) = &self.extra {
            head[3] |= 4;
            head.extend_from_slice(&(e.len() as u16).to_le_bytes());
            head.extend_from_slice(e);
        }
        if let Some(n) = &self.name {
            head[3] |= 8;
            head.extend_from_slice(n);
            head.push(0);
        }
        if let Some(c) = &self.comment {
            head[3] |= 16;
            head.extend_from_slice(c);
            head.push(0);
        }
        if let Some(h) = self.hcrc {
            head[3] |= 2;
            let value = h.unwrap_or((crc32(&head, 0) & 0xffff) as u16);
            head.extend_from_slice(&value.to_le_bytes());
        }
        head.extend_from_slice(&stored_stream(self.payload));
        head.extend_from_slice(&self.crc.unwrap_or_else(|| crc32(self.payload, 0)).to_le_bytes());
        head.extend_from_slice(&self.isize.unwrap_or(self.payload.len() as u32).to_le_bytes());
        head
    }
}

const PAYLOAD: &[u8] = b"hello gzip header world";

fn full_member() -> Vec<u8> {
    Member {
        extra: Some(b"extra!".to_vec()),
        name: Some(b"name.txt".to_vec()),
        comment: Some(b"a comment".to_vec()),
        hcrc: Some(None),
        ..Member::new(PAYLOAD)
    }
    .build()
}

#[test]
fn gzip_plain_and_library_made_streams_decode() {
    // Covers: SG-R-CDC-02
    assert_eq!(gzip_decode(&Member::new(PAYLOAD).build()).unwrap(), PAYLOAD);
    assert_eq!(gzip_decode(&full_member()).unwrap(), PAYLOAD);
    assert_eq!(gzip_decode(&enc_gzip(PAYLOAD, 6)).unwrap(), PAYLOAD);
    assert_eq!(gzip_decode(&enc_gzip(b"", 6)).unwrap(), b"");
    // FTEXT is harmless; MTIME, XFL and OS are ignored
    let mut m = Member::new(PAYLOAD).build();
    m[3] |= 1;
    m[4..10].copy_from_slice(&[9, 9, 9, 9, 7, 7]);
    assert_eq!(gzip_decode(&m).unwrap(), PAYLOAD);
}

#[test]
fn gzip_bad_magic_method_and_reserved_flags_are_corrupt() {
    // Covers: SG-R-CDC-02
    for (index, values) in [
        (0usize, vec![0x1e, 0, 0x8b]),
        (1, vec![0x8a, 0, 0x1f]),
        (2, (0..=255u8).filter(|&v| v != 8).collect()),
    ] {
        for v in values {
            let mut m = Member::new(PAYLOAD).build();
            m[index] = v;
            assert_corrupt(gzip_decode(&m), &format!("byte {index} = {v:#x}"));
        }
    }
    for bit in 5..8 {
        let mut m = Member::new(PAYLOAD).build();
        m[3] |= 1 << bit;
        assert_corrupt(gzip_decode(&m), &format!("reserved flag {bit}"));
    }
}

#[test]
fn gzip_header_crc_is_verified() {
    // Covers: SG-R-CDC-02
    for h in [
        Member {
            hcrc: Some(None),
            ..Member::new(PAYLOAD)
        },
        Member {
            hcrc: Some(None),
            name: Some(b"n".to_vec()),
            ..Member::new(PAYLOAD)
        },
    ] {
        assert_eq!(gzip_decode(&h.build()).unwrap(), PAYLOAD);
    }
    let good = (crc32(&[0x1f, 0x8b, 8, 2, 1, 2, 3, 4, 0, 3], 0) & 0xffff) as u16;
    for wrong in [good ^ 1, good ^ 0x8000, good.wrapping_add(1), 0, 0xffff] {
        if wrong == good {
            continue;
        }
        let m = Member {
            hcrc: Some(Some(wrong)),
            ..Member::new(PAYLOAD)
        }
        .build();
        assert_corrupt(gzip_decode(&m), &format!("hcrc {wrong:#x}"));
    }
    let m = Member {
        hcrc: Some(Some(good)),
        ..Member::new(PAYLOAD)
    }
    .build();
    assert_eq!(gzip_decode(&m).unwrap(), PAYLOAD);
}

#[test]
fn gzip_extra_field_sizes() {
    // Covers: SG-R-CDC-02 SG-R-MEM-01
    for len in [0usize, 1, 2, 255, 256, 511, 512, 513, 4096, 65534, 65535] {
        let m = Member {
            extra: Some(vec![0xaa; len]),
            hcrc: Some(None),
            ..Member::new(PAYLOAD)
        }
        .build();
        for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 4), (7, 3), (512, 100)] {
            assert_eq!(
                run_codec(&GzipCodec, &m, chunk, read).0.unwrap(),
                PAYLOAD,
                "extra {len}"
            );
        }
        assert_eq!(ref_gzip(&m).as_deref(), Some(PAYLOAD));
    }
    // XLEN larger than what follows
    let mut m = Member {
        extra: Some(vec![1; 10]),
        ..Member::new(PAYLOAD)
    }
    .build();
    m[10] = 0xff;
    m[11] = 0xff;
    assert_corrupt(gzip_decode(&m), "xlen too large");
    // the extra field ends the input
    let m = Member {
        extra: Some(vec![1; 10]),
        ..Member::new(PAYLOAD)
    }
    .build();
    for cut in 10..22 {
        assert_corrupt(gzip_decode(&m[..cut]), &format!("cut {cut}"));
    }
}

#[test]
fn gzip_name_and_comment_limits_are_512_bytes_with_the_terminator() {
    // Covers: SG-R-CDC-02 SG-R-MEM-01 SG-I-04
    for len in [0usize, 1, 100, 510, 511] {
        for use_comment in [false, true] {
            let s = Some(vec![b'n'; len]);
            let m = if use_comment {
                Member {
                    comment: s,
                    hcrc: Some(None),
                    ..Member::new(PAYLOAD)
                }
            } else {
                Member {
                    name: s,
                    hcrc: Some(None),
                    ..Member::new(PAYLOAD)
                }
            };
            let m = m.build();
            for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 4), (100, 3), (511, 3), (512, 3), (513, 3)] {
                assert_eq!(
                    run_codec(&GzipCodec, &m, chunk, read).0.unwrap(),
                    PAYLOAD,
                    "len {len} chunk {chunk}"
                );
            }
        }
    }
    for len in [512usize, 513, 1000, 100_000] {
        for use_comment in [false, true] {
            let s = Some(vec![b'n'; len]);
            let m = if use_comment {
                Member {
                    comment: s,
                    ..Member::new(PAYLOAD)
                }
            } else {
                Member {
                    name: s,
                    ..Member::new(PAYLOAD)
                }
            };
            let m = m.build();
            for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 4), (100, 3), (511, 3), (512, 3), (513, 3)] {
                let (res, used) = run_codec(&GzipCodec, &m, chunk, read);
                assert_corrupt(res, &format!("len {len} chunk {chunk}"));
                assert!(used <= 10 + 512, "an over-long string consumed {used} bytes");
            }
        }
    }
    // an endless string without a terminator stops early
    let mut m = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
    m.extend(std::iter::repeat_n(b'x', 1_000_000));
    let (res, used) = run_codec(&GzipCodec, &m, 4096, 100);
    assert_corrupt(res, "endless name");
    assert!(used <= 10 + 512 + 4096);
    // name and comment both at their maximum
    let m = Member {
        name: Some(vec![b'a'; 511]),
        comment: Some(vec![b'b'; 511]),
        hcrc: Some(None),
        ..Member::new(PAYLOAD)
    }
    .build();
    assert_eq!(gzip_decode(&m).unwrap(), PAYLOAD);
    // a string cut off before the terminator
    let m = Member {
        name: Some(vec![b'a'; 20]),
        ..Member::new(PAYLOAD)
    }
    .build();
    for cut in 10..31 {
        assert_corrupt(gzip_decode(&m[..cut]), &format!("name cut {cut}"));
    }
}

#[test]
fn gzip_every_header_byte_mutation() {
    // Covers: SG-R-CDC-02 SG-I-05
    let member = full_member();
    let header_len = member.len() - stored_stream(PAYLOAD).len() - 8;
    assert_eq!(gzip_decode(&member).unwrap(), PAYLOAD);
    let mut accepted_mutations = 0;
    for pos in 0..header_len {
        for value in 0..=255u8 {
            if value == member[pos] {
                continue;
            }
            let mut m = member.clone();
            m[pos] = value;
            match run_codec(&GzipCodec, &m, if pos % 2 == 0 { NO_CHUNKING } else { 3 }, 50).0 {
                Ok(out) => {
                    // only the fields the header CRC does not protect... but it protects all of them
                    assert_eq!(out, PAYLOAD);
                    assert_eq!(ref_gzip(&m).as_deref(), Some(PAYLOAD));
                    accepted_mutations += 1;
                }
                Err(e) => assert_eq!(e.kind(), ErrorKind::Corrupt),
            }
        }
    }
    // the header CRC protects every byte, so a single changed byte is (almost) never accepted
    assert!(accepted_mutations < 4, "{accepted_mutations} mutations accepted");
}

#[test]
fn gzip_header_fields_not_covered_by_a_header_crc_are_free() {
    // Covers: SG-R-CDC-02
    let member = Member::new(PAYLOAD).build();
    for pos in [4usize, 5, 6, 7, 8, 9] {
        for value in 0..=255u8 {
            let mut m = member.clone();
            m[pos] = value;
            assert_eq!(gzip_decode(&m).unwrap(), PAYLOAD, "byte {pos} = {value}");
        }
    }
}

#[test]
fn gzip_every_trailer_byte_mutation() {
    // Covers: SG-R-CDC-02 SG-R-CDC-07
    let member = Member::new(PAYLOAD).build();
    let t = member.len() - 8;
    for pos in t..member.len() {
        for value in 0..=255u8 {
            if value == member[pos] {
                continue;
            }
            let mut m = member.clone();
            m[pos] = value;
            assert_corrupt(gzip_decode(&m), &format!("trailer byte {pos} = {value}"));
            assert_corrupt(run_codec(&GzipCodec, &m, 1, 1).0, "byte at a time");
        }
    }
    // the wrong ISIZE is never an allowance or an early rejection: output is delivered first
    let m = Member {
        isize: Some(5),
        ..Member::new(PAYLOAD)
    }
    .build();
    let (input, _) = Chunked::new(&m, NO_CHUNKING);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    let mut buf = [0u8; 100];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], PAYLOAD);
    assert_corrupt(reader.read(&mut buf), "isize 5");
    let m = Member {
        isize: Some(1 << 30),
        ..Member::new(PAYLOAD)
    }
    .build();
    assert_corrupt(gzip_decode(&m), "isize 1 GiB");
    let m = Member {
        isize: Some(u32::MAX),
        crc: Some(1),
        ..Member::new(PAYLOAD)
    }
    .build();
    assert_corrupt(gzip_decode(&m), "isize max");
}

#[test]
fn gzip_isize_is_compared_modulo_2_pow_32() {
    // Covers: SG-R-CDC-02 SG-R-CDC-07
    let ok = |crc: u32, size: u32, isize_field: u32| {
        let mut t = [0u8; 8];
        t[..4].copy_from_slice(&crc.to_le_bytes());
        t[4..].copy_from_slice(&isize_field.to_le_bytes());
        crate::gzip::check_trailer(&t, crc, size).is_ok()
    };
    assert!(ok(7, 0, 0));
    assert!(ok(7, 5, 5));
    assert!(!ok(7, 5, 6));
    // 2^32 + 5 bytes produce a counter of 5
    let counted = (0u32).wrapping_add(u32::MAX).wrapping_add(6);
    assert!(ok(1, counted, 5));
    assert!(!ok(1, counted, 5 + 1));
}

#[test]
#[ignore = "decodes 4 GiB; run with --release -- --ignored"]
fn gzip_member_larger_than_4_gib_wraps_isize() {
    // Covers: SG-R-CDC-02 SG-R-CDC-07
    let n: u64 = (1 << 32) + 1000;
    let mut w = Bits::new();
    let mut toks = vec![Tok::Lit(0)];
    let mut left = n - 1;
    while left >= 258 {
        toks.push(Tok::Match { len: 258, dist: 1 });
        left -= 258;
    }
    toks.extend((0..left).map(|_| Tok::Lit(0)));
    fixed_block(&mut w, &toks, true);
    let raw = w.bytes();
    let block = vec![0u8; 1 << 16];
    let mut crc = 0;
    let mut remaining = n;
    while remaining > 0 {
        let k = remaining.min(block.len() as u64) as usize;
        crc = crc32(&block[..k], crc);
        remaining -= k as u64;
    }
    let mut g = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    g.extend_from_slice(&raw);
    g.extend_from_slice(&crc.to_le_bytes());
    g.extend_from_slice(&(n as u32).to_le_bytes());
    let (input, _) = Chunked::new(&g, 65536);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let k = reader.read(&mut buf).unwrap();
        if k == 0 {
            break;
        }
        total += k as u64;
    }
    assert_eq!(total, n);
}

#[test]
fn gzip_trailing_garbage_and_zero_padding_are_corrupt() {
    // Covers: SG-R-CDC-02
    let member = Member::new(PAYLOAD).build();
    for tail in [
        vec![0u8],
        vec![0; 8],
        vec![0; 512],
        vec![0x1f],
        vec![0x1f, 0x8b],
        vec![0x1f, 0x8b, 8],
        b"garbage after".to_vec(),
        vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0],
    ] {
        let mut m = member.clone();
        m.extend_from_slice(&tail);
        for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (member.len(), 5)] {
            assert_corrupt(
                run_codec(&GzipCodec, &m, chunk, read).0,
                &format!("tail {tail:?} chunk {chunk}"),
            );
        }
    }
    // output before the error is still delivered (the data of the valid member)
    let mut m = member.clone();
    m.push(0);
    let (input, _) = Chunked::new(&m, NO_CHUNKING);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    let mut buf = [0u8; 100];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], PAYLOAD);
    assert_corrupt(reader.read(&mut buf), "garbage");
}

#[test]
fn gzip_concatenated_members() {
    // Covers: SG-R-CDC-02 SG-R-LAY-02
    let mut rng = Rng::new(21);
    for round in 0..60 {
        let count = 1 + rng.below(6);
        let mut input = Vec::new();
        let mut expect = Vec::new();
        for i in 0..count {
            let data = gen(
                rng.below(KINDS),
                rng.below(if round < 30 { 30 } else { 5000 }),
                (round * 10 + i) as u64,
            );
            let member = match rng.below(3) {
                0 => enc_gzip(&data, (i % 10) as u32),
                1 => Member {
                    name: Some(b"x".to_vec()),
                    hcrc: Some(None),
                    ..Member::new(&data)
                }
                .build(),
                _ => {
                    let mut w = Bits::new();
                    fixed_block(&mut w, &tokenize(&data), true);
                    gzip_member(&w.bytes(), &data)
                }
            };
            input.extend_from_slice(&member);
            expect.extend_from_slice(&data);
        }
        assert_eq!(ref_gzip(&input).as_deref(), Some(&expect[..]));
        for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (3, 7), (11, 1000)] {
            let (res, used) = run_codec(&GzipCodec, &input, chunk, read);
            assert_eq!(res.unwrap(), expect, "round {round} chunk {chunk} read {read}");
            assert_eq!(used, input.len());
        }
    }
    // empty members
    let empty = enc_gzip(b"", 6);
    let mut many = Vec::new();
    for _ in 0..100 {
        many.extend_from_slice(&empty);
    }
    assert_eq!(gzip_decode(&many).unwrap(), b"");
    assert_eq!(run_codec(&GzipCodec, &many, 1, 1).0.unwrap(), b"");
    // an error in a later member is reported
    let a = enc_gzip(b"first", 6);
    let mut b = enc_gzip(b"second", 6);
    let last = b.len() - 1;
    b[last] ^= 1;
    let mut both = a.clone();
    both.extend_from_slice(&b);
    assert_corrupt(gzip_decode(&both), "second member damaged");
    // output is limited only by the caller: both members' data comes out
    let (input, _) = Chunked::new(&a, NO_CHUNKING);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    let mut buf = [0u8; 3];
    let mut out = Vec::new();
    loop {
        let n = reader.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(out, b"first");
}

// ---------------------------------------------------------------------------------------------
// zlib / deflate framing
// ---------------------------------------------------------------------------------------------

#[test]
fn zlib_header_detection_table() {
    // Covers: SG-R-CDC-03
    assert!(is_zlib_header(0x78, 0x01));
    assert!(is_zlib_header(0x78, 0x9c));
    assert!(is_zlib_header(0x78, 0xda));
    assert!(is_zlib_header(0x08, 0x1d));
    assert!(!is_zlib_header(0x78, 0x00));
    assert!(!is_zlib_header(0x88, 0x1c)); // CINFO 8
    assert!(!is_zlib_header(0x79, 0x9c)); // CM 9
    assert!(!is_zlib_header(0x00, 0x00));
    for cmf in 0..=255u8 {
        for flg in 0..=255u8 {
            let expected = cmf & 15 == 8 && cmf >> 4 <= 7 && (u32::from(cmf) * 256 + u32::from(flg)) % 31 == 0;
            assert_eq!(is_zlib_header(cmf, flg), expected);
        }
    }
}

#[test]
fn every_two_byte_header_prefix_is_classified_right() {
    // Covers: SG-R-CDC-03
    let payload = b"a";
    let mut w = Bits::new();
    fixed_block(&mut w, &[Tok::Lit(b'a')], true);
    let body = w.bytes();
    let adler = adler32(payload, 1).to_be_bytes();
    for cmf in 0..=255u8 {
        for flg in 0..=255u8 {
            let mut data = vec![cmf, flg];
            data.extend_from_slice(&body);
            data.extend_from_slice(&adler);
            let valid = is_zlib_header(cmf, flg);
            let strict = run_codec(&DeflateCodec::new(true), &data, NO_CHUNKING, 100).0;
            let loose = run_codec(&DeflateCodec::new(false), &data, 1, 1).0;
            if valid && flg & 0x20 != 0 {
                assert_corrupt(strict, &format!("fdict {cmf:#x} {flg:#x}"));
                assert_corrupt(loose, &format!("fdict (not retried as raw) {cmf:#x} {flg:#x}"));
            } else if valid {
                assert_eq!(strict.unwrap(), payload, "{cmf:#x} {flg:#x}");
                assert_eq!(loose.unwrap(), payload);
            } else {
                assert_corrupt(strict, &format!("strict {cmf:#x} {flg:#x}"));
                // the raw reading of the whole input: all bytes must be one raw stream
                match ref_raw(&data) {
                    Some((out, used)) if used == data.len() => assert_eq!(loose.unwrap(), out, "{cmf:#x} {flg:#x}"),
                    _ => assert_corrupt(loose, &format!("loose {cmf:#x} {flg:#x}")),
                }
            }
        }
    }
}

#[test]
fn raw_deflate_is_accepted_unless_strict() {
    // Covers: SG-R-CDC-03
    let mut accepted = 0;
    for (name, payload, raw) in small_streams() {
        if is_zlib_header(raw[0], raw[1]) {
            // a raw stream that looks like zlib is treated as zlib and fails, never misread as data
            assert_corrupt(deflate_decode(&raw), &format!("{name} looks like zlib"));
            continue;
        }
        accepted += 1;
        assert_eq!(deflate_decode(&raw).unwrap(), payload, "{name}");
        assert_eq!(run_codec(&DeflateCodec::new(false), &raw, 1, 1).0.unwrap(), payload);
        assert_corrupt(
            run_codec(&DeflateCodec::new(true), &raw, NO_CHUNKING, 100).0,
            &format!("{name} strict"),
        );
    }
    assert!(accepted > 3);
    // every zlib stream is zlib in both modes
    for (name, payload, raw) in small_streams() {
        let z = zlib_wrap(&raw, &payload);
        assert_eq!(deflate_decode(&z).unwrap(), payload, "{name}");
        assert_eq!(run_codec(&DeflateCodec::new(true), &z, 2, 3).0.unwrap(), payload);
        assert_eq!(ref_zlib(&z).unwrap(), payload);
    }
}

#[test]
fn zlib_adler_trailer_and_trailing_bytes() {
    // Covers: SG-R-CDC-03
    let payload = gen(2, 300, 1);
    let z = enc_zlib(&payload, 6);
    let t = z.len() - 4;
    assert_eq!(deflate_decode(&z).unwrap(), payload);
    for pos in t..z.len() {
        for value in 0..=255u8 {
            if value == z[pos] {
                continue;
            }
            let mut m = z.clone();
            m[pos] = value;
            assert_corrupt(deflate_decode(&m), &format!("adler byte {pos} = {value}"));
        }
    }
    for extra in [vec![0u8], vec![0; 4], b"x".to_vec(), z.clone()] {
        let mut m = z.clone();
        m.extend_from_slice(&extra);
        for strict in [true, false] {
            for (chunk, read) in [(NO_CHUNKING, BIG_READ), (1, 1), (z.len(), 3)] {
                assert_corrupt(
                    run_codec(&DeflateCodec::new(strict), &m, chunk, read).0,
                    &format!("extra {extra:?}"),
                );
            }
        }
    }
    for cut in 0..4 {
        assert_corrupt(deflate_decode(&z[..z.len() - 1 - cut]), &format!("trailer cut {cut}"));
    }
    // raw deflate: bytes after the final block are corrupt
    let mut raw = Bits::new();
    fixed_block(&mut raw, &[Tok::Lit(b'q')], true);
    let mut raw = raw.bytes();
    assert!(!is_zlib_header(raw[0], raw[1]));
    assert_eq!(deflate_decode(&raw).unwrap(), b"q");
    raw.push(0);
    assert_corrupt(deflate_decode(&raw), "raw + 1");
    // the output of a zlib stream is delivered before a bad Adler-32 is reported
    let mut m = z.clone();
    let last = m.len() - 1;
    m[last] ^= 1;
    let (input, _) = Chunked::new(&m, NO_CHUNKING);
    let mut reader = DeflateCodec::new(false).new_reader(Box::new(input));
    let mut buf = vec![0u8; 1000];
    let mut got = Vec::new();
    let err = loop {
        match reader.read(&mut buf) {
            Ok(0) => panic!("a bad Adler-32 was accepted"),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => break e,
        }
    };
    assert_eq!(err.kind(), ErrorKind::Corrupt);
    assert_eq!(got, payload);
}

#[test]
fn zlib_raw_prefix_replay_with_tiny_chunks() {
    // Covers: SG-R-CDC-03 SG-R-RAT-02
    // a raw stream whose first two bytes cross a chunk boundary: the bytes are data, and are all consumed
    for (name, payload, raw) in small_streams() {
        if is_zlib_header(raw[0], raw[1]) {
            continue;
        }
        for chunk in [1usize, 2, 3] {
            let (res, used) = run_codec(&DeflateCodec::new(false), &raw, chunk, 7);
            assert_eq!(res.unwrap(), payload, "{name} chunk {chunk}");
            assert_eq!(used, raw.len());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// the codec contract
// ---------------------------------------------------------------------------------------------

struct FailingInput {
    data: Vec<u8>,
    pos: usize,
    fail_after: usize,
}

impl Read for FailingInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = self.fill_buf()?;
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for FailingInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.fail_after {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "boom"));
        }
        let end = (self.pos + 3).min(self.data.len()).min(self.fail_after);
        Ok(&self.data[self.pos..end])
    }
    fn consume(&mut self, amount: usize) {
        self.pos += amount;
    }
}

#[test]
fn source_errors_are_passed_through_as_source_error() {
    // Covers: SG-R-RDR-05
    let data = gen(2, 2000, 4);
    let g = enc_gzip(&data, 6);
    let z = enc_zlib(&data, 6);
    for fail_after in [0usize, 1, 5, 11, 40, z.len() - 3] {
        for (codec, bytes) in [(&GzipCodec as &dyn Codec, &g), (&DeflateCodec::new(false), &z)] {
            let input = FailingInput {
                data: bytes.clone(),
                pos: 0,
                fail_after,
            };
            let mut reader = codec.new_reader(Box::new(input));
            let mut buf = [0u8; 64];
            let err = loop {
                match reader.read(&mut buf) {
                    Ok(0) => panic!("a failed source gave a clean end"),
                    Ok(_) => {}
                    Err(e) => break e,
                }
            };
            assert_eq!(err.kind(), ErrorKind::SourceError, "fail_after {fail_after}");
            assert!(std::error::Error::source(&err).is_some());
        }
    }
}

#[test]
fn a_zero_length_buffer_is_not_the_end() {
    // Covers: SG-R-RDR-01
    let g = enc_gzip(b"abc", 6);
    let (input, _) = Chunked::new(&g, NO_CHUNKING);
    let mut reader = GzipCodec.new_reader(Box::new(input));
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    let mut buf = [0u8; 10];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"abc");
}

// ---------------------------------------------------------------------------------------------
// speed (not run by default)
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "benchmark; run with --release -- --ignored --nocapture"]
fn bench_against_flate2() {
    let mb = |bytes: usize, secs: f64| bytes as f64 / 1e6 / secs;
    for (name, data) in [
        ("zeros", vec![0u8; 100_000_000]),
        ("text", gen(2, 100_000_000, 1)),
        ("mixed", gen(7, 50_000_000, 2)),
    ] {
        let raw = enc_raw(&data, 6);
        let t = std::time::Instant::now();
        let mut inflater = Inflater::new();
        let mut input: &[u8] = &raw;
        let mut buf = vec![0u8; 65536];
        let mut total = 0;
        loop {
            let n = inflater.read(&mut input, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        let ours = t.elapsed().as_secs_f64();
        assert_eq!(total, data.len());
        let t = std::time::Instant::now();
        let mut d = flate2::read::DeflateDecoder::new(&raw[..]);
        let mut total = 0;
        loop {
            let n = d.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        let theirs = t.elapsed().as_secs_f64();
        assert_eq!(total, data.len());
        let g = enc_gzip(&data, 6);
        let t = std::time::Instant::now();
        let (input, _) = Chunked::new(&g, 4096);
        let mut reader = GzipCodec.new_reader(Box::new(input));
        let mut total = 0;
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        let gz = t.elapsed().as_secs_f64();
        assert_eq!(total, data.len());
        eprintln!(
            "{name}: inflate {:.0} MB/s, flate2 {:.0} MB/s, gzip codec {:.0} MB/s (compressed {} bytes)",
            mb(data.len(), ours),
            mb(data.len(), theirs),
            mb(data.len(), gz),
            raw.len()
        );
    }
}
