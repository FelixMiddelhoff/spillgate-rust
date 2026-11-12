//! Robustness fixes that upstream `brotli-decompressor` made after 5.0.0 (the version vendored in
//! `src/vendored/brotli_decompressor`), probed through the public API with hand-built hostile streams.
//!
//! One test per upstream fix: is the bug in the vendored 5.0.0 source, and can attacker-controlled brotli
//! input reach it through `Decoder`? A passing test documents that the input ends in a typed error (or the
//! right bytes) and never in a panic (`internal`), a hang or a wrong accept. The commits examined are named
//! in each test. Step 1 of the 6.3.1 review only probes; it changes no vendored code.
//!
//! Set `SPILLGATE_BR_DUMP=<dir>` to write every probed stream (`<name>.br`) and spillgate's verdict
//! (`manifest.txt`: `name OK len fnv` or `name ERR`) for a differential run against another decoder;
//! `SPILLGATE_BR_DUMP_ROUNDS` (default 300) says how many structured fuzz streams are written.
#![cfg(feature = "br")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod br_support;

use std::io::{self, Read};
use std::sync::Mutex;

use br_support::*;
use spillgate::{ErrorKind, Limits};
use spillgate_test_support::{brotli_stored, BitWriter};

const MIB: u64 = 1 << 20;

// -- helpers -------------------------------------------------------------------------------------

fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

static DUMP: Mutex<()> = Mutex::new(());

/// Write the stream and the verdict for an external differential run (only with SPILLGATE_BR_DUMP).
fn dump(name: &str, stream: &[u8], outcome: &Outcome) {
    let Ok(dir) = std::env::var("SPILLGATE_BR_DUMP") else {
        return;
    };
    let _guard = DUMP.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(format!("{dir}/{name}.br"), stream).unwrap();
    let line = match outcome.kind {
        None => format!("{name} OK {} {:x}\n", outcome.bytes.len(), fnv(&outcome.bytes)),
        Some(kind) => format!("{name} ERR {kind:?}\n"),
    };
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{dir}/manifest.txt"))
        .unwrap()
        .write_all(line.as_bytes())
        .unwrap();
}

/// Same verdict, and bytes that are prefixes of each other (a failing step may deliver less than another
/// way of feeding the same input does; this is the tolerance of `br_hostile.rs` as well).
fn same_outcome(name: &str, a: &Outcome, b: &Outcome, what: &str) {
    assert_eq!(a.kind, b.kind, "{name}: {what}: different verdict");
    if a.kind.is_none() {
        assert_eq!(a.bytes, b.bytes, "{name}: {what}");
    } else {
        let (short, long) = if a.bytes.len() < b.bytes.len() { (a, b) } else { (b, a) };
        assert!(
            long.bytes.starts_with(&short.bytes),
            "{name}: {what}: delivered bytes are not prefixes"
        );
    }
}

/// Decode with three shapes (big reads and whole input, 1-byte reads and 1-byte chunks, mid-size), require
/// the same verdict, and return the first outcome. A panic would show as `internal`.
fn probe(name: &str, stream: &[u8]) -> Outcome {
    let d = decoder(Limits::new(64 * MIB).disable_ratio_limit(), 24);
    let a = run_with(&d, stream, &["br"], 1 << 16, usize::MAX);
    let b = run_with(&d, stream, &["br"], 1, 1);
    let c = run_with(&d, stream, &["br"], 4096, 7);
    same_outcome(name, &a, &b, "1-byte reads/chunks");
    same_outcome(name, &a, &c, "7-byte chunks");
    assert_ne!(
        a.kind,
        Some(ErrorKind::Internal),
        "{name}: the codec panicked or made no progress"
    );
    dump(name, stream, &a);
    a
}

fn expect_corrupt(name: &str, stream: &[u8]) {
    let o = probe(name, stream);
    assert_eq!(
        o.kind,
        Some(ErrorKind::Corrupt),
        "{name}: an invalid stream was not rejected ({} bytes delivered)",
        o.bytes.len()
    );
}

fn expect_bytes(name: &str, stream: &[u8], bytes: &[u8]) {
    let o = probe(name, stream);
    assert_eq!((o.kind, &o.bytes[..]), (None, bytes), "{name}");
}

fn window_22(w: &mut BitWriter) {
    w.bits(1, 1);
    w.bits(5, 3); // 17 + 5
}

fn window_24(w: &mut BitWriter) {
    w.bits(1, 1);
    w.bits(7, 3);
}

/// A non-last uncompressed meta-block of `data` (at most 65536 bytes).
fn uncompressed(w: &mut BitWriter, data: &[u8]) {
    w.bits(0, 1); // ISLAST
    w.bits(0, 2); // MNIBBLES = 4
    w.bits(data.len() as u64 - 1, 16);
    w.bits(1, 1); // ISUNCOMPRESSED
    w.align();
    w.raw(data);
}

fn end_of_stream(w: &mut BitWriter) {
    w.bits(1, 1); // ISLAST
    w.bits(1, 1); // ISLASTEMPTY
}

/// Header of a compressed meta-block with one block type per category, no context maps and one simple
/// one-symbol prefix code for literals, insert-and-copy commands and distances (they cost no bits).
fn one_symbol_block(w: &mut BitWriter, last: bool, mlen: u64, literal: u64, command: u64, distance: u64) {
    w.bits(u64::from(last), 1);
    if last {
        w.bits(0, 1); // ISLASTEMPTY
    }
    w.bits(0, 2); // MNIBBLES = 4
    w.bits(mlen - 1, 16);
    if !last {
        w.bits(0, 1); // ISUNCOMPRESSED
    }
    w.bits(0, 3); // NBLTYPESL = NBLTYPESI = NBLTYPESD = 1
    w.bits(0, 2); // NPOSTFIX
    w.bits(0, 4); // NDIRECT
    w.bits(0, 2); // context mode of the literal block type
    w.bits(0, 2); // NTREESL = NTREESD = 1
    for (symbol, symbol_bits) in [(literal, 8u32), (command, 10), (distance, 6)] {
        w.bits(1, 2); // HSKIP = 1: simple prefix code
        w.bits(0, 2); // NSYM - 1
        w.bits(symbol, symbol_bits);
    }
}

/// Window 22, one last compressed meta-block of the shape above, then `extra` bits (value, count).
fn single_block(mlen: u64, literal: u64, command: u64, distance: u64, extra: &[(u64, u32)]) -> Vec<u8> {
    let mut w = BitWriter::new();
    window_22(&mut w);
    one_symbol_block(&mut w, true, mlen, literal, command, distance);
    for &(value, n) in extra {
        w.bits(value, n);
    }
    w.finish()
}

// insert-and-copy symbols used below (RFC 7932 section 5): the cell 0..127 has an implicit distance 0,
// the later ones read a distance symbol first.
const INSERT_2_COPY_2_IMPLICIT: u64 = 16; // insert code 2 (2 literals), copy code 0 (2 bytes)
const INSERT_1_COPY_3_EXPLICIT: u64 = 128 + 9; // insert code 1 (1 literal), copy code 1 (3 bytes)
const INSERT_0_COPY_4_EXPLICIT: u64 = 128 + 2; // no literals, copy code 2 (4 bytes)
/// Distance symbol 16: one extra bit, distance 1 + bit.
const DISTANCE_16: u64 = 16;

// -- 693a4a1: meta-blocks that exceed their declared MLEN ----------------------------------------

#[test]
fn control_streams_that_fit_their_mlen_decode() {
    // Covers: SG-R-CDC-04
    // Proves the builder: the same shapes as the hostile streams below, with an MLEN that fits.
    expect_bytes(
        "fit-insert",
        &single_block(2, 65, INSERT_2_COPY_2_IMPLICIT, 0, &[]),
        b"AA",
    );
    expect_bytes(
        "fit-copy",
        &single_block(4, 65, INSERT_1_COPY_3_EXPLICIT, DISTANCE_16, &[(0, 1)]),
        b"AAAA",
    );
    let o = probe(
        "fit-dictionary",
        &single_block(4, 65, INSERT_0_COPY_4_EXPLICIT, DISTANCE_16, &[(0, 1)]),
    );
    assert_eq!((o.kind, o.bytes.len()), (None, 4), "a dictionary word of 4 bytes");
}

#[test]
fn a_command_that_inserts_more_literals_than_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    // Upstream 693a4a1: RFC 7932 section 9.3 requires rejecting it; 5.0.0 only checked in WriteRingBuffer.
    expect_corrupt(
        "overshoot-insert",
        &single_block(1, 65, INSERT_2_COPY_2_IMPLICIT, 0, &[]),
    );
}

#[test]
fn a_copy_longer_than_the_rest_of_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    expect_corrupt(
        "overshoot-copy",
        &single_block(3, 65, INSERT_1_COPY_3_EXPLICIT, DISTANCE_16, &[(0, 1)]),
    );
}

#[test]
fn a_dictionary_word_longer_than_the_rest_of_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    expect_corrupt(
        "overshoot-dictionary",
        &single_block(2, 65, INSERT_0_COPY_4_EXPLICIT, DISTANCE_16, &[(0, 1)]),
    );
}

/// A non-last overshooting meta-block, then an uncompressed one and the end of the stream.
fn overshoot_then_more(mlen: u64, command: u64, distance: u64, extra: &[(u64, u32)]) -> Vec<u8> {
    let mut w = BitWriter::new();
    window_22(&mut w);
    one_symbol_block(&mut w, false, mlen, 65, command, distance);
    for &(value, n) in extra {
        w.bits(value, n);
    }
    uncompressed(&mut w, b"tail");
    end_of_stream(&mut w);
    w.finish()
}

// Not last: upstream 693a4a1 says the overshoot decoded as success when the whole output fitted in the ring
// buffer. The three tests below are separate so that each shape reports on its own.

#[test]
#[ignore = "reason: known, fix pending rebase to 6.3.1"] // upstream 693a4a1
fn a_non_last_meta_block_inserting_more_literals_than_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    expect_corrupt(
        "overshoot-insert-then-more",
        &overshoot_then_more(1, INSERT_2_COPY_2_IMPLICIT, 0, &[]),
    );
}

#[test]
#[ignore = "reason: known, fix pending rebase to 6.3.1"] // upstream 693a4a1
fn a_non_last_meta_block_copying_more_than_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    expect_corrupt(
        "overshoot-copy-then-more",
        &overshoot_then_more(3, INSERT_1_COPY_3_EXPLICIT, DISTANCE_16, &[(0, 1)]),
    );
}

#[test]
#[ignore = "reason: known, fix pending rebase to 6.3.1"] // upstream 693a4a1
fn a_non_last_meta_block_with_a_dictionary_word_longer_than_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    expect_corrupt(
        "overshoot-dictionary-then-more",
        &overshoot_then_more(2, INSERT_0_COPY_4_EXPLICIT, DISTANCE_16, &[(0, 1)]),
    );
}

#[test]
fn a_huge_copy_far_beyond_mlen_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    // Copy code 23 with all extra bits set (2118 + 2^24 - 1 bytes) in a meta-block of 2 bytes: the run
    // wraps the 4 MiB ring buffer of window 22, where 5.0.0 checks the length in WriteRingBuffer.
    for last in [true, false] {
        let mut w = BitWriter::new();
        window_22(&mut w);
        one_symbol_block(&mut w, last, 2, 65, 384 + 8 + 7, DISTANCE_16);
        w.bits((1 << 24) - 1, 24); // copy length extra bits
        w.bits(0, 1); // distance extra bit
        if !last {
            end_of_stream(&mut w);
        }
        expect_corrupt(&format!("huge-copy-last{last}"), &w.finish());
    }
}

// -- cc7ee0e: a block switch with one block type -------------------------------------------------

/// A command inserting `2^24 + 5` literals through a literal tree of one symbol (zero bits per literal):
/// more literals than the 2^24 that one block type can hold. `start` bytes are written before it by an
/// uncompressed meta-block (so that the ring buffer is full-size and the run does not start at 0).
fn long_insert(start: usize, window: u32) -> Vec<u8> {
    let mut w = BitWriter::new();
    if window == 24 {
        window_24(&mut w);
    } else {
        w.bits(1, 1);
        w.bits(0, 3);
        w.bits(u64::from(window) - 8, 3); // 10..=15
    }
    if start > 0 {
        uncompressed(&mut w, &vec![b'x'; start]);
    }
    one_symbol_block(&mut w, true, 1, 65, 504, 0); // 504: insert code 23, copy code 0
    w.bits((1 << 24) + 5 - 22594, 24); // extra bits of insert code 23
    w.finish()
}

#[test]
fn more_literals_than_one_block_type_holds_is_corrupt_not_a_wait_for_input() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08 SG-R-INP-01
    // Upstream cc7ee0e (commit text: CVE-2026-111497 in the C decoder, unverified): a block switch in a
    // category with a single block type is a format error; reported as "needs more input" the streaming
    // decoder waits for input that cannot help. 5.0.0 has the same shape, so probe it: 2^24 + 5 literals
    // from a handful of input bytes, at several starting positions of the ring buffer.
    for (start, window) in [
        (0usize, 24u32),
        (1, 24),
        (5, 24),
        (100, 24),
        (1000, 24),
        (0, 10),
        (1, 10),
    ] {
        let stream = long_insert(start, window);
        assert!(stream.len() < 1200, "{} bytes", stream.len());
        let o = probe(&format!("long-insert-{start}-{window}"), &stream);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt), "start {start} window {window}");
    }
}

#[test]
fn the_long_insert_with_an_endless_source_ends_in_a_typed_error_with_bounded_input() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08 SG-R-INP-01 SG-R-INP-02
    // The question behind cc7ee0e: does a decoder that keeps getting data hang or loop without progress?
    // The stream is followed by an endless supply of bytes; MaxInput must not be the only thing that ends it.
    for (start, window) in [(0usize, 24u32), (1, 24), (100, 24), (1, 10)] {
        let stream = long_insert(start, window);
        let o = endless(&stream, 0xff, Limits::new(64 * MIB).disable_ratio_limit(), 4 << 30);
        assert_eq!(
            o.kind,
            Some(ErrorKind::Corrupt),
            "start {start} window {window}: {:?}",
            o.kind
        );
        // and with the MaxInput guard, the same verdict arrives long before the cap
        let o = endless(
            &stream,
            0,
            Limits::new(64 * MIB).disable_ratio_limit().max_input(1 << 20),
            4 << 30,
        );
        assert!(
            matches!(o.kind, Some(ErrorKind::Corrupt) | Some(ErrorKind::InputLimit)),
            "start {start} window {window}: {:?}",
            o.kind
        );
    }
}

/// Source that yields `stream` and then `filler` forever; counts what it handed out and stops handing out
/// after `budget` bytes in total (an error, so a test cannot hang).
struct Endless {
    stream: Vec<u8>,
    pos: usize,
    filler: u8,
    handed: u64,
    budget: u64,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.handed >= self.budget {
            return Err(io::Error::other("test budget exhausted: the decoder never finished"));
        }
        let n = buf.len().min(4096);
        for slot in &mut buf[..n] {
            *slot = self.stream.get(self.pos).copied().unwrap_or(self.filler);
            self.pos += 1;
        }
        self.handed += n as u64;
        Ok(n)
    }
}

fn endless(stream: &[u8], filler: u8, limits: Limits, budget: u64) -> Outcome {
    // a hostile stream followed by filler cannot be tested with an endless allowance: cap the total
    let budget = budget.min(256 * MIB);
    let src = Endless {
        stream: stream.to_vec(),
        pos: 0,
        filler,
        handed: 0,
        budget,
    };
    let d = decoder(limits, 24);
    match d.reader(src, &["br"]) {
        Err(e) => Outcome {
            bytes: Vec::new(),
            kind: Some(e.kind()),
        },
        Ok(mut r) => {
            let o = drain(&mut r, 1 << 16);
            r.close();
            o
        }
    }
}

// -- 8ed0d7d, 677eef1: padding -------------------------------------------------------------------

#[test]
#[ignore = "reason: known, fix pending rebase to 6.3.1"] // upstream 8ed0d7d
fn nonzero_padding_bits_at_the_end_of_the_stream_are_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    // Upstream 8ed0d7d: PADDING_2 was set but not returned, and the final write replaced it with success.
    let stream = brotli_stored(b"hello", 16).unwrap();
    let last = stream.len() - 1;
    assert_eq!(stream[last], 0b11, "ISLAST, ISLASTEMPTY and zero padding");
    expect_bytes("padding-end-control", &stream, b"hello");
    for bit in 2..8 {
        let mut damaged = stream.clone();
        damaged[last] |= 1 << bit;
        expect_corrupt(&format!("padding-end-bit{bit}"), &damaged);
    }
}

#[test]
#[ignore = "reason: known, fix pending rebase to 6.3.1"] // upstream 8ed0d7d
fn nonzero_padding_bits_after_a_compressed_last_meta_block_are_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    // Upstream 8ed0d7d, the same rule after a compressed meta-block.
    let compressed = single_block(2, 65, INSERT_2_COPY_2_IMPLICIT, 0, &[]);
    expect_bytes("padding-compressed-control", &compressed, b"AA");
    let used_bits = 1 + 3 + 1 + 1 + 2 + 16 + 3 + 2 + 4 + 2 + 2 + 3 * (2 + 2) + 8 + 10 + 6;
    assert!(used_bits % 8 != 0, "the test needs padding bits ({used_bits})");
    for bit in (used_bits % 8)..8 {
        let mut damaged = compressed.clone();
        let last = damaged.len() - 1;
        damaged[last] |= 1 << bit;
        expect_corrupt(&format!("padding-compressed-bit{bit}"), &damaged);
    }
}

#[test]
fn nonzero_padding_before_uncompressed_data_is_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    // Upstream 677eef1 only changes the error code (PADDING_1 instead of PADDING_2); both are rejections.
    let stream = brotli_stored(b"hello", 16).unwrap();
    // 1 (WBITS 16) + 1 (ISLAST) + 2 + 16 + 1 = 21 bits: bits 5..7 of byte 2 are padding
    assert_eq!(stream[2] >> 5, 0);
    for bit in 5..8 {
        let mut damaged = stream.clone();
        damaged[2] |= 1 << bit;
        expect_corrupt(&format!("padding-uncompressed-bit{bit}"), &damaged);
    }
}

#[test]
fn metadata_blocks_obey_the_reserved_bit_and_padding_rules() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08
    // WBITS 16, ISLAST 0, MNIBBLES 3 (metadata), reserved 0, MSKIPBYTES 1, MSKIPLEN-1 = 2, pad, 3 bytes.
    let build = |reserved: u64, padding: u64| {
        let mut w = BitWriter::new();
        w.bits(0, 1);
        w.bits(0, 1);
        w.bits(3, 2);
        w.bits(reserved, 1);
        w.bits(1, 2);
        w.bits(2, 8);
        w.bits(padding, 1); // bit 15, the only padding bit
        w.align();
        w.raw(b"xyz");
        end_of_stream(&mut w);
        w.finish()
    };
    expect_bytes("metadata-control", &build(0, 0), b"");
    expect_corrupt("metadata-reserved-bit", &build(1, 0));
    expect_corrupt("metadata-padding", &build(0, 1));
}

// -- 8cb69d1, c1f6944, c31d20b: sizes the caller hands in ----------------------------------------

/// A source recording the largest buffer it was asked to fill.
struct Widest<'a> {
    data: &'a [u8],
    pos: usize,
    widest: &'a std::cell::Cell<usize>,
}

impl Read for Widest<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.widest.set(self.widest.get().max(buf.len()));
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn the_decoder_is_never_shown_more_than_one_small_buffer_of_input() {
    // Covers: SG-R-CDC-04 SG-R-INP-02
    // 8cb69d1 (uncompressed copy length cast to i32: needs >= 2^31 bytes of available input), c1f6944
    // (input_offset + available_in overflow: needs a length near usize::MAX) and c31d20b (input past
    // 4 GiB wrapping the u32 cursor) all need one huge slice handed to the decoder. The input meter
    // fetches at most 4096 bytes, so the codec never sees such a slice, whatever the caller's source is.
    let payload = noise(11, 300_000);
    let stream = brotli_stored(&payload, 18).unwrap();
    for read_size in [1usize, 4096, 1 << 20] {
        let widest = std::cell::Cell::new(0);
        let src = Widest {
            data: &stream,
            pos: 0,
            widest: &widest,
        };
        let d = decoder(loose(), 24);
        let mut r = d.reader(src, &["br"]).unwrap();
        let o = drain(&mut r, read_size);
        r.close();
        assert_eq!((o.kind, o.bytes.len()), (None, payload.len()));
        assert!(o.bytes == payload);
        assert!(
            widest.get() <= 4096,
            "the source was asked for {} bytes at once",
            widest.get()
        );
    }
}

#[test]
fn uncompressed_meta_blocks_larger_than_the_window_copy_correctly_at_every_chunking() {
    // Covers: SG-R-CDC-04
    // The code of 8cb69d1 clamps by ring-buffer room; a meta-block of 1 MiB through a 1 KiB window and
    // the other windows must copy exactly, whatever the chunking.
    let payload = noise(12, 200_000);
    for wbits in [10u32, 11, 16, 24] {
        let stream = brotli_stored(&payload, wbits).unwrap();
        for chunk in [1usize, 5, 4095, 4096, 4097, usize::MAX] {
            let o = run_with(&decoder(loose(), 24), &stream, &["br"], 70_000, chunk);
            assert_eq!(
                (o.kind, o.bytes == payload),
                (None, true),
                "window {wbits} chunk {chunk}"
            );
        }
    }
    // declared longer than delivered: corrupt, never a short success
    let mut w = BitWriter::new();
    w.bits(0, 1);
    w.bits(0, 1);
    w.bits(0, 2);
    w.bits(60_000, 16); // 60001 bytes declared
    w.bits(1, 1);
    w.align();
    w.raw(&payload[..5000]);
    let truncated = w.finish();
    for chunk in [1usize, 4096, usize::MAX] {
        let o = run_with(&decoder(loose(), 24), &truncated, &["br"], 4096, chunk);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt), "chunk {chunk}");
        assert!(payload.starts_with(&o.bytes));
    }
}

// -- 79404c1: Huffman group leak on a distance error ----------------------------------------------

#[test]
fn the_largest_distances_the_format_can_express_are_rejected_without_a_leak() {
    // Covers: SG-R-CDC-04 SG-R-CDC-08 SG-R-MEM-02
    // Upstream 79404c1: the FORMAT_DISTANCE return for a distance above 0x7FFFFFFC dropped the tree groups.
    // Without the large-window extension (refused here) the largest distance is below 2^30, so the line is
    // unreachable; probe the extreme distance symbols and confirm a clean typed error whose reader releases
    // everything (later reads repeat the error).
    for np in 0..=3u64 {
        let nd = 15u64;
        let alphabet = 16 + nd + (48 << np);
        let symbol_bits = 64 - (alphabet - 1).leading_zeros();
        for dist in [alphabet - 1, alphabet - 2, 16, 20] {
            let mut w = BitWriter::new();
            window_22(&mut w);
            w.bits(1, 1); // ISLAST
            w.bits(0, 1);
            w.bits(0, 2);
            w.bits(99, 16); // MLEN 100
            w.bits(0, 3);
            w.bits(np, 2);
            w.bits(nd, 4);
            w.bits(0, 2);
            w.bits(0, 2);
            for (symbol, bits) in [(65u64, 8u32), (128 + 2, 10), (dist, symbol_bits)] {
                w.bits(1, 2);
                w.bits(0, 2);
                w.bits(symbol, bits);
            }
            w.bits(u64::MAX >> 40, 24); // extra bits: all ones
            w.bits(u64::MAX >> 40, 24);
            let name = format!("far-distance-np{np}-sym{dist}");
            let stream = w.finish();
            let o = probe(&name, &stream);
            assert_eq!(o.kind, Some(ErrorKind::Corrupt), "{name}");
            // a reader repeats its failure and does not turn it into a clean end
            let d = decoder(loose(), 24);
            let mut r = d.reader(&stream[..], &["br"]).unwrap();
            let mut buf = [0u8; 256];
            let mut errors = 0;
            for _ in 0..4 {
                if r.read(&mut buf).is_err() {
                    errors += 1;
                }
            }
            assert!(errors >= 3, "{name}: the failure is not repeated");
        }
    }
}

// -- b1d31a8: decoder panics on malformed streams -----------------------------------------------

struct Rng2(u64);
impl Rng2 {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// A random simple prefix code (NSYM 1..4 symbols below `limit`) over an alphabet of `symbol_bits` bits.
fn random_simple_code(w: &mut BitWriter, rng: &mut Rng2, symbol_bits: u32, limit: u64) {
    w.bits(1, 2); // HSKIP = 1: simple
    let nsym = 1 + rng.below(4);
    w.bits(nsym - 1, 2);
    for _ in 0..nsym {
        let s = if rng.below(8) == 0 {
            rng.below(1 << symbol_bits)
        } else {
            rng.below(limit)
        };
        w.bits(s, symbol_bits);
    }
    if nsym == 4 {
        w.bits(rng.below(2), 1); // tree-select
    }
}

fn alphabet_bits(alphabet: u64) -> u32 {
    64 - (alphabet - 1).leading_zeros()
}

/// A block-type count of 1, 2 or 3 types with the trees and first block count it needs.
fn random_block_types(w: &mut BitWriter, rng: &mut Rng2, deep: bool) -> u64 {
    match if deep { 0 } else { rng.below(6) } {
        0..=3 => {
            w.bits(0, 1);
            1
        }
        4 => {
            w.bits(1, 1);
            w.bits(0, 3); // 2 types
            random_simple_code(w, rng, alphabet_bits(4), 4);
            random_simple_code(w, rng, alphabet_bits(26), 26);
            w.bits(rng.below(1 << 12), 12); // first block count (extra bits, whatever it needs)
            2
        }
        _ => {
            w.bits(1, 1);
            w.bits(1, 3);
            w.bits(0, 1); // 3 types
            random_simple_code(w, rng, alphabet_bits(5), 5);
            random_simple_code(w, rng, alphabet_bits(26), 26);
            w.bits(rng.below(1 << 12), 12);
            3
        }
    }
}

fn random_stream(rng: &mut Rng2) -> Vec<u8> {
    // `deep` streams keep to a few symbols and one tree so that the command loop, copies, distances and
    // dictionary words actually run; the others roam the whole header space.
    let deep = rng.below(10) < 6;
    let mut w = BitWriter::new();
    match rng.below(5) {
        0 => w.bits(0, 1),
        1 => {
            w.bits(1, 1);
            w.bits(0, 3);
            w.bits(0, 3);
        }
        2 => {
            w.bits(1, 1);
            w.bits(0, 3);
            w.bits(2 + rng.below(6), 3); // 10..15
        }
        _ => {
            w.bits(1, 1);
            w.bits(1 + rng.below(7), 3); // 18..24
        }
    }
    for index in 0..1 + rng.below(3) {
        let last = rng.below(3) == 0;
        w.bits(u64::from(last), 1);
        if last {
            w.bits(rng.below(8) / 7, 1); // sometimes ISLASTEMPTY
        }
        w.bits(0, 2);
        let span = if deep {
            120
        } else if rng.below(4) == 0 {
            65536
        } else {
            400
        };
        w.bits(rng.below(span), 16);
        if !last {
            w.bits(u64::from(rng.below(10) == 0), 1);
        }
        if index == 0 && rng.below(12) == 0 {
            // an uncompressed or empty meta-block is possible here; the tail is random anyway
            for _ in 0..rng.below(40) {
                w.bits(rng.next(), 8);
            }
            continue;
        }
        let lt = random_block_types(&mut w, rng, deep);
        random_block_types(&mut w, rng, deep);
        random_block_types(&mut w, rng, deep);
        let np = if !deep && rng.below(3) == 0 { rng.below(4) } else { 0 };
        let nd = if !deep && rng.below(3) == 0 { rng.below(16) } else { 0 };
        w.bits(np, 2);
        w.bits(nd, 4);
        for _ in 0..lt {
            w.bits(rng.below(4), 2); // context modes
        }
        // NTREESL, NTREESD: mostly one tree (no context map)
        for _ in 0..2 {
            if !deep && rng.below(5) == 0 {
                w.bits(1, 1);
                w.bits(0, 3); // 2 trees: a context map follows (random bits)
            } else {
                w.bits(0, 1);
            }
        }
        random_simple_code(&mut w, rng, 8, 256);
        random_simple_code(&mut w, rng, 10, if deep { 200 } else { 704 });
        let dist_alphabet = 16 + nd + (48 << np);
        let dist_limit = if deep { dist_alphabet.min(26) } else { dist_alphabet };
        random_simple_code(&mut w, rng, alphabet_bits(dist_alphabet), dist_limit);
        for _ in 0..rng.below(24) {
            w.bits(rng.next(), 8);
        }
    }
    if rng.below(2) == 0 {
        end_of_stream(&mut w);
    }
    w.finish()
}

#[test]
fn structured_hostile_streams_never_panic_and_stop_with_a_typed_error() {
    // Covers: SG-I-05 SG-R-CDC-04 SG-R-CDC-08
    // Upstream b1d31a8 replaces asserts, unchecked indexing and unchecked arithmetic in the decoder with
    // errors. Streams here are random meta-blocks of simple prefix codes with random command bits (so
    // copies, dictionary words, block switches and distance codes run), random block-type counts and
    // random tails. Anything but ok or a typed limit/corrupt error fails, and a panic shows as `internal`.
    let rounds: u64 = std::env::var("SPILLGATE_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000);
    let dump_rounds: u64 = std::env::var("SPILLGATE_BR_DUMP_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut rng = Rng2(0x6f1d_2b9a_77c3_01e5);
    let mut seen = std::collections::BTreeMap::new();
    for round in 0..rounds {
        let stream = random_stream(&mut rng);
        let d = decoder(Limits::new(8 * MIB).disable_ratio_limit(), 24);
        let a = run_with(&d, &stream, &["br"], 1 << 16, usize::MAX);
        assert!(
            matches!(
                a.kind,
                None | Some(ErrorKind::Corrupt) | Some(ErrorKind::MemoryLimit) | Some(ErrorKind::OutputLimit)
            ),
            "round {round}: {:?} for {stream:02x?}",
            a.kind
        );
        if round % 7 == 0 {
            // the chunking must not change the verdict or the bytes
            let b = run_with(&d, &stream, &["br"], 3, 1);
            same_outcome(&format!("round {round} {stream:02x?}"), &a, &b, "chunking");
        }
        if round < dump_rounds {
            dump(&format!("fuzz-{round:05}"), &stream, &a);
        }
        *seen.entry(format!("{:?}", a.kind)).or_insert(0u32) += 1;
    }
    eprintln!("structured fuzz over {rounds} rounds: {seen:?}");
    // the generator must reach the decoding loop, not only die in the headers
    assert!(
        seen.get("None").copied().unwrap_or(0) > 0,
        "no stream was accepted: {seen:?}"
    );
}

#[test]
fn streams_followed_by_endless_data_end_in_a_typed_error_not_a_hang() {
    // Covers: SG-I-05 SG-R-CDC-04 SG-R-CDC-08 SG-R-INP-01
    // Question (b): can an input keep the decoder busy while the source keeps delivering? 400 hostile
    // streams followed by endless filler: each must end, with the budget as a backstop, and never in
    // `internal` (panic, or the codec's own no-progress guard).
    let mut rng = Rng2(0x1357_9bdf_2468_ace0);
    for round in 0..400 {
        let stream = random_stream(&mut rng);
        let filler = [0u8, 0xff, 0x55][round % 3];
        let o = endless(&stream, filler, Limits::new(8 * MIB).disable_ratio_limit(), 64 * MIB);
        assert!(
            matches!(
                o.kind,
                Some(ErrorKind::Corrupt) | Some(ErrorKind::OutputLimit) | Some(ErrorKind::MemoryLimit)
            ),
            "round {round}: {:?} for {stream:02x?}",
            o.kind
        );
    }
}

// -- mutated encoder streams ---------------------------------------------------------------------

fn mutate(rng: &mut Rng2, base: &[u8]) -> Vec<u8> {
    let mut data = base.to_vec();
    for _ in 0..1 + rng.below(4) {
        if data.is_empty() {
            data.push(rng.next() as u8);
            continue;
        }
        let at = rng.below(data.len() as u64) as usize;
        match rng.below(7) {
            0..=2 => data[at] ^= 1 << rng.below(8),
            3 => data[at] = rng.next() as u8,
            4 => data.insert(at, rng.next() as u8),
            5 => {
                data.remove(at);
            }
            _ => data.truncate(at),
        }
    }
    data
}

#[test]
fn mutated_encoder_streams_never_panic_and_stay_deterministic() {
    // Covers: SG-I-05 SG-R-CDC-04 SG-R-CDC-08
    // Deep coverage of the command loop (real Huffman codes, context maps, block switches, dictionary
    // words): the streams of the reference encoder with one to four random edits.
    let rounds: u64 = std::env::var("SPILLGATE_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6000);
    let bases: Vec<Vec<u8>> = vec![
        compress(&text(3000), 5, 22),
        compress(&text(1500), 11, 24),
        compress(&mixed(5000), 9, 12),
        compress(&mixed(3000), 6, 16),
        compress(&noise(8, 700), 1, 16),
        compress(&[noise(5, 150), text(300), noise(6, 150)].concat(), 5, 14),
        compress(&vec![b'a'; 3000], 5, 22),
        brotli_stored(&noise(4, 300), 24).unwrap(),
    ];
    let dump_rounds: u64 = std::env::var("SPILLGATE_BR_DUMP_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut rng = Rng2(0x5eed_1234_abcd_9876);
    let mut seen = std::collections::BTreeMap::new();
    for round in 0..rounds {
        let base = &bases[rng.below(bases.len() as u64) as usize];
        let stream = mutate(&mut rng, base);
        let d = decoder(Limits::new(8 * MIB).disable_ratio_limit(), 24);
        let a = run_with(&d, &stream, &["br"], 1 << 16, usize::MAX);
        assert!(
            matches!(
                a.kind,
                None | Some(ErrorKind::Corrupt) | Some(ErrorKind::MemoryLimit) | Some(ErrorKind::OutputLimit)
            ),
            "round {round}: {:?} for {stream:02x?}",
            a.kind
        );
        if round % 5 == 0 {
            let b = run_with(&d, &stream, &["br"], 4096, 1);
            same_outcome(&format!("mutated round {round}"), &a, &b, "chunking");
        }
        if round < dump_rounds {
            dump(&format!("mutated-{round:05}"), &stream, &a);
        }
        *seen.entry(format!("{:?}", a.kind)).or_insert(0u32) += 1;
    }
    eprintln!("mutated streams over {rounds} rounds: {seen:?}");
}
