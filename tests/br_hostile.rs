//! The brotli codec on hostile and damaged streams: bombs, truncation, bit flips, trailing data,
//! exact input accounting, seeded mutation fuzzing.
#![cfg(feature = "br")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod br_support;

use br_support::*;
use spillgate::br::{self, BrotliOptions};
use spillgate::{Codec, ErrorKind, Limits};
use spillgate_test_support::{brotli_stored, brotli_zeros};

const MIB: u64 = 1 << 20;

// -- bombs ---------------------------------------------------------------------------------------

#[test]
fn bombs_end_in_output_limit_with_bounded_steps() {
    // Covers: SG-R-LAY-02 SG-R-MEM-02 SG-I-08 SG-R-CDC-01
    // 1 GiB, 4 GiB and 64 GiB of zeros in at most a few dozen KiB of brotli. `drain` asserts that no single
    // read returns more than the 64 KiB step although the caller offers 1 MiB.
    for (size, wbits) in [(1u64 << 30, 24u32), (4 << 30, 24), (64 << 30, 22), (1 << 30, 10)] {
        let bomb = brotli_zeros(size, wbits).unwrap();
        assert!(bomb.len() < 100_000, "{} bytes", bomb.len());
        let d = decoder(Limits::new(64 * MIB).disable_ratio_limit(), 24);
        let mut reader = d.reader(&bomb[..], &["br"]).unwrap();
        let o = drain(&mut reader, 1 << 20);
        assert_eq!(o.kind, Some(ErrorKind::OutputLimit), "{size}/{wbits}");
        assert_eq!(o.bytes.len() as u64, 64 * MIB, "{size}/{wbits}");
        assert!(o.bytes.iter().all(|&b| b == 0));
        reader.close();
    }
}

#[test]
fn an_encoder_made_bomb_ends_in_output_limit() {
    // Covers: SG-R-LAY-02 SG-I-08
    let bomb = compress(&vec![0u8; 100 << 20], 1, 22);
    assert!(bomb.len() < 1_000_000, "{} bytes", bomb.len());
    let d = decoder(Limits::new(10 * MIB).disable_ratio_limit(), 24);
    let o = run_with(&d, &bomb, &["br"], 1 << 20, 4096);
    assert_eq!((o.kind, o.bytes.len() as u64), (Some(ErrorKind::OutputLimit), 10 * MIB));
}

#[test]
fn the_ratio_limit_fires_on_a_brotli_bomb() {
    // Covers: SG-R-RAT-01 SG-R-CDC-01
    let bomb = brotli_zeros(1 << 30, 24).unwrap();
    let o = run(&bomb, Limits::new(1 << 31));
    assert_eq!(o.kind, Some(ErrorKind::RatioLimit));
    // far fewer bytes than the output limit allowed were delivered: the ratio stopped it early
    assert!(o.bytes.len() < (64 << 20));
    // a lower ratio fires earlier
    let o2 = run(&bomb, Limits::new(1 << 31).max_ratio(10));
    assert_eq!(o2.kind, Some(ErrorKind::RatioLimit));
    assert!(o2.bytes.len() <= o.bytes.len());
}

#[test]
fn a_bomb_within_the_budget_is_a_clean_end() {
    // Covers: SG-R-LAY-02
    let bomb = brotli_zeros(40 * MIB, 24).unwrap();
    let o = run(&bomb, Limits::new(64 * MIB).disable_ratio_limit());
    assert_eq!((o.kind, o.bytes.len() as u64), (None, 40 * MIB));
    // exactly the output limit is fine, one byte less is not
    let o = run(&bomb, Limits::new(40 * MIB).disable_ratio_limit());
    assert_eq!((o.kind, o.bytes.len() as u64), (None, 40 * MIB));
    let o = run(&bomb, Limits::new(40 * MIB - 1).disable_ratio_limit());
    assert_eq!(
        (o.kind, o.bytes.len() as u64),
        (Some(ErrorKind::OutputLimit), 40 * MIB - 1)
    );
}

// -- truncation and trailing data ----------------------------------------------------------------

#[test]
fn an_empty_input_is_corrupt() {
    // Covers: SG-R-CDC-06
    assert_eq!(run(&[], loose()).kind, Some(ErrorKind::Corrupt));
    let d = decoder(loose(), 24);
    assert_eq!(run_with(&d, &[], &["br"], 1, 1).kind, Some(ErrorKind::Corrupt));
}

#[test]
fn every_truncation_is_corrupt() {
    // Covers: SG-R-CDC-06
    for (name, payload, quality, lgwin) in [
        ("mixed", mixed(4000), 5, 22),
        ("noise q1", noise(2, 600), 1, 16),
        ("text q11", text(1500), 11, 24),
    ] {
        let stream = compress(&payload, quality, lgwin);
        for cut in 0..stream.len() {
            let o = run(&stream[..cut], loose());
            assert_eq!(o.kind, Some(ErrorKind::Corrupt), "{name} cut {cut}/{}", stream.len());
            assert!(
                payload.starts_with(&o.bytes),
                "{name} cut {cut}: output is not a prefix"
            );
        }
        // byte-wise delivery gives the same verdict
        let d = decoder(loose(), 24);
        for cut in (0..stream.len()).step_by(7) {
            assert_eq!(
                run_with(&d, &stream[..cut], &["br"], 4096, 1).kind,
                Some(ErrorKind::Corrupt),
                "{name} cut {cut} (1-byte chunks)"
            );
        }
    }
}

#[test]
fn trailing_bytes_after_the_stream_are_corrupt() {
    // Covers: SG-R-CDC-04 SG-R-CDC-06
    let payload = mixed(5000);
    let stream = compress(&payload, 5, 22);
    let d = decoder(loose(), 24);
    for tail in [vec![0u8], vec![120; 100], vec![0; 5000], vec![0xff], stream.clone()] {
        let mut data = stream.clone();
        data.extend(&tail);
        for chunk in [1usize, 3, 4096, usize::MAX] {
            let o = run_with(&d, &data, &["br"], 4096, chunk);
            assert_eq!(
                o.kind,
                Some(ErrorKind::Corrupt),
                "tail {} bytes, chunk {chunk}",
                tail.len()
            );
            // the stream itself was decoded completely before the verdict
            assert!(payload.starts_with(&o.bytes));
        }
    }
}

#[test]
fn concatenated_streams_are_corrupt_and_the_error_is_sticky() {
    // Covers: SG-R-CDC-04 SG-R-RDR-07
    let a = mixed(3000);
    let b = text(2000);
    let mut data = compress(&a, 5, 22);
    data.extend(compress(&b, 5, 22));
    let d = decoder(loose(), 24);
    let mut reader = d.reader(&data[..], &["br"]).unwrap();
    let o = drain(&mut reader, 4096);
    assert_eq!(o.kind, Some(ErrorKind::Corrupt));
    assert!(a.starts_with(&o.bytes));
    // never a clean end afterwards
    for _ in 0..3 {
        let e = std::io::Read::read(&mut reader, &mut [0u8; 64]).unwrap_err();
        assert_eq!(kind_of(&e), ErrorKind::Corrupt);
    }
}

#[test]
fn an_empty_stream_with_trailing_bytes_is_corrupt() {
    // Covers: SG-R-CDC-04
    let stream = compress(&[], 5, 22);
    assert_eq!(
        run(&stream, loose()),
        Outcome {
            bytes: vec![],
            kind: None
        }
    );
    let mut data = stream.clone();
    data.push(0);
    assert_eq!(run(&data, loose()).kind, Some(ErrorKind::Corrupt));
}

// -- exact input accounting ----------------------------------------------------------------------

fn codec_reader(rec: Recording) -> Box<dyn spillgate::CodecReader> {
    br::codec(BrotliOptions::default()).unwrap().new_reader(Box::new(rec))
}

/// Read to the end or the first error; returns (output, error kind).
fn pump(reader: &mut dyn spillgate::CodecReader) -> (Vec<u8>, Option<ErrorKind>) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => {
                assert!(n <= 64 * 1024, "{n} bytes in one step");
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) => return (out, Some(e.kind())),
        }
    }
}

#[test]
fn the_codec_consumes_exactly_the_stream() {
    // Covers: SG-R-RAT-02 SG-R-CDC-01
    let streams = [
        compress(&mixed(30_000), 5, 22),
        compress(&noise(4, 9000), 1, 16),
        compress(&[], 5, 22),
        compress(b"x", 11, 10),
        brotli_zeros(3 * MIB, 24).unwrap(),
        brotli_stored(&noise(9, 5000), 18).unwrap(),
    ];
    for (i, stream) in streams.iter().enumerate() {
        for chunk in [1usize, 2, 3, 5, 7, 100, 4096, usize::MAX] {
            for extra in [0usize, 1, 100] {
                let mut data = stream.clone();
                data.extend(vec![0xa5u8; extra]);
                let rec = Recording::new(&data, chunk);
                let stats = rec.stats.clone();
                let mut reader = codec_reader(rec);
                let (_, kind) = pump(reader.as_mut());
                let expected = if extra == 0 { None } else { Some(ErrorKind::Corrupt) };
                assert_eq!(kind, expected, "stream {i} chunk {chunk} extra {extra}");
                assert_eq!(
                    stats.consumed.get(),
                    stream.len(),
                    "stream {i} chunk {chunk} extra {extra}: consumed bytes"
                );
                assert_eq!(
                    stats.violations.get(),
                    0,
                    "stream {i} chunk {chunk}: consume beyond fill_buf"
                );
            }
        }
    }
}

#[test]
fn the_codec_never_consumes_beyond_what_it_was_shown() {
    // Covers: SG-R-CDC-01 SG-R-CDC-08
    // Damaged streams too: whatever happens, consume never exceeds the last fill_buf, and the codec
    // never consumes more than the input holds.
    let base = compress(&mixed(3000), 5, 22);
    let mut rng = Rng(0x5eed);
    for round in 0..300 {
        let mut data = base.clone();
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(data.len() as u64) as usize;
            data[at] ^= 1 << rng.below(8);
        }
        let chunk = [1usize, 4, 4096][round % 3];
        let rec = Recording::new(&data, chunk);
        let stats = rec.stats.clone();
        let mut reader = codec_reader(rec);
        let (_, kind) = pump(reader.as_mut());
        assert_ne!(kind, Some(ErrorKind::Internal), "round {round}");
        assert_eq!(stats.violations.get(), 0, "round {round}");
        assert!(stats.consumed.get() <= data.len(), "round {round}");
    }
}

#[test]
fn a_success_with_trailing_data_leaves_the_trailing_data_unconsumed() {
    // Covers: SG-R-RAT-02
    // The bytes after the stream must not be counted as used by the codec.
    let stream = compress(&text(2000), 5, 22);
    let mut data = stream.clone();
    data.extend(vec![7u8; 1000]);
    let rec = Recording::new(&data, usize::MAX);
    let stats = rec.stats.clone();
    let mut reader = codec_reader(rec);
    let (_, kind) = pump(reader.as_mut());
    assert_eq!(kind, Some(ErrorKind::Corrupt));
    assert_eq!(stats.consumed.get(), stream.len());
}

// -- bit flips and mutation fuzz -----------------------------------------------------------------

fn is_allowed(kind: Option<ErrorKind>) -> bool {
    matches!(
        kind,
        None | Some(ErrorKind::Corrupt) | Some(ErrorKind::MemoryLimit) | Some(ErrorKind::OutputLimit)
    )
}

/// Check one damaged stream: never a panic (`internal`), only ok/corrupt/memory_limit/output_limit,
/// and when ok the same bytes as the reference decoder.
fn check_damaged(data: &[u8], read_size: usize, chunk: usize, context: &str) -> Option<ErrorKind> {
    let d = decoder(Limits::new(4 * MIB).disable_ratio_limit(), 24);
    let o = run_with(&d, data, &["br"], read_size, chunk);
    assert!(is_allowed(o.kind), "{context}: {:?}", o.kind);
    if o.kind.is_none() {
        let reference = reference_decode(data, 8 * MIB as usize);
        assert!(
            reference.as_deref() == Some(&o.bytes[..]),
            "{context}: spillgate accepted a stream the reference decodes differently ({} bytes, reference {:?})",
            o.bytes.len(),
            reference.as_ref().map(Vec::len)
        );
    }
    o.kind
}

#[test]
fn every_single_bit_flip_is_ok_or_a_typed_error() {
    // Covers: SG-I-05 SG-R-CDC-08
    let streams = [
        ("text q5", compress(&text(300), 5, 22)),
        ("noise q1", compress(&noise(1, 200), 1, 16)),
        ("zeros q11", compress(&vec![0u8; 20_000], 11, 24)),
        ("mixed q9 w10", compress(&mixed(1500), 9, 10)),
        (
            "literals q5 w14",
            compress(&[noise(5, 150), text(300), noise(6, 150)].concat(), 5, 14),
        ),
        ("stored", brotli_stored(&noise(3, 150), 17).unwrap()),
        ("zeros meta-block", brotli_zeros(MIB, 20).unwrap()),
    ];
    for (name, stream) in &streams {
        let mut oks = 0;
        for position in 0..stream.len() {
            for bit in 0..8 {
                let mut damaged = stream.clone();
                damaged[position] ^= 1 << bit;
                if check_damaged(&damaged, 4096, usize::MAX, &format!("{name} {position}:{bit}")).is_none() {
                    oks += 1;
                }
            }
        }
        // the undamaged stream is accepted (sanity for the harness)
        assert_eq!(check_damaged(stream, 4096, usize::MAX, name), None);
        eprintln!(
            "{name}: {} bytes, {oks} of {} flips still decode",
            stream.len(),
            stream.len() * 8
        );
    }
}

fn mutate(rng: &mut Rng, base: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    let mut data = base.to_vec();
    for _ in 0..1 + rng.below(6) {
        if data.is_empty() {
            data.push(rng.next() as u8);
            continue;
        }
        let at = rng.below(data.len() as u64) as usize;
        match rng.below(9) {
            0 | 1 => data[at] ^= 1 << rng.below(8),
            2 => data[at] = rng.next() as u8,
            3 => data.insert(at, rng.next() as u8),
            4 => {
                data.remove(at);
            }
            5 => data.truncate(at),
            6 => {
                let end = (at + 1 + rng.below(32) as usize).min(data.len());
                let piece = data[at..end].to_vec();
                data.splice(at..at, piece);
            }
            7 => data[0] = rng.next() as u8,
            _ => {
                let other = &others[rng.below(others.len() as u64) as usize];
                let from = rng.below(other.len() as u64) as usize;
                let len = rng.below(64) as usize;
                let piece: Vec<u8> = other.iter().skip(from).take(len).copied().collect();
                data.splice(at.., piece);
            }
        }
    }
    data
}

#[test]
fn seeded_mutation_fuzz() {
    // Covers: SG-I-05 SG-R-CDC-08 SG-R-CDC-04
    let rounds: u64 = std::env::var("SPILLGATE_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let bases: Vec<Vec<u8>> = vec![
        compress(&text(2000), 5, 22),
        compress(&mixed(6000), 9, 12),
        compress(&noise(8, 700), 0, 16),
        compress(&vec![0u8; 50_000], 6, 24),
        compress(&mixed(3000), 11, 20),
        brotli_stored(&noise(4, 300), 24).unwrap(),
        brotli_zeros(8 * MIB, 22).unwrap(),
        compress(&[], 5, 22),
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut seen = std::collections::BTreeMap::new();
    for round in 0..rounds {
        let base = &bases[rng.below(bases.len() as u64) as usize];
        let data = mutate(&mut rng, base, &bases);
        let read_size = [1usize, 7, 4096, 1 << 20][rng.below(4) as usize];
        let chunk = [1usize, 3, 100, usize::MAX][rng.below(4) as usize];
        // a 1-byte read size over a megabyte-sized output would take long: use it on short outputs only
        let read_size = if read_size == 1 && base.len() > 2000 {
            7
        } else {
            read_size
        };
        let kind = check_damaged(&data, read_size, chunk, &format!("round {round}"));
        *seen.entry(format!("{kind:?}")).or_insert(0u32) += 1;
    }
    eprintln!("fuzz outcomes over {rounds} rounds: {seen:?}");
}

#[test]
fn decoding_is_deterministic_across_read_sizes_and_chunks_for_damaged_streams() {
    // Covers: SG-I-09 SG-R-RDR-01
    // Same verdict and same delivered prefix for every way of reading.
    let base = compress(&mixed(4000), 5, 22);
    let mut rng = Rng(77);
    for round in 0..150 {
        let mut data = base.clone();
        let at = rng.below(data.len() as u64) as usize;
        data[at] ^= 1 << rng.below(8);
        let d = decoder(Limits::new(4 * MIB).disable_ratio_limit(), 24);
        let reference = run_with(&d, &data, &["br"], 4096, usize::MAX);
        for (read_size, chunk) in [(1usize, 1usize), (7, 3), (1 << 20, 100), (4096, 4096)] {
            let o = run_with(&d, &data, &["br"], read_size, chunk);
            // the verdict is the same; the bytes delivered before it may differ in length (a failing
            // step delivers nothing) but are prefixes of each other
            assert_eq!(o.kind, reference.kind, "round {round} read {read_size} chunk {chunk}");
            let (short, long) = if o.bytes.len() < reference.bytes.len() {
                (&o.bytes, &reference.bytes)
            } else {
                (&reference.bytes, &o.bytes)
            };
            assert!(long.starts_with(short), "round {round} read {read_size} chunk {chunk}");
        }
    }
}

// -- CPU: many tiny meta-blocks that each declare 256 + 256 Huffman trees ----------------------------

mod hostile_trees {
    use spillgate_test_support::BitWriter;

    fn var_len_255(w: &mut BitWriter) {
        w.bits(1, 1);
        w.bits(7, 3);
        w.bits(127, 7);
    }

    /// A simple prefix code with one symbol.
    fn simple1(w: &mut BitWriter, alphabet: u32, symbol: u64) {
        let bits = 32 - (alphabet - 1).leading_zeros();
        w.bits(1, 2);
        w.bits(0, 2);
        w.bits(symbol, bits);
    }

    /// A compressed meta-block of about 700 bytes: MLEN = 1, 256 literal and 256 distance trees.
    fn meta_block(w: &mut BitWriter) {
        w.bits(0, 1); // ISLAST = 0
        w.bits(0, 2); // MNIBBLES = 4
        w.bits(0, 16); // MLEN - 1 = 0
        w.bits(0, 1); // not uncompressed
        w.bits(0, 3); // one block type of each kind
        w.bits(0, 2); // NPOSTFIX
        w.bits(0, 4); // NDIRECT
        w.bits(0, 2); // context mode
        var_len_255(w); // NTREESL = 256
        w.bits(0, 1); // no RLE in the context map
        simple1(w, 256, 0);
        w.bits(0, 1); // no inverse move-to-front
        var_len_255(w); // NTREESD = 256
        w.bits(0, 1);
        simple1(w, 256, 0);
        w.bits(0, 1);
        for _ in 0..256 {
            simple1(w, 256, 65); // the literal trees
        }
        simple1(w, 704, 8); // the insert-and-copy tree
        for _ in 0..256 {
            simple1(w, 64, 0); // the distance trees
        }
    }

    /// A stream of `n` such meta-blocks (one output byte each) and an empty last block.
    pub fn stream(n: usize) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(0, 1); // window 16
        for _ in 0..n {
            meta_block(&mut w);
        }
        w.bits(3, 2); // ISLAST, ISLASTEMPTY
        w.finish()
    }
}

#[test]
fn many_tiny_meta_blocks_with_256_trees_each_cost_bounded_cpu() {
    // Covers: SG-R-MEM-03 SG-R-CDC-01
    // 4000 meta-blocks of 716 bytes each (2.86 MB in, 4000 bytes out), each declaring 256 literal and
    // 256 distance trees. The ratio limit never fires on this (the output is smaller than the input),
    // so the decoder's own cost per input byte is the only protection besides MaxInput and a deadline.
    // Measured 2026-11-12, release: unpatched brotli-decompressor 5.0.0 2.5-3.0 s (about 900-1030 ns
    // per input byte, 0.74 ms of table allocation and zeroing per meta-block), vendored and patched
    // decoder (tables kept between meta-blocks, src/vendored/brotli_decompressor/VENDORED.md) 0.28 s
    // (about 100 ns per input byte). The dev profile gives the same (0.34 s; the package is optimized in
    // dev). The bound is 1.5 s on the best of three runs: 5 times the measured time as margin for slow or
    // loaded CI machines, and below the old decoder's time even on this machine.
    const BLOCKS: usize = 4000;
    let stream = hostile_trees::stream(BLOCKS);
    let d = decoder(loose(), 24);
    let mut best = std::time::Duration::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        let o = run_with(&d, &stream, &["br"], 65_536, usize::MAX);
        best = best.min(start.elapsed());
        assert_eq!((o.kind, o.bytes.len()), (None, BLOCKS));
    }
    eprintln!(
        "brotli hostile meta-blocks: {BLOCKS} blocks, {} input bytes, best of 3 {:.3} s ({:.0} ns/input byte)",
        stream.len(),
        best.as_secs_f64(),
        best.as_nanos() as f64 / stream.len() as f64
    );
    assert!(best.as_millis() < 1500, "took {best:?}");
}
