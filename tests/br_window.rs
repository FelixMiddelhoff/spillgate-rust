//! The window of a brotli stream: the table of RFC 7932 section 9.1, the exact cap, the large-window
//! marker, refusal before anything is decoded.
#![cfg(feature = "br")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod br_support;

use br_support::*;
use spillgate::br;
use spillgate::{ErrorKind, Limits};
use spillgate_test_support::{brotli_large_window_prefix, brotli_stored, brotli_zeros};

/// RFC 7932 section 9.1 read bit by bit (least significant bit first), independent of `br::window_bits`.
fn rfc_window(first: u8) -> (u32, bool) {
    let bit = |i: u32| u32::from((first >> i) & 1);
    if bit(0) == 0 {
        return (16, false);
    }
    let n = bit(1) | bit(2) << 1 | bit(3) << 2;
    if n != 0 {
        return (17 + n, false);
    }
    let m = bit(4) | bit(5) << 1 | bit(6) << 2;
    match m {
        0 => (17, false),
        1 => (0, true),
        m => (8 + m, false),
    }
}

#[test]
fn window_bits_table_for_all_256_first_bytes() {
    // Covers: SG-R-CDC-04
    for b in 0..=255u8 {
        assert_eq!(br::window_bits(b), rfc_window(b), "first byte {b:#010b}");
    }
    // hand-written anchors of the RFC table
    assert_eq!(br::window_bits(0b0), (16, false));
    for n in 1..8u8 {
        assert_eq!(br::window_bits(1 | n << 1), (17 + u32::from(n), false));
    }
    assert_eq!(br::window_bits(0b0000_0001), (17, false));
    assert_eq!(br::window_bits(0b0001_0001), (0, true));
    for m in 2..8u8 {
        assert_eq!(br::window_bits(1 | m << 4), (8 + u32::from(m), false));
    }
    // bit 7 belongs to the next field and never changes the window
    for b in 0..128u8 {
        assert_eq!(br::window_bits(b), br::window_bits(b | 0x80));
    }
    // the large-window marker is exactly the low seven bits 0010001
    let large: Vec<u8> = (0..=255u8).filter(|&b| br::window_bits(b).1).collect();
    assert_eq!(large, vec![0x11, 0x91]);
}

#[test]
fn the_encoder_writes_the_window_the_table_reads() {
    // Covers: SG-R-CDC-04
    let payload = mixed(1 << 20);
    for lgwin in 10..=24 {
        let stream = compress(&payload, 5, lgwin);
        assert_eq!(br::window_bits(stream[0]), (lgwin as u32, false), "lgwin {lgwin}");
    }
}

#[test]
fn large_window_marker_is_memory_limit_whatever_the_cap() {
    // Covers: SG-R-CDC-04
    for cap in 10..=24 {
        for first in [0x11u8, 0x91] {
            let mut stream = brotli_large_window_prefix();
            stream[0] = first;
            stream.extend(vec![0u8; 50]);
            let o = run_cap(&stream, cap);
            assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::MemoryLimit), 0), "cap {cap}");
        }
    }
}

#[test]
fn a_real_large_window_stream_is_refused() {
    // Covers: SG-R-CDC-04 SG-R-CDC-07
    // 16 MiB of zeros with lgwin 30 and the large-window option, a few hundred bytes.
    let zeros = vec![0u8; 16 << 20];
    let stream = compress_large_window(&zeros, 5, 30);
    assert!(stream.len() < 2000, "the stream is {} bytes", stream.len());
    assert_eq!(
        stream[0] & 0x7f,
        0x11,
        "not a large-window stream: first byte {:#x}",
        stream[0]
    );
    for cap in [10, 17, 24] {
        let src = Src::new(&stream, usize::MAX);
        let counters = src.counters.clone();
        let d = decoder(loose(), cap);
        let mut reader = d.reader(src, &["br"]).unwrap();
        let o = drain(&mut reader, 65536);
        assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::MemoryLimit), 0), "cap {cap}");
        assert_eq!(counters.reads.get(), 1, "cap {cap}");
    }
}

#[test]
fn the_window_cap_is_exact_for_every_size() {
    // Covers: SG-R-CDC-04 SG-R-CDC-07
    let payload = noise(11, 300);
    for wbits in 10..=24u32 {
        let stream = brotli_stored(&payload, wbits).unwrap();
        assert_eq!(br::window_bits(stream[0]), (wbits, false));
        let o = run_cap(&stream, wbits);
        assert_eq!((o.kind, &o.bytes), (None, &payload), "window {wbits}");
        if wbits > 10 {
            let src = Src::new(&stream, usize::MAX);
            let counters = src.counters.clone();
            let d = decoder(loose(), wbits - 1);
            let mut reader = d.reader(src, &["br"]).unwrap();
            let o = drain(&mut reader, 4096);
            assert_eq!(
                (o.kind, o.bytes.len()),
                (Some(ErrorKind::MemoryLimit), 0),
                "window {wbits} cap {}",
                wbits - 1
            );
            // one source read at most, and not a byte more than the meter's buffer
            assert_eq!(counters.reads.get(), 1);
            assert!(counters.bytes.get() <= 4096);
            // the error carries the cap that was exceeded
            let mut again = d.reader(Src::new(&stream, usize::MAX), &["br"]).unwrap();
            let e = std::io::Read::read(&mut again, &mut [0u8; 8]).unwrap_err();
            assert_eq!(spillgate::Error::from_io(&e).unwrap().limit(), 1u64 << (wbits - 1));
        }
    }
}

#[test]
fn a_hostile_window_is_refused_before_anything_is_decoded() {
    // Covers: SG-R-CDC-04 SG-R-CDC-07 SG-I-04
    // 1 GiB of zeros behind a 2^24 window header, cap 16: one read, no output.
    let bomb = brotli_zeros(1 << 30, 24).unwrap();
    let src = Src::new(&bomb, usize::MAX);
    let counters = src.counters.clone();
    let d = decoder(loose(), 16);
    let mut reader = d.reader(src, &["br"]).unwrap();
    let o = drain(&mut reader, 1 << 20);
    assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::MemoryLimit), 0));
    assert_eq!(counters.reads.get(), 1);
    assert!(counters.bytes.get() <= 4096);
}

#[test]
fn every_hostile_first_byte_is_refused_by_the_first_read() {
    // Covers: SG-R-CDC-04 SG-R-CDC-07 SG-I-05
    // The tail is a valid bomb body after a fixed header; the first byte alone decides.
    let bomb = brotli_zeros(1 << 28, 24).unwrap();
    for cap in [10u32, 16, 20, 24] {
        let d = decoder(loose(), cap);
        for first in 0..=255u8 {
            let (bits, large) = br::window_bits(first);
            let mut stream = bomb.clone();
            stream[0] = first;
            let src = Src::new(&stream, usize::MAX);
            let counters = src.counters.clone();
            let mut reader = d.reader(src, &["br"]).unwrap();
            let o = drain(&mut reader, 65536);
            if large || bits > cap {
                assert_eq!(
                    (o.kind, o.bytes.len(), counters.reads.get()),
                    (Some(ErrorKind::MemoryLimit), 0, 1),
                    "cap {cap} first byte {first:#04x}"
                );
            } else {
                // decoded or refused as corrupt, but never as a window problem
                assert_ne!(
                    o.kind,
                    Some(ErrorKind::MemoryLimit),
                    "cap {cap} first byte {first:#04x}"
                );
                assert_ne!(o.kind, Some(ErrorKind::Internal), "cap {cap} first byte {first:#04x}");
            }
        }
    }
}

#[test]
fn the_default_cap_is_24_and_refuses_only_the_marker() {
    // Covers: SG-R-CDC-04
    let payload = noise(5, 100);
    let stream = brotli_stored(&payload, 24).unwrap();
    let o = run(&stream, Limits::new(1 << 20).disable_ratio_limit());
    assert_eq!((o.kind, &o.bytes), (None, &payload));
}
