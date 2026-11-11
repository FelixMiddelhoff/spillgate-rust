//! The brotli codec on valid streams: round trips with the reference encoder, read sizes, source
//! chunking, chains, the input limit, options.
#![cfg(feature = "br")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod br_support;

use std::io::Write;

use br_support::*;
use spillgate::br::{self, BrotliOptions};
use spillgate::{Decoder, ErrorKind, Limits};

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

#[test]
fn round_trip_all_qualities_and_windows() {
    // Covers: SG-R-CDC-04 SG-R-RDR-01
    let d = loose_decoder();
    for (name, payload) in payloads() {
        for quality in 0..=11 {
            for lgwin in 10..=24 {
                let stream = compress(&payload, quality, lgwin);
                let o = run_with(&d, &stream, &["br"], 4096, usize::MAX);
                assert_eq!(o.kind, None, "{name} q{quality} w{lgwin}");
                assert!(o.bytes == payload, "{name} q{quality} w{lgwin}: output differs");
            }
        }
    }
}

#[test]
fn round_trip_large_payload() {
    // Covers: SG-R-CDC-04 SG-R-RDR-01 SG-R-MEM-02
    let mut payload = mixed(900_000);
    payload.extend(noise(3, 300_000));
    payload.extend(text(200_000));
    assert!(payload.len() > (1 << 20));
    let d = loose_decoder();
    for quality in [0, 1, 5, 9, 11] {
        for lgwin in [10, 16, 22, 24] {
            let stream = compress(&payload, quality, lgwin);
            let o = run_with(&d, &stream, &["br"], 1 << 20, 4096);
            assert_eq!(o.kind, None, "q{quality} w{lgwin}");
            assert!(o.bytes == payload, "q{quality} w{lgwin}: output differs");
        }
    }
}

#[test]
fn every_window_cap_accepts_streams_it_covers() {
    // Covers: SG-R-CDC-04 SG-R-CDC-07
    let payload = mixed(30_000);
    for lgwin in 10..=24 {
        let stream = compress(&payload, 5, lgwin);
        let needed = br::window_bits(stream[0]).0;
        assert!(needed <= lgwin as u32);
        for cap in needed..=24 {
            let o = run_cap(&stream, cap);
            assert_eq!((o.kind, o.bytes == payload), (None, true), "lgwin {lgwin} cap {cap}");
        }
    }
}

#[test]
fn read_sizes_do_not_change_the_result() {
    // Covers: SG-R-RDR-01 SG-I-09
    let payload = mixed(120_000);
    let stream = compress(&payload, 4, 20);
    let d = loose_decoder();
    for size in [1usize, 7, 4096, 1 << 20] {
        let payload = if size == 1 { &payload[..20_000] } else { &payload[..] };
        let stream = if size == 1 {
            compress(payload, 4, 20)
        } else {
            stream.clone()
        };
        let o = run_with(&d, &stream, &["br"], size, usize::MAX);
        assert_eq!(o.kind, None, "read size {size}");
        assert!(o.bytes == payload, "read size {size}");
    }
}

#[test]
fn source_chunking_does_not_change_the_result() {
    // Covers: SG-R-RDR-01 SG-I-09
    let payload = mixed(120_000);
    let stream = compress(&payload, 4, 20);
    let d = loose_decoder();
    for chunk in [1usize, 3, 100, 4096, usize::MAX] {
        let o = run_with(&d, &stream, &["br"], 4096, chunk);
        assert_eq!(o.kind, None, "chunk {chunk}");
        assert!(o.bytes == payload, "chunk {chunk}");
    }
}

#[test]
fn chains_with_gzip() {
    // Covers: SG-R-LAY-01 SG-R-HDR-12
    let payload = mixed(40_000);
    let d = loose_decoder();
    // "br, gzip": br was applied first, gzip last, so the body is gzip(br(x)).
    let body = gzip(&compress(&payload, 5, 22));
    let o = run_with(&d, &body, &["br, gzip"], 4096, usize::MAX);
    assert_eq!((o.kind, o.bytes == payload), (None, true));
    // "gzip, br": the body is br(gzip(x)).
    let body = compress(&gzip(&payload), 5, 22);
    let o = run_with(&d, &body, &["gzip, br"], 4096, 7);
    assert_eq!((o.kind, o.bytes == payload), (None, true));
    // two header fields mean the same as one
    let o = run_with(&d, &body, &["gzip", "br"], 4096, usize::MAX);
    assert_eq!((o.kind, o.bytes == payload), (None, true));
}

#[test]
fn chain_errors_name_the_brotli_layer() {
    // Covers: SG-R-LAY-01 SG-R-CDC-04
    let d = decoder(loose(), 16);
    let big_window = compress(&mixed(5000), 5, 22);
    // body = br(gzip(x)): br is the first layer decoded
    let got = kind_and_layer(&mut d.reader(&big_window[..], &["gzip, br"]).unwrap());
    assert_eq!(got, (ErrorKind::MemoryLimit, 1));
    // body = gzip(br(x)): br is the second layer
    let inner = gzip(&big_window);
    let got = kind_and_layer(&mut d.reader(&inner[..], &["br, gzip"]).unwrap());
    assert_eq!(got, (ErrorKind::MemoryLimit, 2));
}

fn kind_and_layer(reader: &mut spillgate::SpillgateReader<'_>) -> (ErrorKind, usize) {
    use std::io::Read;
    let e = reader.read_to_end(&mut Vec::new()).unwrap_err();
    let e = spillgate::Error::from_io(&e).unwrap();
    (e.kind(), e.layer())
}

#[test]
fn max_input_boundary() {
    // Covers: SG-R-INP-01 SG-R-INP-02
    let stream = compress(&mixed(30_000), 5, 22);
    let n = stream.len() as u64;
    let ok = run(&stream, Limits::new(1 << 30).disable_ratio_limit().max_input(n));
    assert_eq!(ok.kind, None);
    let over = run(&stream, Limits::new(1 << 30).disable_ratio_limit().max_input(n - 1));
    assert_eq!(over.kind, Some(ErrorKind::InputLimit));
    // the same with a source that trickles one byte at a time
    let d = decoder(Limits::new(1 << 30).disable_ratio_limit().max_input(n), 24);
    assert_eq!(run_with(&d, &stream, &["br"], 4096, 1).kind, None);
    // a stream with one trailing byte and max_input = stream length: the probe byte is the limit,
    // not a clean end
    let mut plus = stream.clone();
    plus.push(0);
    let o = run(&plus, Limits::new(1 << 30).disable_ratio_limit().max_input(n));
    assert_eq!(o.kind, Some(ErrorKind::InputLimit));
}

#[test]
fn option_validation() {
    // Covers: SG-R-CDC-09
    for bad in (0..10).chain(25..64).chain([u32::MAX]) {
        let e = br::codec(BrotliOptions { max_window_bits: bad }).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidOption, "{bad}");
    }
    for good in 10..=24 {
        assert!(br::codec(BrotliOptions { max_window_bits: good }).is_ok(), "{good}");
    }
    assert_eq!(BrotliOptions::default().max_window_bits, 24);
    assert_eq!(br::DEFAULT_MAX_WINDOW_BITS, 24);
    assert_eq!(br::MIN_WINDOW_BITS, 10);
}

#[test]
fn a_decoder_without_the_codec_refuses_br() {
    // Covers: SG-R-HDR-08 SG-I-06
    let d = Decoder::new(loose()).unwrap();
    let e = d.reader(&compress(b"x", 5, 22)[..], &["br"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedEncoding);
}

#[test]
fn the_codec_is_reusable_across_streams() {
    // Covers: SG-R-RDR-06
    let d = loose_decoder();
    for i in 0..20u64 {
        let payload = mixed(1000 + 777 * i as usize);
        let o = run_with(&d, &compress(&payload, 5, 18), &["br"], 4096, usize::MAX);
        assert_eq!((o.kind, o.bytes == payload), (None, true), "stream {i}");
    }
}
