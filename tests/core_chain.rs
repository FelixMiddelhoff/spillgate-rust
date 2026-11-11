//! Layer chaining: depth, identity layers, per-layer budgets, intermediate limits, error layers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::Read;

use common::*;
use spillgate::{Decoder, Error, ErrorKind, Limits};

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 253) as u8).collect()
}

fn failure(reader: &mut impl Read) -> (Vec<u8>, Error) {
    let mut out = Vec::new();
    let e = reader.read_to_end(&mut out).unwrap_err();
    (out, Error::from_io(&e).expect("a spillgate error").clone_for_test())
}

trait CloneForTest {
    fn clone_for_test(&self) -> Error;
}
impl CloneForTest for Error {
    fn clone_for_test(&self) -> Error {
        Error::new(self.kind(), self.message())
            .with_limit(self.limit())
            .with_layer(self.layer())
    }
}

#[test]
fn sg_r_hdr_11_chain_depth_up_to_the_limit() {
    // Covers: SG-R-HDR-11 SG-R-HDR-06 SG-I-07 SG-R-LAY-01
    let payload = data(10_000);
    for depth in 1..=16usize {
        let d = decoder(Limits::new(1 << 20).max_layers(16).disable_ratio_limit());
        let header = vec!["pass"; depth].join(", ");
        for size in [1usize, 4096, 1 << 20] {
            let o = run(&d, &payload, &[&header], size);
            assert_eq!((o.kind, &o.bytes), (None, &payload), "depth {depth} size {size}");
        }
        // one layer fewer than the depth in max_layers is refused at construction
        if depth >= 2 {
            let strict = decoder(Limits::new(1 << 20).max_layers(depth as u32 - 1).disable_ratio_limit());
            assert_eq!(
                strict.reader(&payload[..], &[&header]).unwrap_err().kind(),
                ErrorKind::LayerLimit
            );
        }
    }
}

#[test]
fn sg_r_hdr_10_identity_layers_are_no_ops() {
    // Covers: SG-R-HDR-10 SG-R-CDC-10
    let d = decoder(Limits::new(1 << 20).max_layers(2).disable_ratio_limit());
    let payload = data(3000);
    let framed = stored(&payload, 500);
    for header in [
        "stored",
        "identity, stored",
        "stored, identity",
        "identity, stored, identity, identity",
        "identity,identity,identity,identity,identity,identity,stored",
    ] {
        let o = run(&d, &framed, &[header], 100);
        assert_eq!((o.kind, &o.bytes), (None, &payload), "{header}");
    }
    // identity is bounded and counted like everything else
    let d = decoder(Limits::new(10).disable_ratio_limit());
    let o = run(&d, &data(11), &["identity, identity"], 4);
    assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::OutputLimit), 10));
}

#[test]
fn sg_r_hdr_12_layers_apply_in_reverse_order_of_the_header() {
    // Covers: SG-R-HDR-12
    let d = decoder(loose());
    let input = [1u8, 2, 200];
    // up then dbl (listed "dbl, up"): ((x + 1) * 2) mod 256
    let o = run(&d, &input, &["dbl, up"], 8);
    assert_eq!(o.bytes, [4, 6, 146]);
    let o = run(&d, &input, &["up, dbl"], 8);
    assert_eq!(o.bytes, [3, 5, 145]);
    let o = run(&d, &input, &["up, up, up, dbl"], 8);
    assert_eq!(o.bytes, [5, 7, 147]);
    // stored framing is layer 1 (listed last), the transform is layer 2
    let o = run(&d, &stored(&input, 2), &["up, stored"], 8);
    assert_eq!(o.bytes, [2, 3, 201]);
}

#[test]
fn sg_r_lay_01_every_layer_has_its_own_budget() {
    // Covers: SG-R-LAY-01 SG-R-LAY-02 SG-I-01
    // layer 1 = expand10 turns 100 bytes into 1000, layer 2 = shrink10 turns them into 100.
    let source = data(100);
    let header = ["shrink10, expand10"];
    let ok = decoder(Limits::new(1000).disable_ratio_limit());
    let o = run(&ok, &source, &header, 64);
    assert_eq!((o.kind, o.bytes.len()), (None, 100));
    // the final output (100) is far below max_output (999), but layer 1 would produce 1000
    let tight = decoder(Limits::new(999).disable_ratio_limit());
    for size in [1usize, 64, 1 << 20] {
        let mut r = tight.reader(&source[..], &header).unwrap();
        let mut out = Vec::new();
        let mut buf = vec![0u8; size];
        let error = loop {
            match r.read(&mut buf) {
                Ok(0) => panic!("a limit hit must not look like the end"),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => break Error::from_io(&e).unwrap().clone_for_test(),
            }
        };
        assert_eq!(
            (error.kind(), error.layer(), error.limit()),
            (ErrorKind::OutputLimit, 1, 999),
            "size {size}"
        );
        assert!(out.len() <= 100);
    }
    // layer 1 exactly at the limit is fine
    let exact = decoder(Limits::new(1000).disable_ratio_limit());
    assert_eq!(run(&exact, &source, &header, 7).kind, None);
}

#[test]
fn sg_r_lay_01_the_second_layer_names_itself() {
    // Covers: SG-R-LAY-01 SG-R-API-05
    // layer 1 = pass (100 bytes), layer 2 = expand10 (1000 bytes) against max_output 500
    let d = decoder(Limits::new(500).disable_ratio_limit());
    let source = data(100);
    let mut r = d.reader(&source[..], &["expand10, pass"]).unwrap();
    let (out, e) = failure(&mut r);
    assert_eq!((e.kind(), e.layer(), e.limit()), (ErrorKind::OutputLimit, 2, 500));
    assert_eq!(out.len(), 500);
}

#[test]
fn sg_r_lay_01_an_intermediate_layer_exceeding_the_limit_is_output_limit_even_if_later_layers_shrink() {
    // Covers: SG-R-LAY-01 SG-R-LAY-07
    let d = decoder(Limits::new(50).disable_ratio_limit());
    let o = run(&d, &data(100), &["shrink1000, pass"], 16);
    // layer 1 = pass: 100 bytes > 50, layer 2 would shrink to 1 byte
    assert_eq!(o.kind, Some(ErrorKind::OutputLimit));
    let d = decoder(Limits::new(100).disable_ratio_limit());
    let o = run(&d, &data(100), &["shrink1000, pass"], 16);
    assert_eq!((o.kind, o.bytes.len()), (None, 1));
}

#[test]
fn errors_of_a_lower_layer_pass_through_with_their_layer() {
    // Covers: SG-R-LAY-01 SG-R-LAY-05 SG-R-API-05
    let d = decoder(loose());
    // layer 1 (stored) hits garbage
    let mut r = d.reader(&[5u8, 0, 1][..], &["pass, up, stored"]).unwrap();
    let (_, e) = failure(&mut r);
    assert_eq!((e.kind(), e.layer()), (ErrorKind::Corrupt, 1));
    // layer 2 (stored) gets garbage from a healthy layer 1
    let mut r = d.reader(&[5u8, 0, 1, 2, 3, 4, 5][..], &["stored, pass"]).unwrap();
    let (_, e) = failure(&mut r);
    assert_eq!((e.kind(), e.layer()), (ErrorKind::Corrupt, 2));
    // layer 3 of 3
    let mut r = d.reader(&[0u8; 7][..], &["stored, up, pass"]).unwrap();
    let (_, e) = failure(&mut r);
    assert_eq!((e.kind(), e.layer()), (ErrorKind::Corrupt, 3));
    // sticky after passing through the layers above
    for _ in 0..3 {
        let e = r.read(&mut [0u8; 8]).unwrap_err();
        let typed = Error::from_io(&e).unwrap();
        assert_eq!((typed.kind(), typed.layer()), (ErrorKind::Corrupt, 3));
    }
}

#[test]
fn a_source_error_names_layer_one_in_a_long_chain() {
    // Covers: SG-R-RDR-05 SG-R-API-05
    let d = decoder(loose());
    let source = FailAfter::new(vec![1u8; 10], || std::io::Error::other("down"));
    let mut r = d.reader(source, &["pass, up, dbl, pass"]).unwrap();
    let (out, e) = failure(&mut r);
    assert_eq!((e.kind(), e.layer()), (ErrorKind::SourceError, 1));
    assert_eq!(out.len(), 10);
}

#[test]
fn an_input_limit_in_a_long_chain_names_layer_one() {
    // Covers: SG-R-INP-01 SG-R-API-05
    let d = decoder(Limits::new(1 << 20).max_input(100).disable_ratio_limit());
    let mut r = d.reader(&[1u8; 1000][..], &["pass, up, dbl"]).unwrap();
    let (out, e) = failure(&mut r);
    assert_eq!((e.kind(), e.layer(), e.limit()), (ErrorKind::InputLimit, 1, 100));
    assert_eq!(out.len(), 100);
}

#[test]
fn chains_are_independent_of_read_sizes_and_source_chunking() {
    // Covers: SG-R-RDR-01 SG-I-09
    let payload = data(20_000);
    let framed = stored(&payload, 1500);
    let framed_twice = stored(&framed, 999);
    let d = decoder(loose());
    let reference = run(&d, &framed_twice, &["stored, stored"], 1 << 20);
    assert_eq!((reference.kind, &reference.bytes), (None, &payload));
    for size in [1usize, 2, 5, 4095, 4096, 4097, 65536] {
        assert_eq!(
            run(&d, &framed_twice, &["stored, stored"], size),
            reference,
            "size {size}"
        );
        for step in [1usize, 3, 4096] {
            let mut r = d
                .reader(Chunked::new(framed_twice.clone(), step), &["stored, stored"])
                .unwrap();
            assert_eq!(drain(&mut r, size), reference, "size {size} step {step}");
        }
    }
}

#[test]
fn a_long_chain_of_shrinking_and_expanding_layers() {
    // Covers: SG-R-LAY-01 SG-R-RAT-01 SG-I-01
    // 100 -> x10 -> /10 -> x10 -> /10 : every layer stays within 1000
    let d = decoder(Limits::new(1000).disable_ratio_limit().max_layers(4));
    let o = run(&d, &data(100), &["shrink10, expand10, shrink10, expand10"], 33);
    assert_eq!((o.kind, o.bytes.len()), (None, 100));
    // with default ratio 1000 and a small grace, 10x layers are fine
    let d = decoder(Limits::new(1000).ratio_grace(0));
    let o = run(&d, &data(100), &["shrink10, expand10, shrink10, expand10"], 33);
    assert_eq!((o.kind, o.bytes.len()), (None, 100));
}

#[test]
fn a_hostile_chain_of_expanding_layers_stops_at_the_first_budget() {
    // Covers: SG-R-LAY-01 SG-I-01 SG-I-08
    let d = decoder(Limits::new(1_000_000).disable_ratio_limit().max_layers(16));
    let header = ["expand1000"; 8].join(", ");
    let mut r = d.reader(&[1u8; 16][..], &[&header]).unwrap();
    let (out, e) = failure(&mut r);
    assert_eq!(e.kind(), ErrorKind::OutputLimit);
    assert!(out.len() <= 1_000_000);
    // the failing layer is the last one that was asked for more than its budget; layer 1 produced
    // only 16000 bytes, so a later layer is blamed
    assert!(e.layer() >= 2, "layer {}", e.layer());
}

#[test]
fn nested_decoding_of_a_spillgate_reader_as_a_source() {
    // Covers: SG-R-RDR-05 SG-R-API-01
    // The output of one reader is a valid source for another; its typed error passes through.
    let d = decoder(loose());
    let framed = stored(&data(5000), 100);
    let inner = d.reader(&framed[..], &["stored"]).unwrap();
    let outer = d.reader(inner, &["up"]).unwrap();
    let o = {
        let mut outer = outer;
        drain(&mut outer, 777)
    };
    assert_eq!(o.kind, None);
    assert_eq!(o.bytes.len(), 5000);
    let bad = d.reader(&[9u8, 0][..], &["stored"]).unwrap();
    let mut outer = d.reader(bad, &["up"]).unwrap();
    let o = drain(&mut outer, 777);
    assert_eq!(o.kind, Some(ErrorKind::Corrupt));
}

#[test]
fn decoders_with_different_limits_do_not_share_state() {
    // Covers: SG-R-LIM-09 SG-R-CDC-09
    let small = decoder(Limits::new(10).disable_ratio_limit());
    let big = decoder(Limits::new(100).disable_ratio_limit());
    assert_eq!(run(&small, &[0u8; 50], &["pass"], 8).kind, Some(ErrorKind::OutputLimit));
    assert_eq!(run(&big, &[0u8; 50], &["pass"], 8).kind, None);
    let _: &Decoder = &small;
}
