//! Memory behavior that can be checked without a counting allocator (the allocator test lives in
//! `tools/alloc-check`, because this crate forbids unsafe code): a bomb of 4 GiB under a 100 MiB
//! budget completes with a typed error, and nothing is sized from `max_output` or declared sizes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::Read;

use common::*;
use spillgate::{decode_all, Decoder, ErrorKind, Limits};

#[test]
fn sg_r_mem_02_a_4_gib_bomb_ends_at_the_budget() {
    // Covers: SG-R-MEM-02 SG-I-08 SG-I-01 SG-R-LAY-01
    let max = 100u64 << 20;
    let d = Decoder::builder(Limits::new(max).disable_ratio_limit())
        .codec("zeros", Zeros(4 << 30))
        .build()
        .unwrap();
    let mut r = d.reader(&b""[..], &["zeros"]).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    let kind = loop {
        match r.read(&mut buf) {
            Ok(0) => panic!("the bomb must not look like a clean end"),
            Ok(n) => {
                assert!(n <= 64 * 1024);
                total += n as u64;
            }
            Err(e) => break kind_of(&e),
        }
    };
    assert_eq!((total, kind), (max, ErrorKind::OutputLimit));
}

#[test]
fn sg_r_mem_02_decode_all_never_preallocates_from_max_output() {
    // Covers: SG-R-MEM-02 SG-R-CDC-07 SG-R-MEM-01 SG-I-04
    // A preallocation of 2^45 or 2^63-1 bytes would abort the process or panic with a capacity
    // overflow; growing with the output does neither.
    for max in [1u64 << 40, 1 << 45, 1 << 62, (1 << 63) - 1] {
        let out = decode_all(&b"small body"[..], &[], Limits::new(max)).unwrap();
        assert_eq!(out, b"small body");
        let d = Decoder::builder(Limits::new(max).disable_ratio_limit())
            .codec("pass", Pass)
            .build()
            .unwrap();
        assert_eq!(
            d.decode_all(&b"small body"[..], &["pass, pass"]).unwrap(),
            b"small body"
        );
        let framed = stored(b"tiny", 2);
        let d = decoder(Limits::new(max));
        assert_eq!(d.decode_all(&framed[..], &["stored"]).unwrap(), b"tiny");
    }
}

#[test]
fn sg_r_mem_02_decode_all_of_a_failing_stream_returns_no_data() {
    // Covers: SG-R-MEM-02 SG-R-API-02
    let d = Decoder::builder(Limits::new(10 << 20).disable_ratio_limit())
        .codec("zeros", Zeros(1 << 40))
        .build()
        .unwrap();
    let e = d.decode_all(&b""[..], &["zeros"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::OutputLimit);
    assert_eq!(e.limit(), 10 << 20);
}

#[test]
fn sg_r_mem_01_declared_sizes_do_not_size_allocations() {
    // Covers: SG-R-MEM-01 SG-R-CDC-07 SG-I-04
    // The stored format declares chunk lengths up to 65535; a header that declares a chunk and
    // then ends costs nothing and is corrupt.
    let d = decoder(Limits::new(1 << 40));
    for declared in [1u16, 1000, 65535] {
        let mut input = declared.to_le_bytes().to_vec();
        input.extend_from_slice(b"abc");
        let o = run(&d, &input, &["stored"], 4096);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt));
        assert!(b"abc".starts_with(&o.bytes));
    }
}

#[test]
fn sg_r_mem_03_a_chain_of_sixteen_layers_can_be_built_and_dropped_many_times() {
    // Covers: SG-R-MEM-03 SG-I-10
    let d = decoder(Limits::new(1 << 20).max_layers(16).disable_ratio_limit());
    let header = vec!["pass"; 16].join(", ");
    for _ in 0..2000 {
        let mut r = d.reader(&b"abc"[..], &[&header]).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abc");
    }
}
