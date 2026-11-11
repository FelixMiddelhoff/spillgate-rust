//! Limits (SPEC section 3), decoder construction and the header through the public API
//! (SPEC section 4). The header grammar tables themselves are unit tests in `src/header.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::cell::Cell;
use std::io::Read;
use std::rc::Rc;

use common::*;
use spillgate::{decode_all, Decoder, EffectiveLimits, Error, ErrorKind, Limits};

const INT64: u64 = (1 << 63) - 1;

fn bad(limits: Limits) {
    let e = EffectiveLimits::from_limits(&limits).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidLimits, "{e}");
    assert_eq!(Decoder::new(limits).unwrap_err().kind(), ErrorKind::InvalidLimits);
}

fn good(limits: Limits) -> EffectiveLimits {
    EffectiveLimits::from_limits(&limits).unwrap()
}

// -- limits --------------------------------------------------------------------------------------

#[test]
fn sg_r_lim_01_max_output_is_required_and_positive() {
    // Covers: SG-R-LIM-01 SG-R-API-01
    bad(Limits::new(0));
    bad(Limits::new(INT64 + 1));
    bad(Limits::new(u64::MAX));
    bad(Limits::new(1 << 63));
    assert_eq!(
        Decoder::new(Limits::new(0)).unwrap_err().kind(),
        ErrorKind::InvalidLimits
    );
}

#[test]
fn sg_r_lim_02_max_output_up_to_2_pow_63_minus_1() {
    // Covers: SG-R-LIM-01 SG-R-LIM-02 SG-R-LIM-07
    for v in [1, 2, 1 << 20, u64::from(u32::MAX), 1 << 53, 1 << 62, INT64 - 1, INT64] {
        assert_eq!(good(Limits::new(v)).max_output, v);
        Decoder::new(Limits::new(v)).unwrap();
    }
}

#[test]
fn sg_r_lim_03_max_layers_range() {
    // Covers: SG-R-LIM-03 SG-R-LIM-07
    for v in [0, 17, 100, u32::MAX] {
        bad(Limits::new(1).max_layers(v));
    }
    for v in [1, 2, 5, 15, 16] {
        assert_eq!(good(Limits::new(1).max_layers(v)).max_layers, v);
    }
    assert_eq!(good(Limits::new(1)).max_layers, 5);
}

#[test]
fn sg_r_lim_04_no_numeric_max_ratio_disables_the_check() {
    // Covers: SG-R-LIM-04 SG-R-LIM-07
    for v in [0, 1 << 31, (1 << 31) + 1, u64::MAX] {
        bad(Limits::new(1).max_ratio(v));
    }
    assert_eq!(good(Limits::new(1).max_ratio(1)).max_ratio, 1);
    assert_eq!(good(Limits::new(1).max_ratio((1 << 31) - 1)).max_ratio, (1 << 31) - 1);
    assert_eq!(good(Limits::new(1)).max_ratio, 1000);
}

#[test]
fn sg_r_lim_04_the_opt_out_is_distinct_and_cannot_be_combined() {
    // Covers: SG-R-LIM-04 SG-R-RAT-04
    assert_eq!(good(Limits::new(1).disable_ratio_limit()).max_ratio, 0);
    bad(Limits::new(1).max_ratio(10).disable_ratio_limit());
    bad(Limits::new(1).disable_ratio_limit().max_ratio(10));
    // a contradicting value is invalid even if the value itself is invalid
    bad(Limits::new(1).max_ratio(0).disable_ratio_limit());
}

#[test]
fn sg_r_lim_05_ratio_grace_may_be_zero_never_above_the_cap() {
    // Covers: SG-R-LIM-05
    assert_eq!(good(Limits::new(1).ratio_grace(0)).ratio_grace, 0);
    assert_eq!(good(Limits::new(1)).ratio_grace, 65536);
    assert_eq!(good(Limits::new(1).ratio_grace(INT64)).ratio_grace, INT64);
    bad(Limits::new(1).ratio_grace(INT64 + 1));
    bad(Limits::new(1).ratio_grace(u64::MAX));
    let e = good(Limits::new(10).max_ratio(2).ratio_grace(0));
    assert!(e.ratio_exceeded(3, 1));
    assert!(!e.ratio_exceeded(2, 1));
}

#[test]
fn sg_r_lim_06_max_input_zero_does_not_mean_unlimited() {
    // Covers: SG-R-LIM-06
    bad(Limits::new(1).max_input(0));
    bad(Limits::new(1).max_input(INT64 + 1));
    assert_eq!(good(Limits::new(1)).max_input, 0);
    assert_eq!(good(Limits::new(1).max_input(7)).max_input, 7);
    assert_eq!(good(Limits::new(1).max_input(INT64)).max_input, INT64);
}

#[test]
fn sg_r_lim_08_validated_at_construction_before_any_read() {
    // Covers: SG-R-LIM-08 SG-R-API-03
    let reads = Rc::new(Cell::new(0));
    let source = FailAfter::new(Vec::new(), || std::io::Error::other("must not be read"));
    let counter = source.calls.clone();
    let e = decode_all(source, &[], Limits::new(0)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidLimits);
    assert_eq!(counter.get(), 0);
    let e = decode_all(Endless(0, Rc::new(Cell::new(0))), &[], Limits::new(5).max_layers(0)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidLimits);
    reads.set(1);
}

#[test]
fn sg_r_lim_09_limits_are_captured_by_value() {
    // Covers: SG-R-LIM-09
    let mut limits = Limits::new(100);
    let decoder = Decoder::new(limits.clone()).unwrap();
    limits = Limits::new(0); // later changes to the caller's value do not matter
    let _ = limits;
    let out = decoder.decode_all(&[7u8; 100][..], &[]).unwrap();
    assert_eq!(out.len(), 100);
    let e = decoder.decode_all(&[7u8; 101][..], &[]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::OutputLimit);
}

#[test]
fn sg_r_rat_01_the_ratio_boundary_is_exact_and_cannot_overflow() {
    // Covers: SG-R-RAT-01
    let e = good(Limits::new(INT64).max_ratio(10).ratio_grace(100));
    assert!(!e.ratio_exceeded(100, 1)); // inside the grace
    assert!(!e.ratio_exceeded(10 * 50, 50)); // exactly at the ratio
    assert!(e.ratio_exceeded(10 * 50 + 1, 50)); // one byte over
    assert!(e.ratio_exceeded(101, 0)); // consumed counts as at least 1
    assert!(!e.ratio_exceeded(101, 11)); // 101 <= 110
    assert!(!e.ratio_exceeded(u64::MAX, u64::MAX)); // the product does not wrap
    assert!(e.ratio_exceeded(u64::MAX, 1));
    let off = good(Limits::new(INT64).disable_ratio_limit());
    assert!(!off.ratio_exceeded(u64::MAX, 0));
}

// -- decoder construction and codec registration ---------------------------------------------------

#[test]
fn sg_r_cdc_09_codec_names_are_checked() {
    // Covers: SG-R-CDC-09
    let build = |name: &str| Decoder::builder(Limits::new(10)).codec(name, Pass).build();
    for name in ["identity", "gzip", "deflate", "x-gzip"] {
        let e = build(name).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidOption, "{name}");
        assert_eq!(e.kind().as_str(), "invalid_option");
        assert_eq!(e.kind().http_status(), 500);
    }
    // not lower case, not a token
    for name in [
        "Gzip",
        "BR",
        "",
        " br",
        "br;q=1",
        "a b",
        "-x",
        ".x",
        "\u{e9}",
        &"a".repeat(33),
        "x\n",
        "x,y",
    ] {
        assert_eq!(build(name).unwrap_err().kind(), ErrorKind::InvalidOption, "{name:?}");
    }
    for name in ["br", "zstd", "x", "a.b_c-d", "9", &"a".repeat(32)] {
        build(name).unwrap();
    }
    // twice
    let e = Decoder::builder(Limits::new(10))
        .codec("br", Pass)
        .codec("br", Pass)
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidOption);
    // errors do not hide invalid limits and the other way around
    assert_eq!(
        Decoder::builder(Limits::new(0))
            .codec("gzip", Pass)
            .build()
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidLimits
    );
    // the message never carries more than 32 bytes of the name
    let e = build(&format!("{}\n", "A".repeat(500))).unwrap_err();
    assert!(e.to_string().matches('A').count() <= 32);
    assert!(!e.to_string().contains('\n'));
}

#[test]
fn sg_r_cdc_09_registered_codecs_are_per_decoder_not_global() {
    // Covers: SG-R-CDC-09
    let with = decoder(loose());
    let without = Decoder::new(loose()).unwrap();
    assert_eq!(run(&with, b"abc", &["pass"], 16).bytes, b"abc");
    assert_eq!(
        run(&without, b"abc", &["pass"], 16).kind,
        Some(ErrorKind::UnsupportedEncoding)
    );
    assert_eq!(
        run(&without, b"abc", &["br"], 16).kind,
        Some(ErrorKind::UnsupportedEncoding)
    );
}

#[test]
fn sg_r_cdc_09_builtin_and_optional_names() {
    // Covers: SG-R-CDC-09 SG-R-HDR-08
    let plain = Decoder::new(loose()).unwrap();
    for header in ["gzip", "deflate", "x-gzip", "identity", "GZIP"] {
        plain.reader(&b""[..], &[header]).unwrap();
    }
    // the optional codecs are only available when registered
    for header in [
        "br",
        "zstd",
        "compress",
        "dcb",
        "dcz",
        "aes128gcm",
        "snappy",
        "deflate64",
    ] {
        assert_eq!(
            plain.reader(&b""[..], &[header]).unwrap_err().kind(),
            ErrorKind::UnsupportedEncoding,
            "{header}"
        );
    }
}

#[test]
fn sg_r_api_01_there_is_no_decoder_without_limits() {
    // Covers: SG-R-API-01
    // The API takes Limits everywhere; the only way to "no limit" is an invalid value.
    assert!(Decoder::new(Limits::new(0)).is_err());
    assert!(decode_all(&b""[..], &[], Limits::new(0)).is_err());
    let out = decode_all(&b"abc"[..], &[], Limits::new(3)).unwrap();
    assert_eq!(out, b"abc");
}

// -- header through the public API -----------------------------------------------------------------

#[test]
fn sg_r_hdr_12_decoding_order_is_the_reverse_of_the_list() {
    // Covers: SG-R-HDR-12 SG-R-HDR-01
    let d = decoder(loose());
    let input = [10u8, 20, 30];
    // last token = layer 1: "up, dbl" applies dbl first: (x*2)+1
    assert_eq!(run(&d, &input, &["up, dbl"], 16).bytes, [21, 41, 61]);
    // "dbl, up" applies up first: (x+1)*2
    assert_eq!(run(&d, &input, &["dbl, up"], 16).bytes, [22, 42, 62]);
    // several field values are the same list
    assert_eq!(run(&d, &input, &["up", "dbl"], 16).bytes, [21, 41, 61]);
}

#[test]
fn sg_r_hdr_14_equivalent_presentations_decode_the_same() {
    // Covers: SG-R-HDR-14 SG-R-HDR-03 SG-R-HDR-05
    let d = decoder(loose());
    let input = [1u8, 2, 3];
    let reference = run(&d, &input, &["up,dbl"], 16);
    assert_eq!(reference.bytes, [3, 5, 7]);
    let presentations: Vec<Vec<&str>> = vec![
        vec!["UP, DBL"],
        vec!["up", "dbl"],
        vec![" up ", "\tdbl\t"],
        vec![",,up,,dbl,,"],
        vec!["", "up", " ", "dbl", ""],
        vec!["identity", "up", "identity", "dbl", "identity"],
        vec!["Up", "dBl"],
    ];
    for p in presentations {
        assert_eq!(run(&d, &input, &p, 16), reference, "{p:?}");
    }
}

#[test]
fn sg_r_hdr_03_the_empty_header_is_the_identity_chain() {
    // Covers: SG-R-HDR-03 SG-R-HDR-10 SG-R-CDC-10
    let d = decoder(loose());
    for p in [
        vec![],
        vec![""],
        vec![" "],
        vec![","],
        vec!["identity"],
        vec!["identity, identity"],
        vec![", ,\t,"],
    ] {
        let o = run(&d, b"payload", &p, 3);
        assert_eq!(o.bytes, b"payload", "{p:?}");
        assert_eq!(o.kind, None, "{p:?}");
    }
}

#[test]
fn sg_r_hdr_04_malformed_and_unsupported_are_construction_errors() {
    // Covers: SG-R-HDR-04 SG-R-HDR-08 SG-R-API-03 SG-I-06
    let d = decoder(loose());
    for (header, kind) in [
        ("gzip;q=1", ErrorKind::MalformedEncoding),
        ("\"gzip\"", ErrorKind::MalformedEncoding),
        ("pass, ba d", ErrorKind::MalformedEncoding),
        ("pass\n", ErrorKind::MalformedEncoding),
        ("compress", ErrorKind::UnsupportedEncoding),
        ("pass, compress", ErrorKind::UnsupportedEncoding),
        ("compress, pass", ErrorKind::UnsupportedEncoding),
    ] {
        let source = FailAfter::new(Vec::new(), || std::io::Error::other("must not be read"));
        let calls = source.calls.clone();
        let e = d.reader(source, &[header]).unwrap_err();
        assert_eq!(e.kind(), kind, "{header:?}");
        assert_eq!(calls.get(), 0, "{header:?}: the source must stay untouched");
    }
}

#[test]
fn sg_r_hdr_09_support_is_checked_for_the_whole_list_before_any_read() {
    // Covers: SG-R-HDR-09 SG-R-API-03 SG-I-06
    let d = decoder(loose());
    let source = Chunked::new(b"data".to_vec(), 1);
    let counters = source.counters.clone();
    let e = d.reader(source, &["pass", "compress"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedEncoding);
    assert_eq!(counters.calls.get(), 0);
    // and decode_all returns no data
    let e = d.decode_all(&b"data"[..], &["pass, compress"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedEncoding);
}

#[test]
fn sg_r_hdr_02_sg_r_hdr_06_sg_r_hdr_11_header_limits_through_the_decoder() {
    // Covers: SG-R-HDR-02 SG-R-HDR-06 SG-R-HDR-11 SG-I-07
    let d = decoder(Limits::new(1 << 20).max_layers(16).disable_ratio_limit());
    let sixteen = vec!["pass"; 16].join(", ");
    assert_eq!(run(&d, b"x", &[&sixteen], 4).bytes, b"x");
    let seventeen = vec!["pass"; 17].join(", ");
    let e = d.reader(&b"x"[..], &[&seventeen]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::LayerLimit);
    assert_eq!(e.limit(), 16);
    assert_eq!(
        d.reader(&b"x"[..], &[&vec!["identity"; 17].join(",")])
            .unwrap_err()
            .kind(),
        ErrorKind::LayerLimit
    );
    // 17 elements but only unsupported: the count comes first
    assert_eq!(
        d.reader(&b"x"[..], &[&vec!["compress"; 17].join(",")])
            .unwrap_err()
            .kind(),
        ErrorKind::LayerLimit
    );
    // too long
    let long = format!("pass{}", " ".repeat(1021));
    assert_eq!(
        d.reader(&b"x"[..], &[&long]).unwrap_err().kind(),
        ErrorKind::MalformedEncoding
    );
    let ok = format!("pass{}", " ".repeat(1020));
    d.reader(&b"x"[..], &[&ok]).unwrap();
    // default MaxLayers is 5, identity does not count
    let d5 = decoder(Limits::new(1 << 20).disable_ratio_limit());
    d5.reader(&b"x"[..], &["pass,pass,pass,pass,pass,identity,identity"])
        .unwrap();
    let e = d5.reader(&b"x"[..], &["pass,pass,pass,pass,pass,pass"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::LayerLimit);
    assert_eq!(e.limit(), 5);
    // the layer limit is reported at construction, before any read
    let d1 = decoder(Limits::new(1 << 20).max_layers(1).disable_ratio_limit());
    assert_eq!(
        d1.reader(&b"x"[..], &["pass, pass"]).unwrap_err().kind(),
        ErrorKind::LayerLimit
    );
}

#[test]
fn sg_r_hdr_13_errors_carry_bounded_quoted_text() {
    // Covers: SG-R-HDR-13 SG-I-05
    let d = decoder(loose());
    let evil = format!("evil\nSEVERITY=ALERT;{}\u{1b}]0;title\u{7}", "x".repeat(500));
    let e = d.reader(&b""[..], &[&evil]).unwrap_err();
    let shown = e.to_string();
    assert!(!shown.chars().any(char::is_control), "{shown:?}");
    assert!(shown.matches('x').count() <= 32);
    assert!(shown.len() < 300);
    let e = d.reader(&b""[..], &["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedEncoding);
    assert!(e.message().contains('"'));
    assert_eq!(spillgate::quote_untrusted("é\n".as_bytes()), "\"\\xc3\\xa9\\x0a\"");
    assert_eq!(spillgate::quote_untrusted(b"q\"b\\"), "\"q\\\"b\\\\\"");
    assert!(spillgate::quote_untrusted(&[b'z'; 100]).matches('z').count() <= 32);
}

#[test]
fn error_kinds_have_names_and_statuses() {
    // Covers: SG-R-API-05
    let all = [
        (ErrorKind::InvalidLimits, "invalid_limits", 500),
        (ErrorKind::InvalidOption, "invalid_option", 500),
        (ErrorKind::OutputLimit, "output_limit", 413),
        (ErrorKind::RatioLimit, "ratio_limit", 413),
        (ErrorKind::LayerLimit, "layer_limit", 413),
        (ErrorKind::InputLimit, "input_limit", 413),
        (ErrorKind::MemoryLimit, "memory_limit", 503),
        (ErrorKind::UnsupportedEncoding, "unsupported_encoding", 415),
        (ErrorKind::MalformedEncoding, "malformed_encoding", 400),
        (ErrorKind::Corrupt, "corrupt", 400),
        (ErrorKind::Internal, "internal", 500),
        (ErrorKind::Canceled, "canceled", 503),
        (ErrorKind::SourceError, "source_error", 400),
    ];
    for (kind, name, status) in all {
        assert_eq!(kind.as_str(), name);
        assert_eq!(kind.to_string(), name);
        assert_eq!(kind.http_status(), status, "{name}");
    }
    let e = Error::new(ErrorKind::OutputLimit, "m")
        .with_limit(5)
        .with_layer(2)
        .with_layer(3);
    assert_eq!((e.kind(), e.limit(), e.layer()), (ErrorKind::OutputLimit, 5, 2));
    assert!(e.to_string().contains("layer 2") && e.to_string().contains("limit 5"));
}

#[test]
fn a_decoder_is_send_sync_and_shareable() {
    // Covers: SG-R-RDR-07 SG-R-CDC-09
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Decoder>();
    assert_send_sync::<Limits>();
    assert_send_sync::<Error>();
    assert_send_sync::<EffectiveLimits>();
    let d = std::sync::Arc::new(decoder(loose()));
    let threads: Vec<_> = (0..8u8)
        .map(|i| {
            let d = d.clone();
            std::thread::spawn(move || {
                let data = vec![i; 10_000];
                let mut r = d.reader(&data[..], &["pass, up"]).unwrap();
                let mut out = Vec::new();
                r.read_to_end(&mut out).unwrap();
                assert_eq!(out, vec![i + 1; 10_000]);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}
