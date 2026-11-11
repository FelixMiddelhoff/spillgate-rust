//! Regressions for defects found by the independent review of the Rust port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Read;

use spillgate::{Decoder, Error, ErrorKind, Limits};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn decode_with_read_size(data: &[u8], encoding: &str, size: usize) -> (Vec<u8>, Option<ErrorKind>) {
    let decoder = Decoder::new(Limits::new(1 << 20).disable_ratio_limit()).unwrap();
    let mut reader = decoder.reader(data, &[encoding]).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; size];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Error::from_io(&e).map(Error::kind)),
        }
    }
}

#[test]
fn sg_r_cdc_03_repeat_previous_after_a_zero_run_repeats_zero() {
    // Covers: SG-R-CDC-03 (code 16 after code 17 or 18 repeats a length of 0, as zlib does)
    let stream = hex("05c0250100000000a0ad04f9ff0004");
    for size in [1, 2, 7, 4096] {
        assert_eq!(
            decode_with_read_size(&stream, "deflate", size),
            (b"a".to_vec(), None),
            "read size {size}"
        );
    }
}

#[test]
fn sg_r_rdr_01_bytes_before_a_deflate_error_do_not_depend_on_the_read_size() {
    // Covers: SG-R-RDR-01 SG-I-09
    let stream = hex("4b4c4c043e00");
    let reference = decode_with_read_size(&stream, "deflate", 4096);
    assert_eq!(reference.1, Some(ErrorKind::Corrupt));
    for size in [1, 2, 3, 5, 64] {
        assert_eq!(
            decode_with_read_size(&stream, "deflate", size),
            reference,
            "read size {size}"
        );
    }
}

#[cfg(feature = "zstd")]
#[test]
fn sg_r_cdc_05_a_huffman_tree_without_two_weight_one_symbols_is_corrupt() {
    // Covers: SG-R-CDC-05 (libzstd refuses it; weights [2,2,3])
    let frame = hex("28b52ffd00003d000042c00081226300");
    let decoder = Decoder::builder(Limits::new(1 << 20).disable_ratio_limit())
        .codec(
            "zstd",
            spillgate::zstd::codec(spillgate::zstd::ZstdOptions::default()).unwrap(),
        )
        .build()
        .unwrap();
    let error = decoder.decode_all(&frame[..], &["zstd"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Corrupt);
}
