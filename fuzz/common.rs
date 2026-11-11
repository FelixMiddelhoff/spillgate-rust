//! Shared by all fuzz targets: build the decoder and check the two promises that must hold for
//! any input: no panic, and never more output than `MAX_OUTPUT`.
#![allow(dead_code)]

use std::io::Read;

use spillgate::{br, zstd, Decoder, Error, ErrorKind, Limits};

/// The output bound of every target (per layer, so also of the chain).
pub const MAX_OUTPUT: u64 = 1 << 20;

pub fn decoder() -> Decoder {
    let built = Decoder::builder(Limits::new(MAX_OUTPUT).max_layers(4))
        .codec(
            "br",
            br::codec(br::BrotliOptions { max_window_bits: 18 }).expect("valid br options"),
        )
        .codec(
            "zstd",
            zstd::codec(zstd::ZstdOptions {
                max_window_bytes: 1 << 20,
            })
            .expect("valid zstd options"),
        )
        .build();
    built.expect("valid limits")
}

/// Decode `data` under `content_encoding` and assert the promises. Refusals are fine; a panic, an
/// untyped error, an `internal` error (a bug by definition) or too much output is not.
pub fn run(content_encoding: &[&str], data: &[u8]) {
    let decoder = decoder();
    let Ok(mut reader) = decoder.reader(data, content_encoding) else {
        return;
    };
    let mut total = 0u64;
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                total += n as u64;
                assert!(total <= MAX_OUTPUT, "delivered {total} bytes, more than {MAX_OUTPUT}");
            }
            Err(e) => {
                let typed = Error::from_io(&e).expect("a reader over a slice fails with a spillgate error");
                assert_ne!(typed.kind(), ErrorKind::Internal, "internal error: {typed}");
                return;
            }
        }
    }
}
