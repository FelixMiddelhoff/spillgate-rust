//! Cooperative cancellation (SG-R-API-04).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::Read;

use common::*;
use spillgate::{CancelToken, Decoder, ErrorKind, Limits};

fn zero_decoder() -> Decoder {
    Decoder::builder(Limits::new(1 << 40).disable_ratio_limit())
        .codec("zeros", Zeros(1 << 40))
        .build()
        .unwrap()
}

#[test]
fn sg_r_api_04_cancel_before_the_first_read_is_canceled_and_sticky() {
    // Covers: SG-R-API-04 SG-I-03
    let token = CancelToken::new();
    let mut reader = zero_decoder()
        .reader_with_cancel(&b"x"[..], &["zeros"], &token)
        .unwrap();
    token.cancel();
    for _ in 0..3 {
        let error = reader.read(&mut [0u8; 16]).unwrap_err();
        assert_eq!(kind_of(&error), ErrorKind::Canceled);
    }
}

#[test]
fn sg_r_api_04_cancel_between_reads_stops_the_stream() {
    // Covers: SG-R-API-04
    let token = CancelToken::new();
    let mut reader = zero_decoder()
        .reader_with_cancel(&b"x"[..], &["zeros"], &token)
        .unwrap();
    let mut buf = vec![0u8; 100_000];
    assert!(reader.read(&mut buf).unwrap() > 0);
    token.clone().cancel();
    assert_eq!(kind_of(&reader.read(&mut buf).unwrap_err()), ErrorKind::Canceled);
    assert!(token.is_canceled());
}

#[test]
fn sg_r_api_04_cancel_from_another_thread_ends_an_endless_stream() {
    // Covers: SG-R-API-04
    let token = CancelToken::new();
    let remote = token.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        remote.cancel();
    });
    let mut reader = zero_decoder()
        .reader_with_cancel(&b"x"[..], &["zeros"], &token)
        .unwrap();
    let mut buf = vec![0u8; 65_536];
    let error = loop {
        if let Err(error) = reader.read(&mut buf) {
            break error;
        }
    };
    assert_eq!(kind_of(&error), ErrorKind::Canceled);
    handle.join().unwrap();
}

#[test]
fn sg_r_api_04_cancel_is_seen_while_a_layer_only_consumes_input() {
    // Covers: SG-R-API-04 (the check sits in the input meter, so a codec that reads a lot of
    // input without producing output is stopped too)
    let token = CancelToken::new();
    let reader_token = token.clone();
    let source = Endless(0, Default::default());
    let decoder = Decoder::builder(Limits::new(1 << 20))
        .codec("shrink", Shrink(1 << 30))
        .build()
        .unwrap();
    let mut reader = decoder.reader_with_cancel(source, &["shrink"], &reader_token).unwrap();
    token.cancel();
    assert_eq!(kind_of(&reader.read(&mut [0u8; 16]).unwrap_err()), ErrorKind::Canceled);
}

#[test]
fn a_reader_without_a_token_is_unaffected() {
    let mut reader = zero_decoder().reader(&b"x"[..], &["zeros"]).unwrap();
    assert!(reader.read(&mut [0u8; 16]).unwrap() > 0);
}
