//! Misbehaving codecs, panic containment and randomized invariant checks (SG-I-01, SG-I-02,
//! SG-I-05, SG-R-CDC-08, SG-R-RDR-01).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::{BufRead, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use spillgate::{Codec, CodecReader, Decoder, Error, ErrorKind, Limits};

fn kinds(reader: &mut impl Read) -> (Vec<u8>, ErrorKind) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => panic!("expected an error, got the end"),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, kind_of(&e)),
        }
    }
}

#[test]
fn sg_r_cdc_08_a_panicking_codec_is_internal_and_sticky() {
    // Covers: SG-R-CDC-08 SG-I-05 SG-I-03
    for after in [0usize, 1, 100, 70_000] {
        let d = Decoder::builder(loose())
            .codec("panic", Panicker(after))
            .build()
            .unwrap();
        for header in [vec!["panic"], vec!["pass", "panic"]] {
            let d2 = Decoder::builder(loose())
                .codec("panic", Panicker(after))
                .codec("pass", Pass)
                .build()
                .unwrap();
            let d = if header.len() == 2 { &d2 } else { &d };
            let mut r = d.reader(&b"x"[..], &header).unwrap();
            let (out, kind) = kinds(&mut r);
            assert_eq!(kind, ErrorKind::Internal, "{header:?} after {after}");
            assert_eq!(out.len(), after.min(out.len()));
            assert!(out.len() <= after);
            for _ in 0..5 {
                assert_eq!(kind_of(&r.read(&mut [0u8; 8]).unwrap_err()), ErrorKind::Internal);
            }
        }
    }
}

#[test]
fn sg_r_cdc_08_a_panic_in_the_second_layer_names_layer_two() {
    // Covers: SG-R-CDC-08 SG-R-API-05
    let d = Decoder::builder(loose())
        .codec("panic", Panicker(5))
        .codec("pass", Pass)
        .build()
        .unwrap();
    let mut r = d.reader(&b"hello"[..], &["panic, pass"]).unwrap();
    let e = r.read_to_end(&mut Vec::new()).unwrap_err();
    let typed = Error::from_io(&e).unwrap();
    assert_eq!((typed.kind(), typed.layer()), (ErrorKind::Internal, 2));
    assert!(!typed.message().is_empty() && typed.message().len() < 100);
}

#[test]
fn sg_r_cdc_08_a_codec_that_panics_while_it_is_constructed_is_contained() {
    // Covers: SG-R-CDC-08 SG-I-05
    let d = Decoder::builder(loose())
        .codec("boom", PanicOnNew)
        .codec("pass", Pass)
        .build()
        .unwrap();
    let e = d.reader(&b""[..], &["boom"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Internal);
    assert_eq!(e.layer(), 1);
    let e = d.reader(&b""[..], &["boom, pass"]).unwrap_err();
    assert_eq!((e.kind(), e.layer()), (ErrorKind::Internal, 2));
    let e = d.reader(&b""[..], &["pass, boom"]).unwrap_err();
    assert_eq!((e.kind(), e.layer()), (ErrorKind::Internal, 1));
    // the decoder is fine afterwards
    assert_eq!(run(&d, b"ok", &["pass"], 8).bytes, b"ok");
    assert_eq!(
        d.decode_all(&b""[..], &["boom"]).unwrap_err().kind(),
        ErrorKind::Internal
    );
}

#[test]
fn sg_r_cdc_08_a_codec_returning_more_than_requested_is_internal_and_leaks_nothing() {
    // Covers: SG-R-CDC-08 SG-R-LAY-02 SG-I-01
    for extra in [1usize, 5, 1 << 20] {
        let d = Decoder::builder(Limits::new(1000).disable_ratio_limit())
            .codec("over", OverReport(extra))
            .build()
            .unwrap();
        for size in [1usize, 16, 4096, 1 << 20] {
            let mut r = d.reader(&b""[..], &["over"]).unwrap();
            let mut buf = vec![0u8; size];
            let e = r.read(&mut buf).unwrap_err();
            assert_eq!(kind_of(&e), ErrorKind::Internal, "extra {extra} size {size}");
            assert_eq!(kind_of(&r.read(&mut buf).unwrap_err()), ErrorKind::Internal);
        }
        // in the probe step as well: after exactly the budget a codec that over-reports is internal
        let d = Decoder::builder(Limits::new(1).disable_ratio_limit())
            .codec("over", OverReport(extra))
            .build()
            .unwrap();
        let o = run(&d, b"", &["over"], 1);
        assert_eq!(o.kind, Some(ErrorKind::Internal));
    }
}

#[test]
fn sg_r_cdc_08_codec_errors_keep_their_kind_and_get_the_layer() {
    // Covers: SG-R-CDC-08 SG-R-CDC-04 SG-R-API-05
    for kind in [
        ErrorKind::Corrupt,
        ErrorKind::MemoryLimit,
        ErrorKind::Internal,
        ErrorKind::UnsupportedEncoding,
    ] {
        let d = Decoder::builder(loose())
            .codec("f", Fails(kind))
            .codec("pass", Pass)
            .build()
            .unwrap();
        let e = d.decode_all(&b"x"[..], &["f"]).unwrap_err();
        assert_eq!((e.kind(), e.layer()), (kind, 1));
        let e = d.decode_all(&b"x"[..], &["f, pass"]).unwrap_err();
        assert_eq!((e.kind(), e.layer()), (kind, 2));
    }
}

static CALLS_AFTER_END: AtomicUsize = AtomicUsize::new(0);

struct Ends(usize);
struct EndsReader {
    left: usize,
    ended: bool,
}
impl CodecReader for EndsReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.ended {
            CALLS_AFTER_END.fetch_add(1, Ordering::SeqCst);
        }
        let n = buf.len().min(self.left);
        buf[..n].fill(4);
        self.left -= n;
        if n == 0 {
            self.ended = true;
        }
        Ok(n)
    }
}
impl Codec for Ends {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(EndsReader {
            left: self.0,
            ended: false,
        })
    }
}

#[test]
fn a_codec_is_not_called_again_after_its_end_or_failure() {
    // Covers: SG-R-LAY-05 SG-I-03 SG-R-LAY-09
    let d = Decoder::builder(loose()).codec("ends", Ends(10)).build().unwrap();
    let mut r = d.reader(&b""[..], &["ends"]).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    for _ in 0..10 {
        assert_eq!(r.read(&mut [0u8; 4]).unwrap(), 0);
    }
    assert_eq!(CALLS_AFTER_END.load(Ordering::SeqCst), 0);
    assert_eq!(out, [4u8; 10]);
}

#[test]
fn a_codec_that_ends_early_is_a_clean_end() {
    // Covers: SG-R-CDC-06
    // The limiter cannot know what the format wanted: a codec that returns Ok(0) ends the stream.
    // (Codecs themselves must report truncation as corrupt; see the Stored codec tests.)
    let d = Decoder::builder(loose()).codec("ends", Ends(0)).build().unwrap();
    let o = run(&d, b"", &["ends"], 8);
    assert_eq!((o.kind, o.bytes.len()), (None, 0));
}

#[test]
fn sg_r_cdc_01_a_codec_gets_no_private_path_around_the_limits() {
    // Covers: SG-R-CDC-01 SG-R-CDC-09 SG-I-01
    // output budget, ratio, input cap and layer count all apply to an extension codec
    let d = Decoder::builder(Limits::new(100).disable_ratio_limit())
        .codec("z", Zeros(u64::MAX))
        .build()
        .unwrap();
    assert_eq!(run(&d, b"", &["z"], 33).kind, Some(ErrorKind::OutputLimit));
    let d = Decoder::builder(Limits::new(1 << 30))
        .codec("z", Zeros(u64::MAX))
        .build()
        .unwrap();
    assert_eq!(run(&d, b"", &["z"], 33).kind, Some(ErrorKind::RatioLimit));
    let d = Decoder::builder(Limits::new(1 << 30).max_input(3).disable_ratio_limit())
        .codec("p", Pass)
        .build()
        .unwrap();
    assert_eq!(run(&d, b"abcd", &["p"], 33).kind, Some(ErrorKind::InputLimit));
    let d = Decoder::builder(Limits::new(1 << 30).max_layers(1))
        .codec("p", Pass)
        .build()
        .unwrap();
    assert_eq!(run(&d, b"", &["p, p"], 33).kind, Some(ErrorKind::LayerLimit));
}

#[test]
fn a_hostile_panic_payload_is_contained() {
    // Covers: SG-R-CDC-08 SG-I-05
    struct Hostile;
    struct HostilePayload;
    impl Drop for HostilePayload {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                panic!("the payload panics when it is dropped");
            }
        }
    }
    struct HostileReader;
    impl CodecReader for HostileReader {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Error> {
            std::panic::panic_any(HostilePayload);
        }
    }
    impl Codec for Hostile {
        fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
            Box::new(HostileReader)
        }
    }
    let d = Decoder::builder(loose()).codec("hostile", Hostile).build().unwrap();
    let mut r = d.reader(&b""[..], &["hostile"]).unwrap();
    let e = r.read(&mut [0u8; 8]).unwrap_err();
    assert_eq!(kind_of(&e), ErrorKind::Internal);
}

// -- randomized invariants ---------------------------------------------------------------------------------

#[test]
fn random_bytes_never_break_an_invariant() {
    // Covers: SG-I-01 SG-I-02 SG-I-03 SG-I-05 SG-R-CDC-08 SG-R-RDR-01 SG-I-09
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let headers: [&[&str]; 6] = [
        &["stored"],
        &["stored, pass"],
        &["bytes, stored"],
        &["expand10"],
        &["pass, up, dbl"],
        &[],
    ];
    for round in 0..400 {
        let len = rng.below(600) as usize;
        let mut input = rng.bytes(len);
        if round % 3 == 0 {
            // make it look like a stored stream so deeper states are reached
            let (n, chunk) = (rng.below(300) as usize, 1 + rng.below(80) as usize);
            let mut framed = stored(&rng.bytes(n), chunk);
            if round % 6 == 0 && !framed.is_empty() {
                let at = rng.below(framed.len() as u64) as usize;
                framed[at] ^= 1 << rng.below(8);
            }
            input = framed;
        }
        let header = headers[rng.below(headers.len() as u64) as usize];
        let max_output = 1 + rng.below(500);
        let d = decoder(
            Limits::new(max_output)
                .ratio_grace(rng.below(300))
                .max_ratio(1 + rng.below(30)),
        );
        let reference = run(&d, &input, header, 4096);
        assert!(reference.bytes.len() as u64 <= max_output, "round {round}");
        for size in [1usize, 3, 17, 1 << 20] {
            let o = run(&d, &input, header, size);
            assert!(o.bytes.len() as u64 <= max_output);
            assert_eq!(o.kind, reference.kind, "round {round} header {header:?} size {size}");
            if o.kind != Some(ErrorKind::RatioLimit) {
                assert_eq!(o.bytes, reference.bytes, "round {round} header {header:?} size {size}");
            } else {
                // a prefix of the same stream
                let n = o.bytes.len().min(reference.bytes.len());
                assert_eq!(o.bytes[..n], reference.bytes[..n]);
            }
        }
    }
}

#[test]
fn random_chains_never_deliver_more_than_the_budget() {
    // Covers: SG-I-01 SG-R-LAY-01 SG-R-LAY-02 SG-I-08 SG-R-RDR-01
    let names = ["pass", "up", "dbl", "expand10", "shrink10", "bytes"];
    let mut rng = Rng(0xdead_beef_1234_5678);
    for round in 0..300 {
        let depth = 1 + rng.below(6) as usize;
        let header: Vec<&str> = (0..depth)
            .map(|_| names[rng.below(names.len() as u64) as usize])
            .collect();
        let header = header.join(", ");
        let n = rng.below(400) as usize;
        let input = rng.bytes(n);
        let max_output = 1 + rng.below(3000);
        let d = decoder(Limits::new(max_output).max_layers(8).disable_ratio_limit());
        let reference = run(&d, &input, &[&header], 4096);
        assert!(reference.bytes.len() as u64 <= max_output, "round {round} {header}");
        for size in [1usize, 5, 1 << 20] {
            let o = run(&d, &input, &[&header], size);
            assert_eq!(o, reference, "round {round} {header} size {size}");
        }
        // chunked source
        let step = 1 + rng.below(50) as usize;
        let mut r = d.reader(Chunked::new(input.clone(), step), &[&header]).unwrap();
        assert_eq!(drain(&mut r, 7), reference, "round {round} {header} chunked");
    }
}

#[test]
fn arbitrary_header_text_is_a_typed_error_or_a_decoder() {
    // Covers: SG-I-05 SG-I-06 SG-R-HDR-13
    let d = decoder(Limits::new(100).disable_ratio_limit());
    let mut rng = Rng(42);
    let alphabet: Vec<char> =
        "abcdefghijklmnopqrstuvwxyzABCXYZ0123456789,;= \t\r\n\0\"'\\.-_/\u{e9}\u{200b}\u{1b}\u{ff47}\u{fb01}"
            .chars()
            .collect();
    for _ in 0..3000 {
        let len = rng.below(60) as usize;
        let text: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize])
            .collect();
        let second: String = (0..rng.below(10))
            .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize])
            .collect();
        match d.reader(&b"data"[..], &[&text, &second]) {
            Ok(mut r) => {
                let _ = drain(&mut r, 16);
            }
            Err(e) => {
                assert!(
                    matches!(
                        e.kind(),
                        ErrorKind::MalformedEncoding | ErrorKind::UnsupportedEncoding | ErrorKind::LayerLimit
                    ),
                    "{:?}",
                    e.kind()
                );
                let shown = e.to_string();
                assert!(!shown.chars().any(char::is_control), "{shown:?}");
                assert!(shown.len() < 400);
            }
        }
    }
}

#[test]
fn damaged_stored_streams_are_ok_or_corrupt_never_something_else() {
    // Covers: SG-I-05 SG-R-CDC-06 SG-R-LAY-07
    let payload: Vec<u8> = (0..400u32).map(|i| (i * 7) as u8).collect();
    let good = stored(&payload, 64);
    let d = decoder(Limits::new(1 << 20).disable_ratio_limit());
    for at in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[at] ^= 1 << bit;
            let o = run(&d, &bad, &["stored"], 64);
            match o.kind {
                None => {} // a flipped payload bit is still a valid stored stream
                Some(ErrorKind::Corrupt) => {}
                other => panic!("flip {at}:{bit} gave {other:?}"),
            }
        }
    }
}
