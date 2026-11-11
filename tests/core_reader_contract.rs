//! The reader contract (SPEC section 9): read sizes, sticky terminal conditions, zero-length reads,
//! close, misbehaving sources.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::cell::Cell;
use std::error::Error as StdError;
use std::io::{self, BufRead, Read};
use std::rc::Rc;
use std::sync::Arc;

use common::*;
use spillgate::{Codec, CodecReader, Decoder, Error, ErrorKind, Limits};

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + i / 7) as u8).collect()
}

const SIZES: [usize; 7] = [1, 2, 3, 4096, 65536, 1 << 20, 1 << 24];

// -- SG-R-RDR-01: read sizes and chunking do not matter -----------------------------------------------

#[test]
fn sg_r_rdr_01_the_result_does_not_depend_on_read_sizes() {
    // Covers: SG-R-RDR-01 SG-I-09 SG-I-01
    let data = payload(20_000);
    let good = stored(&data, 777);
    let truncated = good[..good.len() - 6].to_vec();
    let mut bad_trailer = good.clone();
    let last = bad_trailer.len() - 1;
    bad_trailer[last] = b'?';
    let mut trailing = good.clone();
    trailing.push(0);
    let cases: Vec<(&str, Vec<u8>, Limits)> = vec![
        ("ok", good.clone(), Limits::new(20_000).disable_ratio_limit()),
        ("ok with room", good.clone(), Limits::new(1 << 20).disable_ratio_limit()),
        ("output_limit", good.clone(), Limits::new(19_999).disable_ratio_limit()),
        ("output_limit tiny", good.clone(), Limits::new(1).disable_ratio_limit()),
        ("truncated", truncated, Limits::new(1 << 20).disable_ratio_limit()),
        ("bad trailer", bad_trailer, Limits::new(1 << 20).disable_ratio_limit()),
        ("trailing byte", trailing, Limits::new(1 << 20).disable_ratio_limit()),
        ("input_limit", good, Limits::new(1 << 20).max_input(5_000).disable_ratio_limit()),
    ];
    for (name, input, limits) in cases {
        let d = decoder(limits);
        let reference = run(&d, &input, &["stored"], SIZES[0]);
        for size in SIZES {
            assert_eq!(run(&d, &input, &["stored"], size), reference, "{name} with read size {size}");
        }
        // mixed sizes
        let mut rng = Rng(0x1234_5678_9abc_def1);
        let mut reader = d.reader(&input[..], &["stored"]).unwrap();
        let mut bytes = Vec::new();
        let mut kind = None;
        loop {
            let mut buf = vec![0u8; rng.below(9000) as usize + 1];
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(e) => {
                    kind = Some(kind_of(&e));
                    break;
                }
            }
        }
        assert_eq!(Outcome { bytes, kind }, reference, "{name} with mixed sizes");
    }
}

#[test]
fn sg_r_rdr_01_the_expected_outcomes_of_the_table() {
    // Covers: SG-R-RDR-01 SG-R-LAY-06
    let data = payload(20_000);
    let good = stored(&data, 777);
    let d = decoder(Limits::new(1 << 20).disable_ratio_limit());
    let o = run(&d, &good, &["stored"], 4096);
    assert_eq!((o.kind, o.bytes), (None, data.clone()));
    let o = run(&d, &good[..good.len() - 6], &["stored"], 4096);
    assert_eq!(o.kind, Some(ErrorKind::Corrupt));
    // the bytes delivered before the error are a prefix of the stream
    assert!(data.starts_with(&o.bytes));
    let d = decoder(Limits::new(1000).disable_ratio_limit());
    let o = run(&d, &good, &["stored"], 4096);
    assert_eq!(o.kind, Some(ErrorKind::OutputLimit));
    assert_eq!(o.bytes, data[..1000]);
}

#[test]
fn sg_r_rdr_01_source_chunking_does_not_matter() {
    // Covers: SG-R-RDR-01 SG-I-09
    let data = payload(30_000);
    let good = stored(&data, 5000);
    let d = decoder(Limits::new(1 << 20).disable_ratio_limit());
    let cases: Vec<(Vec<&str>, Vec<u8>)> = vec![
        (vec![], data.clone()),
        (vec!["identity"], data.clone()),
        (vec!["pass, pass, bytes"], data.clone()),
        (vec!["stored"], good.clone()),
        (vec!["pass, stored"], good.clone()),
        (vec!["bytes, stored"], good.clone()),
    ];
    for (header, input) in cases {
        for step in [1, 2, 7, 4095, 4096, 4097, 1 << 20] {
            for size in [1, 100, 1 << 20] {
                let mut r = d.reader(Chunked::new(input.clone(), step), &header).unwrap();
                let o = drain(&mut r, size);
                assert_eq!(o.kind, None, "{header:?} step {step} size {size}");
                assert_eq!(o.bytes, data, "{header:?} step {step} size {size}");
            }
        }
    }
}

#[test]
fn sg_r_rdr_01_a_codec_that_reads_byte_by_byte_changes_nothing() {
    // Covers: SG-R-RDR-01 SG-R-RAT-02 SG-R-CDC-01
    let data = payload(10_000);
    let d = decoder(loose());
    let o = run(&d, &data, &["bytes"], 3);
    assert_eq!(o.bytes, data);
    let o = run(&d, &stored(&data, 100), &["bytes, stored"], 1 << 16);
    assert_eq!(o.kind, None);
    assert_eq!(o.bytes, data);
}

#[test]
fn a_single_read_returns_at_most_one_step() {
    // Covers: SG-R-MEM-02 SG-I-08
    let d = decoder(loose());
    let data = vec![5u8; 1 << 20];
    let mut r = d.reader(&data[..], &[]).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let n = r.read(&mut buf).unwrap();
    assert!(n > 0 && n <= 64 * 1024, "{n}");
    let mut r = d.reader(Endless(0, Rc::default()), &["pass"]).unwrap();
    let n = r.read(&mut buf).unwrap();
    assert!(n <= 64 * 1024);
}

// -- SG-R-RDR-02: zero-length reads -----------------------------------------------------------------

#[test]
fn sg_r_rdr_02_a_zero_length_read_changes_nothing() {
    // Covers: SG-R-RDR-02
    let d = decoder(loose());
    let source = Chunked::new(b"hello world".to_vec(), 4);
    let counters = source.counters.clone();
    let mut r = d.reader(source, &["pass"]).unwrap();
    for _ in 0..5 {
        assert_eq!(r.read(&mut []).unwrap(), 0);
    }
    assert_eq!(counters.calls.get(), 0, "an empty read must not touch the source");
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"hello world");
    // after the end an empty read is still fine
    assert_eq!(r.read(&mut []).unwrap(), 0);
    // and after an error it may return the sticky error, but never data
    let d = decoder(Limits::new(3).disable_ratio_limit());
    let mut r = d.reader(&b"abcdef"[..], &["pass"]).unwrap();
    let mut out = Vec::new();
    let e = r.read_to_end(&mut out).unwrap_err();
    assert_eq!(kind_of(&e), ErrorKind::OutputLimit);
    match r.read(&mut []) {
        Ok(0) => {}
        Err(e) => assert_eq!(kind_of(&e), ErrorKind::OutputLimit),
        Ok(n) => panic!("data {n}"),
    }
}

// -- sticky -------------------------------------------------------------------------------------------

#[test]
fn sg_r_lay_05_errors_and_a_clean_end_are_sticky() {
    // Covers: SG-R-LAY-05 SG-I-03
    let d = decoder(Limits::new(10).disable_ratio_limit());
    let mut r = d.reader(&[1u8; 50][..], &[]).unwrap();
    let mut buf = [0u8; 100];
    let mut total = 0;
    let first = loop {
        match r.read(&mut buf) {
            Ok(0) => panic!("a limit hit must not look like the end"),
            Ok(n) => total += n,
            Err(e) => break e,
        }
    };
    assert_eq!(total, 10);
    assert_eq!(kind_of(&first), ErrorKind::OutputLimit);
    for size in [0usize, 1, 100] {
        for _ in 0..20 {
            let e = r.read(&mut buf[..size]).map(|n| (n, ()));
            match e {
                Err(e) => assert_eq!(kind_of(&e), ErrorKind::OutputLimit),
                Ok((0, ())) if size == 0 => {}
                Ok(x) => panic!("{x:?}"),
            }
        }
    }
    // a clean end is sticky as well
    let d = decoder(loose());
    let mut r = d.reader(&b"abc"[..], &["pass"]).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    for _ in 0..20 {
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }
}

#[test]
fn sg_r_lay_05_every_error_kind_is_sticky_with_the_same_kind() {
    // Covers: SG-R-LAY-05 SG-I-03 SG-R-LAY-04 SG-I-02
    let limits = || Limits::new(1000).disable_ratio_limit();
    let d = Decoder::builder(limits())
        .codec("corrupt", Fails(ErrorKind::Corrupt))
        .codec("mem", Fails(ErrorKind::MemoryLimit))
        .codec("internal", Fails(ErrorKind::Internal))
        .codec("panic", Panicker(10))
        .codec("overreport", OverReport(1))
        .codec("stored", Stored)
        .build()
        .unwrap();
    let cases: Vec<(&str, Vec<u8>, ErrorKind)> = vec![
        ("corrupt", vec![1], ErrorKind::Corrupt),
        ("mem", vec![1], ErrorKind::MemoryLimit),
        ("internal", vec![1], ErrorKind::Internal),
        ("panic", vec![1], ErrorKind::Internal),
        ("overreport", vec![1], ErrorKind::Internal),
        ("stored", vec![1, 0], ErrorKind::Corrupt),
    ];
    for (header, input, expected) in cases {
        let mut r = d.reader(&input[..], &[header]).unwrap();
        let mut buf = [0u8; 64];
        let mut seen = None;
        for _ in 0..30 {
            match r.read(&mut buf) {
                Ok(0) => panic!("{header}: an error must not look like the end"),
                Ok(_) => {}
                Err(e) => {
                    let kind = kind_of(&e);
                    if let Some(prev) = seen {
                        assert_eq!(kind, prev, "{header}");
                    }
                    seen = Some(kind);
                }
            }
        }
        assert_eq!(seen, Some(expected), "{header}");
    }
}

// -- close --------------------------------------------------------------------------------------------

#[test]
fn sg_r_rdr_06_close_is_idempotent_and_reads_after_close_fail() {
    // Covers: SG-R-RDR-06 SG-I-10
    let d = decoder(loose());
    let mut r = d.reader(&b"abcdef"[..], &["pass"]).unwrap();
    let mut buf = [0u8; 2];
    assert_eq!(r.read(&mut buf).unwrap(), 2);
    r.close();
    r.close();
    r.close();
    for _ in 0..3 {
        let e = r.read(&mut buf).unwrap_err();
        assert!(e.to_string().contains("closed"), "{e}");
        assert!(Error::from_io(&e).is_none(), "a closed error is not an outcome class");
    }
    // a closed reader after its clean end, and after an error
    let mut r = d.reader(&b"ab"[..], &[]).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    r.close();
    assert!(r.read(&mut buf).is_err());
    let d = decoder(Limits::new(1).disable_ratio_limit());
    let mut r = d.reader(&b"ab"[..], &[]).unwrap();
    assert!(r.read_to_end(&mut out).is_err());
    r.close();
    r.close();
    assert!(r.read(&mut buf).is_err());
    // closing a fresh reader that was never read is fine
    let mut r = decoder(loose()).reader(&b"x"[..], &["pass"]).unwrap();
    r.close();
    r.close();
}

#[test]
fn sg_r_rdr_06_close_does_not_close_or_read_the_callers_source() {
    // Covers: SG-R-RDR-06 SG-I-10
    let d = decoder(loose());
    let mut source = Chunked::new(vec![1u8; 100_000], 100_000);
    let counters = source.counters.clone();
    {
        let mut r = d.reader(&mut source, &["pass"]).unwrap();
        let mut buf = [0u8; 10];
        assert_eq!(r.read(&mut buf).unwrap(), 10);
        let before = counters.bytes.get();
        r.close();
        r.close();
        assert_eq!(counters.bytes.get(), before, "close must not read");
    }
    // the caller can keep using the source; the reader took at most one buffer ahead
    let mut rest = Vec::new();
    source.read_to_end(&mut rest).unwrap();
    assert!(rest.len() >= 100_000 - 4096, "{}", rest.len());
}

struct DropProbe(Arc<()>);
struct DropProbeReader<'a>(Box<dyn BufRead + 'a>, #[allow(dead_code)] Arc<()>);
impl CodecReader for DropProbeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = {
            let avail = self.0.fill_buf().map_err(Error::from_input)?;
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            n
        };
        self.0.consume(n);
        Ok(n)
    }
}
impl Codec for DropProbe {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(DropProbeReader(input, self.0.clone()))
    }
}

#[test]
fn sg_i_10_nothing_outlives_close() {
    // Covers: SG-I-10 SG-R-RDR-06
    let token = Arc::new(());
    let d = Decoder::builder(loose()).codec("probe", DropProbe(token.clone())).build().unwrap();
    assert_eq!(Arc::strong_count(&token), 2); // the decoder holds the factory
    let source_token = Rc::new(());
    struct Held(Rc<()>, &'static [u8]);
    impl Read for Held {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.1.len());
            buf[..n].copy_from_slice(&self.1[..n]);
            self.1 = &self.1[n..];
            Ok(n)
        }
    }
    let mut r = d.reader(Held(source_token.clone(), b"hello"), &["probe, probe"]).unwrap();
    assert_eq!(Arc::strong_count(&token), 4); // two codec readers
    assert_eq!(Rc::strong_count(&source_token), 2);
    let mut buf = [0u8; 2];
    r.read(&mut buf).unwrap();
    r.close();
    assert_eq!(Arc::strong_count(&token), 2, "codec readers are released by close");
    assert_eq!(Rc::strong_count(&source_token), 1, "the source is released by close");
    r.close();
    // dropping a reader releases too
    let r = d.reader(Held(source_token.clone(), b"hello"), &["probe"]).unwrap();
    assert_eq!(Arc::strong_count(&token), 3);
    drop(r);
    assert_eq!(Arc::strong_count(&token), 2);
    // a failed construction releases everything
    let e = d.reader(Held(source_token.clone(), b"hello"), &["probe, nope"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnsupportedEncoding);
    assert_eq!(Rc::strong_count(&source_token), 1);
    assert_eq!(Arc::strong_count(&token), 2);
    // a terminal error does not need close to be harmless, and close afterwards is fine
    let d2 = Decoder::builder(Limits::new(1).disable_ratio_limit()).codec("probe", DropProbe(token.clone())).build().unwrap();
    let mut r = d2.reader(Held(source_token.clone(), b"hello"), &["probe"]).unwrap();
    let mut out = Vec::new();
    assert!(r.read_to_end(&mut out).is_err());
    r.close();
    assert_eq!(Rc::strong_count(&source_token), 1);
}

// -- distinct readers ------------------------------------------------------------------------------------

#[test]
fn sg_r_rdr_07_distinct_readers_are_independent() {
    // Covers: SG-R-RDR-07
    let d = decoder(Limits::new(10).disable_ratio_limit());
    let mut a = d.reader(&[1u8; 50][..], &["pass"]).unwrap();
    let mut b = d.reader(&[2u8; 5][..], &["pass"]).unwrap();
    let mut out = Vec::new();
    assert!(a.read_to_end(&mut out).is_err());
    out.clear();
    b.read_to_end(&mut out).unwrap(); // a's failure does not affect b
    assert_eq!(out, [2u8; 5]);
    let mut c = d.reader(&[3u8; 5][..], &["pass"]).unwrap();
    a.close();
    out.clear();
    c.read_to_end(&mut out).unwrap();
    assert_eq!(out, [3u8; 5]);
}

// -- sources -----------------------------------------------------------------------------------------------

#[test]
fn sg_r_rdr_05_a_source_error_is_source_error_with_the_cause() {
    // Covers: SG-R-RDR-05 SG-R-LAY-05
    let d = decoder(loose());
    for header in [vec![], vec!["pass"], vec!["stored"], vec!["bytes"], vec!["pass, stored"], vec!["stored, pass, pass"]] {
        let source = FailAfter::new(stored(&payload(100), 10)[..30].to_vec(), || {
            io::Error::new(io::ErrorKind::ConnectionReset, "the socket exploded")
        });
        let mut r = d.reader(source, &header).unwrap();
        let mut out = Vec::new();
        let e = r.read_to_end(&mut out).unwrap_err();
        let typed = Error::from_io(&e).unwrap_or_else(|| panic!("{header:?}: untyped {e:?}"));
        assert_eq!(typed.kind(), ErrorKind::SourceError, "{header:?}");
        assert_eq!(typed.layer(), 1, "{header:?}");
        let cause = typed.source().expect("the cause is reachable through source()");
        let cause = cause.downcast_ref::<io::Error>().expect("it is the io::Error");
        assert_eq!(cause.kind(), io::ErrorKind::ConnectionReset);
        assert!(cause.to_string().contains("exploded"));
        // sticky, and the cause is still there
        for _ in 0..3 {
            let e = r.read(&mut [0u8; 8]).unwrap_err();
            let typed = Error::from_io(&e).unwrap();
            assert_eq!(typed.kind(), ErrorKind::SourceError);
            assert!(typed.source().is_some());
        }
    }
}

#[test]
fn sg_r_rdr_05_a_source_error_is_reported_even_if_the_codec_swallows_it() {
    // Covers: SG-R-RDR-05 SG-R-CDC-08
    let d = decoder(loose());
    let source = FailAfter::new(b"abc".to_vec(), || io::Error::other("nope"));
    // the "bytes" codec turns any input failure into `corrupt`; the source failure must win
    let mut r = d.reader(source, &["bytes"]).unwrap();
    let mut out = Vec::new();
    let e = r.read_to_end(&mut out).unwrap_err();
    assert_eq!(Error::from_io(&e).unwrap().kind(), ErrorKind::SourceError);
    assert_eq!(out, b"abc");
}

#[test]
fn sg_r_rdr_05_the_decode_all_error_keeps_the_original_cause() {
    // Covers: SG-R-RDR-05 SG-R-API-02
    let d = decoder(loose());
    let source = FailAfter::new(b"abc".to_vec(), || io::Error::new(io::ErrorKind::TimedOut, "slow"));
    let e = d.decode_all(source, &["pass"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::SourceError);
    let cause = e.source().unwrap().downcast_ref::<io::Error>().unwrap();
    assert_eq!(cause.kind(), io::ErrorKind::TimedOut);
    assert_eq!(e.kind().http_status(), 400);
}

#[test]
fn sg_r_cdc_06_a_source_that_ends_early_is_corrupt_not_source_error() {
    // Covers: SG-R-CDC-06 SG-R-RDR-05
    let d = decoder(loose());
    let full = stored(&payload(500), 100);
    for cut in 0..full.len() {
        let o = run(&d, &full[..cut], &["stored"], 64);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt), "cut at {cut}");
    }
    assert_eq!(run(&d, &full, &["stored"], 64).kind, None);
    // an empty source is a clean end for identity and truncation for a codec
    assert_eq!(run(&d, b"", &[], 8), Outcome { bytes: vec![], kind: None });
    assert_eq!(run(&d, b"", &["stored"], 8).kind, Some(ErrorKind::Corrupt));
}

#[test]
fn sg_r_rdr_03_a_source_that_makes_no_progress_is_internal() {
    // Covers: SG-R-RDR-03
    // In Rust `Ok(0)` is the end of the source by the contract of `Read`; "no progress" is a source
    // that is interrupted over and over without ever delivering.
    let d = decoder(loose());
    for header in [vec![], vec!["pass"], vec!["pass, pass"]] {
        let calls = Rc::new(Cell::new(0));
        let mut r = d.reader(AlwaysInterrupted(calls.clone()), &header).unwrap();
        let mut buf = [0u8; 16];
        let e = r.read(&mut buf).unwrap_err();
        assert_eq!(kind_of(&e), ErrorKind::Internal, "{header:?}");
        assert!(calls.get() <= 100, "{header:?}: bounded retries, got {}", calls.get());
        assert!(calls.get() >= 99, "{header:?}: {}", calls.get());
        let after = calls.get();
        for _ in 0..5 {
            assert_eq!(kind_of(&r.read(&mut buf).unwrap_err()), ErrorKind::Internal);
        }
        assert_eq!(calls.get(), after, "no further reads after the terminal error (SG-R-LAY-09)");
    }
}

#[test]
fn sg_r_rdr_03_the_interrupted_boundary() {
    // Covers: SG-R-RDR-03
    let d = decoder(loose());
    // 99 interruptions in a row before every real read are survived, 100 are not
    let ok = Interrupted::new(Chunked::new(payload(10_000), 1000), 99);
    let mut r = d.reader(ok, &["pass"]).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, payload(10_000));
    let too_many = Interrupted::new(Chunked::new(payload(10_000), 1000), 100);
    let mut r = d.reader(too_many, &["pass"]).unwrap();
    let e = r.read_to_end(&mut Vec::new()).unwrap_err();
    assert_eq!(kind_of(&e), ErrorKind::Internal);
}

#[test]
fn an_empty_read_of_the_source_is_its_end() {
    // Covers: SG-R-CDC-06 SG-R-RDR-03
    let d = decoder(loose());
    struct Zero(Rc<Cell<usize>>);
    impl Read for Zero {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            self.0.set(self.0.get() + 1);
            Ok(0)
        }
    }
    let calls = Rc::new(Cell::new(0));
    let mut r = d.reader(Zero(calls.clone()), &["pass"]).unwrap();
    let mut buf = [0u8; 8];
    for _ in 0..10 {
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }
    assert_eq!(calls.get(), 1, "the source is not read again after its end");
    // for a format with a trailer that is truncation
    let r = d.reader(Zero(Rc::default()), &["stored"]).unwrap();
    drop(r);
    assert_eq!(run(&d, b"", &["stored"], 8).kind, Some(ErrorKind::Corrupt));
}

#[test]
fn sg_r_rdr_04_a_source_that_reports_more_than_requested_is_internal() {
    // Covers: SG-R-RDR-04
    let d = decoder(loose());
    for extra in [1usize, 2, 4096, 1 << 20] {
        for header in [vec![], vec!["pass"], vec!["stored"]] {
            let mut r = d.reader(OverReportingSource(extra), &header).unwrap();
            let mut buf = [0u8; 100];
            let e = r.read(&mut buf).unwrap_err();
            assert_eq!(kind_of(&e), ErrorKind::Internal, "{header:?} {extra}");
            assert_eq!(kind_of(&r.read(&mut buf).unwrap_err()), ErrorKind::Internal);
        }
    }
}

#[test]
fn interrupted_reads_of_the_source_are_retried() {
    // Covers: SG-R-RDR-01 SG-R-RDR-05
    let d = decoder(loose());
    let data = payload(9000);
    let mut r = d.reader(Interrupted::new(Chunked::new(stored(&data, 300), 700), 3), &["stored"]).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
}

#[test]
fn sg_r_lay_09_the_source_is_not_read_after_a_terminal_condition() {
    // Covers: SG-R-LAY-09
    let d = decoder(Limits::new(100).disable_ratio_limit());
    // output limit
    let source = Chunked::new(vec![0u8; 1 << 20], 4096);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["pass"]).unwrap();
    assert!(r.read_to_end(&mut Vec::new()).is_err());
    let after = c.calls.get();
    for _ in 0..10 {
        let _ = r.read(&mut [0u8; 64]);
    }
    assert_eq!(c.calls.get(), after);
    assert!(c.bytes.get() <= 4096 * 2, "{}", c.bytes.get());
    // clean end
    let source = Chunked::new(b"abc".to_vec(), 4096);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["pass"]).unwrap();
    r.read_to_end(&mut Vec::new()).unwrap();
    let after = c.calls.get();
    for _ in 0..10 {
        assert_eq!(r.read(&mut [0u8; 64]).unwrap(), 0);
    }
    assert_eq!(c.calls.get(), after);
    // corrupt
    let source = Chunked::new(vec![9u8; 100], 10);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["stored"]).unwrap();
    assert!(r.read_to_end(&mut Vec::new()).is_err());
    let after = c.calls.get();
    for _ in 0..10 {
        assert!(r.read(&mut [0u8; 64]).is_err());
    }
    assert_eq!(c.calls.get(), after);
}

#[test]
fn sg_r_lay_09_sg_r_rat_02_look_ahead_is_bounded() {
    // Covers: SG-R-LAY-09 SG-R-RAT-02
    let d = decoder(loose());
    let source = Chunked::new(vec![1u8; 10 << 20], 1 << 20);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["pass"]).unwrap();
    let mut buf = [0u8; 1];
    r.read(&mut buf).unwrap();
    assert!(c.bytes.get() <= 64 * 1024, "fetched {} bytes for one", c.bytes.get());
    assert!(c.largest_request.get() <= 4096, "asked for {}", c.largest_request.get());
    // with a chain, still bounded
    let source = Chunked::new(vec![1u8; 10 << 20], 1 << 20);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["pass, pass, pass"]).unwrap();
    r.read(&mut buf).unwrap();
    assert!(c.bytes.get() <= 64 * 1024, "fetched {} bytes for one", c.bytes.get());
}

#[test]
fn sg_r_api_05_failures_carry_kind_layer_and_limit() {
    // Covers: SG-R-API-05
    let d = decoder(Limits::new(50).disable_ratio_limit());
    let mut r = d.reader(&[0u8; 100][..], &["pass"]).unwrap();
    let e = r.read_to_end(&mut Vec::new()).unwrap_err();
    let typed = Error::from_io(&e).unwrap();
    assert_eq!((typed.kind(), typed.layer(), typed.limit()), (ErrorKind::OutputLimit, 1, 50));
    assert!(typed.to_string().contains("output_limit"));
    assert_eq!(e.kind(), io::ErrorKind::Other);
    let d = decoder(loose());
    let e = d.decode_all(&[1u8, 0][..], &["stored"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Corrupt);
    assert_eq!(e.layer(), 1);
    let mut r = d.reader(&[1u8, 0][..], &["stored"]).unwrap();
    let e = r.read_to_end(&mut Vec::new()).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn sg_r_lay_06_decode_all_returns_no_data_on_error_but_streams_deliver_a_prefix() {
    // Covers: SG-R-LAY-06 SG-R-API-02
    let data = payload(5000);
    let mut bad = stored(&data, 1000);
    let n = bad.len();
    bad[n - 1] = b'X';
    let d = decoder(loose());
    assert_eq!(d.decode_all(&bad[..], &["stored"]).unwrap_err().kind(), ErrorKind::Corrupt);
    let mut r = d.reader(&bad[..], &["stored"]).unwrap();
    let mut out = Vec::new();
    let e = r.read_to_end(&mut out).unwrap_err();
    assert_eq!(kind_of(&e), ErrorKind::Corrupt);
    assert_eq!(out, data, "all bytes were produced before the trailer was judged");
    // spillgate::decode_all, the free function
    let out = spillgate::decode_all(&data[..], &["gzip", "identity"], Limits::new(5000).disable_ratio_limit());
    assert_eq!(out.unwrap_err().kind(), ErrorKind::Corrupt, "not gzip data");
    let out = spillgate::decode_all(&data[..], &[], Limits::new(5000).disable_ratio_limit());
    assert_eq!(out.unwrap(), data);
    assert_eq!(d.decode_all(&stored(&data, 1000)[..], &["stored"]).unwrap(), data);
}
