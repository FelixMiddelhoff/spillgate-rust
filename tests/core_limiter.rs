//! The limiter: output boundary, ratio, input cap (SPEC sections 5 to 7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::cell::Cell;
use std::io::Read;
use std::rc::Rc;

use common::*;
use spillgate::{Decoder, Error, ErrorKind, Limits};

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

const READ_SIZES: [usize; 5] = [1, 7, 4096, 65536, 1 << 22];

/// What a test needs to know about an error.
struct Info {
    kind: ErrorKind,
    layer: usize,
    limit: u64,
}
impl Info {
    fn kind(&self) -> ErrorKind {
        self.kind
    }
    fn layer(&self) -> usize {
        self.layer
    }
    fn limit(&self) -> u64 {
        self.limit
    }
}

fn typed(reader: &mut impl Read, size: usize) -> (Vec<u8>, Option<Info>) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; size];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => {
                let e = Error::from_io(&e).expect("a spillgate error");
                return (out, Some(Info { kind: e.kind(), layer: e.layer(), limit: e.limit() }));
            }
        }
    }
}

// -- output boundary -------------------------------------------------------------------------------------

#[test]
fn sg_r_lay_03_exact_boundary_with_a_clean_end() {
    // Covers: SG-R-LAY-02 SG-R-LAY-03 SG-I-01 SG-R-RDR-01
    for n in [0usize, 1, 2, 3, 99, 100, 4095, 4096, 4097, 65535, 65536, 65537, 70000] {
        let payload = data(n);
        let framed = stored(&payload, 1000);
        for header in [vec!["stored"], vec!["pass, stored"], vec!["pass, pass, stored"]] {
            for &size in &READ_SIZES {
                // max_output = n: exactly at the limit is success
                if n >= 1 {
                    let d = decoder(Limits::new(n as u64).disable_ratio_limit());
                    let o = run(&d, &framed, &header, size);
                    assert_eq!((o.kind, o.bytes.len()), (None, n), "n={n} {header:?} size {size}");
                    assert_eq!(o.bytes, payload);
                }
                // max_output = n + 1: success
                let d = decoder(Limits::new(n as u64 + 1).disable_ratio_limit());
                let o = run(&d, &framed, &header, size);
                assert_eq!(o.kind, None, "n={n} +1 {header:?} size {size}");
                assert_eq!(o.bytes, payload);
                // max_output = n - 1: output_limit after exactly n - 1 bytes
                if n >= 2 {
                    let d = decoder(Limits::new(n as u64 - 1).disable_ratio_limit());
                    let o = run(&d, &framed, &header, size);
                    assert_eq!(o.kind, Some(ErrorKind::OutputLimit), "n={n} -1 {header:?} size {size}");
                    assert_eq!(o.bytes, payload[..n - 1], "n={n} -1 {header:?} size {size}");
                }
            }
        }
    }
}

#[test]
fn sg_r_lay_03_identity_is_bounded_at_the_same_boundary() {
    // Covers: SG-R-CDC-10 SG-R-LAY-01 SG-R-LAY-03
    for n in [1usize, 2, 10, 4096, 5000] {
        let payload = data(n);
        for header in [vec![], vec!["identity"], vec!["identity, identity"]] {
            for &size in &READ_SIZES {
                let ok = decoder(Limits::new(n as u64).disable_ratio_limit());
                let o = run(&ok, &payload, &header, size);
                assert_eq!((o.kind, o.bytes.len()), (None, n), "n={n} size {size}");
                if n >= 2 {
                    let d = decoder(Limits::new(n as u64 - 1).disable_ratio_limit());
                    let o = run(&d, &payload, &header, size);
                    assert_eq!(o.kind, Some(ErrorKind::OutputLimit));
                    assert_eq!(o.bytes, payload[..n - 1]);
                }
            }
        }
    }
}

#[test]
fn sg_r_lay_07_conditions_are_judged_in_stream_order() {
    // Covers: SG-R-LAY-07 SG-R-LAY-03 SG-R-CDC-06
    let n = 300usize;
    let payload = data(n);
    let good = stored(&payload, 100);
    let mut bad_trailer = good.clone();
    *bad_trailer.last_mut().unwrap() = b'?';
    let truncated = good[..good.len() - 2].to_vec();
    let mut trailing = good.clone();
    trailing.push(1);
    for &size in &READ_SIZES {
        let at = |max: u64| decoder(Limits::new(max).disable_ratio_limit());
        // a bad trailer after exactly max_output bytes is corrupt
        let o = run(&at(n as u64), &bad_trailer, &["stored"], size);
        assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::Corrupt), n), "size {size}");
        // a truncated stream after exactly max_output bytes is corrupt
        let o = run(&at(n as u64), &truncated, &["stored"], size);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt));
        // trailing bytes after the trailer: corrupt at the boundary
        let o = run(&at(n as u64), &trailing, &["stored"], size);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt));
        // a stream longer than max_output is output_limit even if its trailer is bad
        let o = run(&at(n as u64 - 1), &bad_trailer, &["stored"], size);
        assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::OutputLimit), n - 1));
        let o = run(&at(n as u64 - 1), &truncated, &["stored"], size);
        assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::OutputLimit), n - 1));
        // success must not be reported before the trailer was validated
        let o = run(&at(n as u64 + 1), &bad_trailer, &["stored"], size);
        assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::Corrupt), n));
        // corruption before the (max+1)th byte is corrupt
        let mut early = good.clone();
        early[0] = 0xff; // chunk of 65280 + 100 bytes declared, then the stream ends: corrupt
        let o = run(&at(1 << 20), &early, &["stored"], size);
        assert_eq!(o.kind, Some(ErrorKind::Corrupt));
    }
}

#[test]
fn sg_r_lay_04_a_limit_hit_is_never_a_clean_end() {
    // Covers: SG-R-LAY-04 SG-I-02
    let d = decoder(Limits::new(1000).disable_ratio_limit());
    for &size in &READ_SIZES {
        let mut r = d.reader(Endless(7, Rc::default()), &[]).unwrap();
        let (bytes, error) = typed(&mut r, size);
        assert_eq!(bytes.len(), 1000);
        assert_eq!(error.unwrap().kind(), ErrorKind::OutputLimit);
    }
}

#[test]
fn sg_i_01_a_bomb_never_delivers_more_than_the_budget() {
    // Covers: SG-I-01 SG-R-LAY-02 SG-R-CDC-01 SG-R-MEM-02
    for max in [1u64, 2, 65535, 65536, 65537, 200_000] {
        let d = Decoder::builder(Limits::new(max).disable_ratio_limit()).codec("zeros", Zeros(u64::MAX)).build().unwrap();
        for &size in &READ_SIZES {
            let mut r = d.reader(&b""[..], &["zeros"]).unwrap();
            let (bytes, error) = typed(&mut r, size);
            assert_eq!(bytes.len() as u64, max, "max {max} size {size}");
            let e = error.unwrap();
            assert_eq!((e.kind(), e.layer(), e.limit()), (ErrorKind::OutputLimit, 1, max));
        }
    }
    // a bomb of exactly max bytes is fine
    let d = Decoder::builder(Limits::new(70_000).disable_ratio_limit()).codec("zeros", Zeros(70_000)).build().unwrap();
    let o = run(&d, b"", &["zeros"], 9999);
    assert_eq!((o.kind, o.bytes.len()), (None, 70_000));
}

#[test]
fn max_step_bounds_every_codec_call() {
    // Covers: SG-R-MEM-02 SG-R-RAT-02
    // Codecs are Send + Sync, so the observation goes through a static.
    static LARGEST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    struct Spy2;
    impl spillgate::Codec for Spy2 {
        fn new_reader<'a>(&self, _i: Box<dyn std::io::BufRead + 'a>) -> Box<dyn spillgate::CodecReader + 'a> {
            struct R;
            impl spillgate::CodecReader for R {
                fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
                    LARGEST.fetch_max(buf.len(), std::sync::atomic::Ordering::SeqCst);
                    buf.fill(0);
                    Ok(buf.len())
                }
            }
            Box::new(R)
        }
    }
    let d = Decoder::builder(Limits::new(10 << 20).disable_ratio_limit()).codec("spy", Spy2).build().unwrap();
    let mut r = d.reader(&b""[..], &["spy"]).unwrap();
    let mut buf = vec![0u8; 8 << 20];
    let mut total = 0;
    while total < (4 << 20) {
        total += r.read(&mut buf).unwrap();
    }
    assert_eq!(LARGEST.load(std::sync::atomic::Ordering::SeqCst), 64 * 1024);
}

// -- ratio ---------------------------------------------------------------------------------------------

fn ratio_decoder(ratio: u64, grace: u64) -> Decoder {
    decoder(Limits::new(1 << 30).max_ratio(ratio).ratio_grace(grace))
}

#[test]
fn sg_r_rat_01_the_ratio_fires_at_the_exact_byte_with_single_byte_reads() {
    // Covers: SG-R-RAT-01 SG-I-02
    // expand10: every input byte is 10 output bytes. Ratio 9, grace 0: P=10 > 9*1.
    let d = ratio_decoder(9, 0);
    let o = run(&d, &[1u8; 50], &["expand10"], 1);
    assert_eq!(o.kind, Some(ErrorKind::RatioLimit));
    assert_eq!(o.bytes.len(), 10);
    // Ratio 10 is exactly the ratio of the codec: P = 10*C at every full input byte, never above
    let d = ratio_decoder(10, 0);
    let o = run(&d, &[1u8; 5000], &["expand10"], 1);
    assert_eq!((o.kind, o.bytes.len()), (None, 50_000));
    // expand11 against ratio 10 fires at the first byte past 10 * C
    let d = Decoder::builder(Limits::new(1 << 30).max_ratio(10).ratio_grace(0)).codec("e11", Expand(11)).build().unwrap();
    let o = run(&d, &[1u8; 50], &["e11"], 1);
    assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::RatioLimit), 11));
}

#[test]
fn sg_r_rat_01_the_grace_boundary() {
    // Covers: SG-R-RAT-01 SG-R-LIM-05
    let e100 = |grace: u64| {
        Decoder::builder(Limits::new(1 << 30).max_ratio(1).ratio_grace(grace)).codec("e100", Expand(100)).build().unwrap()
    };
    // C = 1 up to the 100th byte, 2 from the 101st: P = 101 > 1*2 fires once P > grace
    for grace in [0u64, 50, 100, 101, 150] {
        let o = run(&e100(grace), &[1u8; 20], &["e100"], 1);
        assert_eq!(o.kind, Some(ErrorKind::RatioLimit), "grace {grace}");
        // inside the grace nothing is checked; past it P > 1 * max(C, 1) holds from P = 2 on
        let expected = (grace + 1).max(2) as usize;
        assert_eq!(o.bytes.len(), expected, "grace {grace}");
    }
    // the default grace is 64 KiB
    let d = decoder(Limits::new(1 << 30).max_ratio(1));
    let o = run(&d, &[1u8; 100_000], &["expand10"], 1);
    assert_eq!(o.kind, Some(ErrorKind::RatioLimit));
    assert_eq!(o.bytes.len(), 65_537);
}

#[test]
fn sg_r_rat_01_consumed_counts_as_at_least_one() {
    // Covers: SG-R-RAT-01
    // A bomb that consumes nothing is judged against max(C, 1).
    let d = Decoder::builder(Limits::new(1 << 30)).codec("zeros", Zeros(u64::MAX)).build().unwrap();
    let mut r = d.reader(&b""[..], &["zeros"]).unwrap();
    let (bytes, error) = typed(&mut r, 1);
    let e = error.unwrap();
    assert_eq!(e.kind(), ErrorKind::RatioLimit);
    assert_eq!((e.layer(), e.limit()), (1, 1000));
    // default grace 65536, ratio 1000 * 1: fires on the first byte past the grace
    assert_eq!(bytes.len(), 65_537);
}

#[test]
fn sg_r_rat_02_read_ahead_gives_no_credit() {
    // Covers: SG-R-RAT-02 SG-R-INP-02
    // The whole 4 KiB source is fetched at once, but the codec consumes one byte per 1001 outputs.
    let d = Decoder::builder(Limits::new(1 << 30).max_ratio(1000).ratio_grace(0)).codec("e1001", Expand(1001)).build().unwrap();
    let source = Chunked::new(vec![1u8; 4096], 4096);
    let mut r = d.reader(source, &["e1001"]).unwrap();
    let (bytes, error) = typed(&mut r, 1);
    assert_eq!(error.unwrap().kind(), ErrorKind::RatioLimit);
    assert_eq!(bytes.len(), 1001);
    // the same at exactly the ratio never fires
    let d = Decoder::builder(Limits::new(1 << 30).max_ratio(1000).ratio_grace(0)).codec("e1000", Expand(1000)).build().unwrap();
    let source = Chunked::new(vec![1u8; 4096], 4096);
    let mut r = d.reader(source, &["e1000"]).unwrap();
    let (bytes, error) = typed(&mut r, 1 << 16);
    assert!(error.is_none());
    assert_eq!(bytes.len(), 4096 * 1000);
}

#[test]
fn sg_r_rat_01_the_ratio_names_layer_and_limit() {
    // Covers: SG-R-RAT-01 SG-I-02 SG-R-API-05
    let d = decoder(Limits::new(1 << 30).ratio_grace(0));
    let mut r = d.reader(&[1u8; 10][..], &["expand2000"]).unwrap();
    let (bytes, error) = typed(&mut r, 1 << 16);
    let e = error.unwrap();
    assert_eq!((e.kind(), e.layer(), e.limit()), (ErrorKind::RatioLimit, 1, 1000));
    // bytes that broke the ratio are delivered first, the error follows (SG-R-LAY-07)
    assert!(!bytes.is_empty() && bytes.len() <= 65536, "{}", bytes.len());
}

#[test]
fn sg_r_rat_03_end_to_end_ratio_without_a_failing_layer() {
    // Covers: SG-R-RAT-03 SG-R-LAY-01
    // Two layers of 10x each are fine alone (limit 50) but 100x end to end.
    let d = decoder(Limits::new(1 << 30).max_ratio(50).ratio_grace(0));
    let mut r = d.reader(&[1u8; 5000][..], &["expand10, expand10"]).unwrap();
    let (bytes, error) = typed(&mut r, 1);
    let e = error.unwrap();
    assert_eq!(e.kind(), ErrorKind::RatioLimit);
    assert_eq!(e.layer(), 0, "an end-to-end error has no layer");
    assert_eq!(e.limit(), 50);
    assert!(bytes.len() < 5000 * 100);
    // with a ratio of 100 it never fires
    let d = decoder(Limits::new(1 << 30).max_ratio(100).ratio_grace(0));
    let mut r = d.reader(&[1u8; 500][..], &["expand10, expand10"]).unwrap();
    let (bytes, error) = typed(&mut r, 1 << 16);
    assert!(error.is_none());
    assert_eq!(bytes.len(), 50_000);
}

#[test]
fn sg_r_rat_01_an_intermediate_layer_names_itself() {
    // Covers: SG-R-RAT-01 SG-R-LAY-01
    let d = decoder(Limits::new(1 << 30).ratio_grace(0));
    // layer 1 = expand2000 (listed last) fails; layer 2 shrinks, so only layer 1 can be blamed
    let mut r = d.reader(&[1u8; 10][..], &["shrink10, expand2000"]).unwrap();
    let (_, error) = typed(&mut r, 4096);
    let e = error.unwrap();
    assert_eq!((e.kind(), e.layer()), (ErrorKind::RatioLimit, 1));
    // with a pass-through on top the same ratio is reported, by the layer or by the whole chain
    let mut r = d.reader(&[1u8; 10][..], &["pass, expand2000"]).unwrap();
    let (_, error) = typed(&mut r, 4096);
    let e = error.unwrap();
    assert_eq!(e.kind(), ErrorKind::RatioLimit);
    assert!(e.layer() <= 1);
}

#[test]
fn sg_r_rat_04_the_opt_out_leaves_the_other_limits_in_force() {
    // Covers: SG-R-RAT-04 SG-R-LIM-07
    let d = Decoder::builder(Limits::new(200_000).disable_ratio_limit())
        .codec("zeros", Zeros(u64::MAX))
        .build()
        .unwrap();
    let mut r = d.reader(&b""[..], &["zeros"]).unwrap();
    let (bytes, error) = typed(&mut r, 1 << 16);
    assert_eq!(bytes.len(), 200_000);
    assert_eq!(error.unwrap().kind(), ErrorKind::OutputLimit);
    let d = Decoder::builder(Limits::new(1 << 30).disable_ratio_limit().max_input(10)).codec("e", Expand(10_000)).build().unwrap();
    let o = run(&d, &[1u8; 11], &["e"], 1 << 16);
    assert_eq!(o.kind, Some(ErrorKind::InputLimit));
    let d = Decoder::builder(Limits::new(1 << 30).disable_ratio_limit().max_layers(1)).codec("e", Expand(10_000)).build().unwrap();
    assert_eq!(d.reader(&b""[..], &["e, e"]).unwrap_err().kind(), ErrorKind::LayerLimit);
}

#[test]
fn a_single_layer_ratio_equals_the_end_to_end_ratio() {
    // Covers: SG-R-RAT-03 SG-R-RAT-01
    // For a one layer chain the layer fires first and names itself, never the chain.
    let d = decoder(Limits::new(1 << 30).max_ratio(5).ratio_grace(0));
    let mut r = d.reader(&[1u8; 10][..], &["expand10"]).unwrap();
    let (_, error) = typed(&mut r, 1);
    assert_eq!(error.unwrap().layer(), 1);
    // identity: P = C, a ratio of 1 never fires even for max_ratio 1
    let d = decoder(Limits::new(1 << 30).max_ratio(1).ratio_grace(0));
    let o = run(&d, &data(100_000), &[], 4096);
    assert_eq!((o.kind, o.bytes.len()), (None, 100_000));
}

// -- input cap -----------------------------------------------------------------------------------------

#[test]
fn sg_r_inp_01_the_input_limit_is_exact_and_asks_for_one_probe_byte_at_most() {
    // Covers: SG-R-INP-01 SG-R-INP-02
    for max in [1u64, 2, 100, 4095, 4096, 4097, 10_000] {
        for step in [1usize, 1000, 4096, 1 << 20] {
            // plenty of bytes in the source
            let source = Chunked::new(vec![3u8; 100_000], step);
            let c = source.counters.clone();
            let d = decoder(Limits::new(1 << 30).max_input(max).disable_ratio_limit());
            let mut r = d.reader(source, &["pass"]).unwrap();
            let (bytes, error) = typed(&mut r, 1 << 16);
            let e = error.unwrap();
            assert_eq!(e.kind(), ErrorKind::InputLimit, "max {max} step {step}");
            assert_eq!((e.layer(), e.limit()), (1, max));
            assert_eq!(bytes.len() as u64, max, "the codec got exactly max_input bytes");
            assert!(c.largest_request.get() as u64 <= max + 1, "asked for {} for max {max}", c.largest_request.get());
            assert!(c.bytes.get() as u64 <= max + 1, "got {} for max {max}", c.bytes.get());
            // exactly max bytes in the source is fine
            let source = Chunked::new(vec![3u8; max as usize], step);
            let c = source.counters.clone();
            let mut r = d.reader(source, &["pass"]).unwrap();
            let (bytes, error) = typed(&mut r, 1 << 16);
            assert!(error.is_none(), "max {max} step {step}");
            assert_eq!(bytes.len() as u64, max);
            assert_eq!(c.bytes.get() as u64, max);
            // one more byte than max is the violation
            let source = Chunked::new(vec![3u8; max as usize + 1], step);
            let c = source.counters.clone();
            let mut r = d.reader(source, &["pass"]).unwrap();
            let (bytes, error) = typed(&mut r, 1 << 16);
            assert_eq!(error.unwrap().kind(), ErrorKind::InputLimit);
            assert_eq!(bytes.len() as u64, max);
            assert!(c.bytes.get() as u64 <= max + 1);
        }
    }
}

#[test]
fn sg_r_inp_01_the_cap_applies_to_identity_chains() {
    // Covers: SG-R-INP-01
    let d = decoder(Limits::new(1 << 30).max_input(10).disable_ratio_limit());
    for header in [vec![], vec!["identity"]] {
        let o = run(&d, &[1u8; 10], &header, 3);
        assert_eq!((o.kind, o.bytes.len()), (None, 10));
        let o = run(&d, &[1u8; 11], &header, 3);
        assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::InputLimit), 10));
    }
}

#[test]
fn sg_r_inp_01_a_stream_that_fits_is_unaffected_by_what_follows_it() {
    // Covers: SG-R-INP-01
    let d = Decoder::builder(Limits::new(1 << 30).max_input(10).disable_ratio_limit()).codec("take10", TakeN(10)).build().unwrap();
    let source = Chunked::new(vec![8u8; 500], 100);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["take10"]).unwrap();
    let (bytes, error) = typed(&mut r, 100);
    assert!(error.is_none());
    assert_eq!(bytes, [8u8; 10]);
    assert!(c.bytes.get() <= 11 && c.largest_request.get() <= 11);
    // a codec stream of 10 bytes: take 11 needs the 11th byte -> input_limit
    let d = Decoder::builder(Limits::new(1 << 30).max_input(10).disable_ratio_limit()).codec("take11", TakeN(11)).build().unwrap();
    let o = run(&d, &[8u8; 500], &["take11"], 100);
    assert_eq!((o.kind, o.bytes.len()), (Some(ErrorKind::InputLimit), 10));
}

#[test]
fn sg_r_inp_01_the_cap_applies_to_the_source_only_not_to_lower_layers() {
    // Covers: SG-R-INP-01 SG-R-LAY-01
    let d = decoder(Limits::new(1 << 30).max_input(10).disable_ratio_limit());
    // layer 1 = expand10 reads 10 source bytes and produces 100, layer 2 consumes those 100
    let o = run(&d, &[2u8; 10], &["pass, expand10"], 7);
    assert_eq!((o.kind, o.bytes.len()), (None, 100));
    let o = run(&d, &[2u8; 11], &["pass, expand10"], 7);
    assert_eq!(o.kind, Some(ErrorKind::InputLimit));
    assert_eq!(o.bytes.len(), 100);
}

#[test]
fn sg_r_inp_02_an_endless_source_is_never_over_read() {
    // Covers: SG-R-INP-02 SG-R-LAY-09
    for max in [1u64, 100, 5000] {
        let total = Rc::new(Cell::new(0u64));
        let d = decoder(Limits::new(1 << 30).max_input(max).disable_ratio_limit());
        let mut r = d.reader(Endless(1, total.clone()), &["pass, pass"]).unwrap();
        let (_, error) = typed(&mut r, 1 << 16);
        assert_eq!(error.unwrap().kind(), ErrorKind::InputLimit);
        assert!(total.get() <= max + 1, "{} for max {max}", total.get());
    }
}

#[test]
fn sg_r_inp_01_input_accounting_is_by_consumption_not_by_fetch() {
    // Covers: SG-R-INP-01 SG-R-RAT-02
    // expand10 consumes 1 byte per 10 outputs; max_input 5 lets it read exactly 5 bytes = 50 outputs
    let d = decoder(Limits::new(1 << 30).max_input(5).disable_ratio_limit());
    let o = run(&d, &[9u8; 4096], &["expand10"], 1);
    assert_eq!(o.kind, Some(ErrorKind::InputLimit));
    assert_eq!(o.bytes.len(), 50);
    let o = run(&d, &[9u8; 5], &["expand10"], 1);
    assert_eq!((o.kind, o.bytes.len()), (None, 50));
}

#[test]
fn sg_r_inp_01_a_codec_cannot_consume_more_than_it_was_shown() {
    // Covers: SG-R-INP-01 SG-R-CDC-01
    struct Greedy;
    struct GreedyReader<'a>(Box<dyn std::io::BufRead + 'a>);
    impl spillgate::CodecReader for GreedyReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let n = {
                let avail = self.0.fill_buf().map_err(Error::from_input)?;
                if avail.is_empty() {
                    return Ok(0);
                }
                let n = avail.len().min(buf.len());
                buf[..n].fill(1);
                n
            };
            self.0.consume(usize::MAX); // lies about what it used
            Ok(n)
        }
    }
    impl spillgate::Codec for Greedy {
        fn new_reader<'a>(&self, input: Box<dyn std::io::BufRead + 'a>) -> Box<dyn spillgate::CodecReader + 'a> {
            Box::new(GreedyReader(input))
        }
    }
    let d = Decoder::builder(Limits::new(1 << 30).max_input(10).disable_ratio_limit()).codec("greedy", Greedy).build().unwrap();
    let source = Chunked::new(vec![1u8; 1000], 1000);
    let c = source.counters.clone();
    let mut r = d.reader(source, &["greedy"]).unwrap();
    let (_, error) = typed(&mut r, 100);
    assert_eq!(error.unwrap().kind(), ErrorKind::InputLimit);
    assert!(c.bytes.get() <= 11);
}
