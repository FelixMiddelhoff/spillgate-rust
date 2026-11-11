//! The behavior that docs/how-to.md promises, checked with the same code. The guide's own code
//! blocks are compiled as doc tests (`#[cfg(doctest)]` include in `src/lib.rs`); this file runs the
//! parts that need data: status mapping, bombs, the partial-data rule, cancellation, custom codecs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use flate2::{write::GzEncoder, Compression};
use spillgate::{CancelToken, Codec, CodecReader, Decoder, Error, ErrorKind, Limits};

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn decode_body(
    decoder: &Decoder,
    compressed: &[u8],
    content_encoding: &[&str],
) -> Result<Vec<u8>, (u16, &'static str)> {
    decoder
        .decode_all(compressed, content_encoding)
        .map_err(|e| (e.kind().http_status(), "request body refused"))
}

fn copy_atomically<R: Read>(
    decoder: &Decoder,
    source: R,
    content_encoding: &[&str],
    final_path: &Path,
) -> io::Result<()> {
    let tmp = final_path.with_extension("part");
    let result = (|| {
        let mut reader = decoder.reader(source, content_encoding).map_err(io::Error::from)?;
        let mut out = fs::File::create(&tmp)?;
        io::copy(&mut reader, &mut out)?;
        out.sync_all()
    })();
    match result {
        Ok(()) => fs::rename(&tmp, final_path),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[test]
fn a_bomb_is_refused_with_413() {
    let decoder = Decoder::new(Limits::new(1 << 20)).unwrap();
    let bomb = gzip(&vec![0u8; 20_000_000]);
    assert!(bomb.len() < 100_000);
    let error = decoder.decode_all(&bomb[..], &["gzip"]).unwrap_err();
    assert_eq!(error.kind().http_status(), 413);
    assert!(matches!(error.kind(), ErrorKind::OutputLimit | ErrorKind::RatioLimit));
}

#[test]
fn the_status_table_of_the_guide_matches_http_status() {
    use ErrorKind::*;
    let table = [
        (OutputLimit, 413),
        (RatioLimit, 413),
        (LayerLimit, 413),
        (InputLimit, 413),
        (UnsupportedEncoding, 415),
        (MalformedEncoding, 400),
        (Corrupt, 400),
        (MemoryLimit, 413),
        (SourceError, 400),
        (Canceled, 503),
        (Internal, 500),
        (InvalidLimits, 500),
        (InvalidOption, 500),
    ];
    for (kind, status) in table {
        assert_eq!(kind.http_status(), status, "{kind}");
    }
}

#[test]
fn every_ingress_test_of_section_5() {
    let decoder = Decoder::new(Limits::new(1 << 20).max_layers(3)).unwrap();
    let plain = gzip(b"hello");
    assert_eq!(decode_body(&decoder, &plain, &["gzip"]).unwrap(), b"hello");
    // deep chain
    assert_eq!(
        decode_body(&decoder, &plain, &["gzip, gzip, gzip, gzip, gzip, gzip, gzip"])
            .unwrap_err()
            .0,
        413
    );
    // unknown encoding
    assert_eq!(decode_body(&decoder, &plain, &["compress"]).unwrap_err().0, 415);
    // truncation
    assert_eq!(
        decode_body(&decoder, &plain[..plain.len() - 5], &["gzip"])
            .unwrap_err()
            .0,
        400
    );
    // malformed header
    assert_eq!(decode_body(&decoder, &plain, &["gzip;;"]).unwrap_err().0, 400);
}

#[test]
fn take_would_truncate_but_spillgate_refuses() {
    // The trap of section 1: Read::take ends a bomb as a clean, truncated success.
    let bomb = gzip(&vec![7u8; 5 << 20]);
    let mut truncated = Vec::new();
    flate2::read::GzDecoder::new(&bomb[..])
        .take(1 << 20)
        .read_to_end(&mut truncated)
        .unwrap();
    assert_eq!(truncated.len(), 1 << 20);
    let decoder = Decoder::new(Limits::new(1 << 20).disable_ratio_limit()).unwrap();
    assert_eq!(
        decoder.decode_all(&bomb[..], &["gzip"]).unwrap_err().kind(),
        ErrorKind::OutputLimit
    );
}

#[test]
fn partial_data_is_never_committed() {
    let dir = std::env::temp_dir().join(format!("spillgate-howto-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let decoder = Decoder::new(Limits::new(1 << 16)).unwrap();

    let ok = dir.join("ok.bin");
    copy_atomically(&decoder, &gzip(b"fine")[..], &["gzip"], &ok).unwrap();
    assert_eq!(fs::read(&ok).unwrap(), b"fine");

    let bad = dir.join("bad.bin");
    let bomb = gzip(&vec![0u8; 1 << 20]);
    let error = copy_atomically(&decoder, &bomb[..], &["gzip"], &bad).unwrap_err();
    assert!(Error::from_io(&error).is_some());
    assert!(!bad.exists(), "the destination must not exist");
    assert!(
        !bad.with_extension("part").exists(),
        "the temporary file must be removed"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn errors_survive_question_mark_into_io_result() {
    fn pump(decoder: &Decoder, body: &[u8]) -> io::Result<()> {
        let mut reader = decoder.reader(body, &["gzip"]).map_err(io::Error::from)?;
        let mut buf = [0u8; 16 * 1024];
        while reader.read(&mut buf)? != 0 {}
        Ok(())
    }
    let decoder = Decoder::new(Limits::new(1024)).unwrap();
    let e = pump(&decoder, b"not gzip").unwrap_err();
    assert_eq!(Error::from_io(&e).map(Error::kind), Some(ErrorKind::Corrupt));
    let e = pump(&decoder, &gzip(&vec![1u8; 4096])).unwrap_err();
    assert_eq!(Error::from_io(&e).map(Error::kind), Some(ErrorKind::OutputLimit));
    // a plain I/O error is not a spillgate error
    assert!(Error::from_io(&io::Error::other("disk")).is_none());
}

#[test]
fn cancellation_from_another_thread() {
    struct Endless;
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(b'a');
            Ok(buf.len())
        }
    }
    let decoder = Decoder::new(Limits::new(1 << 40).disable_ratio_limit()).unwrap();
    let token = CancelToken::new();
    let mut reader = decoder.reader_with_cancel(Endless, &[], &token).unwrap();
    let remote = token.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        remote.cancel();
    });
    // read_to_end retries on io::ErrorKind::Interrupted: a canceled reader must not report that,
    // or the sticky error would make the standard helpers spin forever.
    let error = reader.read_to_end(&mut Vec::new()).unwrap_err();
    handle.join().unwrap();
    assert_eq!(Error::from_io(&error).map(Error::kind), Some(ErrorKind::Canceled));
    // sticky
    let again = reader.read(&mut [0u8; 8]).unwrap_err();
    assert_eq!(Error::from_io(&again).map(Error::kind), Some(ErrorKind::Canceled));
}

struct Rot;
struct RotReader<'a>(Box<dyn BufRead + 'a>);
impl CodecReader for RotReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = {
            let available = self.0.fill_buf().map_err(Error::from_input)?;
            let n = available.len().min(buf.len());
            for (out, byte) in buf.iter_mut().zip(&available[..n]) {
                *out = byte ^ 0x20;
            }
            n
        };
        self.0.consume(n);
        Ok(n)
    }
}
impl Codec for Rot {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(RotReader(input))
    }
}

#[test]
fn custom_codec_runs_behind_the_limiter() {
    let decoder = Decoder::builder(Limits::new(4)).codec("rot", Rot).build().unwrap();
    assert_eq!(decoder.decode_all(&b"hELL"[..], &["rot"]).unwrap(), b"Hell");
    assert_eq!(
        decoder.decode_all(&b"hELLO"[..], &["rot"]).unwrap_err().kind(),
        ErrorKind::OutputLimit
    );
    let reserved = Decoder::builder(Limits::new(4)).codec("gzip", Rot).build().unwrap_err();
    assert_eq!(reserved.kind(), ErrorKind::InvalidOption);
}

#[test]
fn a_panicking_codec_becomes_internal() {
    struct Boom;
    struct BoomReader;
    impl CodecReader for BoomReader {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Error> {
            panic!("codec bug");
        }
    }
    impl Codec for Boom {
        fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
            Box::new(BoomReader)
        }
    }
    let decoder = Decoder::builder(Limits::new(1024)).codec("boom", Boom).build().unwrap();
    let error = decoder.decode_all(&b"x"[..], &["boom"]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.kind().http_status(), 500);
}

#[test]
fn the_decoder_is_shareable_between_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Decoder>();
    assert_send_sync::<CancelToken>();
}

#[cfg(all(feature = "br", feature = "zstd"))]
#[test]
fn br_and_zstd_registration_of_section_3_8() {
    use spillgate::{br, zstd};
    let decoder = Decoder::builder(Limits::new(8 * 1024 * 1024))
        .codec("br", br::codec(br::BrotliOptions { max_window_bits: 22 }).unwrap())
        .codec(
            "zstd",
            zstd::codec(zstd::ZstdOptions {
                max_window_bytes: 4 * 1024 * 1024,
            })
            .unwrap(),
        )
        .build()
        .unwrap();
    let encoded = ::zstd::encode_all(&b"hello zstd"[..], 3).unwrap();
    assert_eq!(decoder.decode_all(&encoded[..], &["zstd"]).unwrap(), b"hello zstd");
    assert!(br::codec(br::BrotliOptions { max_window_bits: 30 }).is_err());
}
