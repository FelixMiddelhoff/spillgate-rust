//! A failure late in the stream (a source error, or corruption in a lower layer) delivers the same
//! bytes before it whatever the caller's read size and the source's chunking: the delivered prefix
//! is a property of the stream, not of the way it is read (SG-I-09, SG-R-RDR-01, SG-R-LAY-06).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::{self, Read, Write};

use common::{drain, Outcome};
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::Compression;
use spillgate::{Decoder, ErrorKind, Limits};

const READ_SIZES: [usize; 7] = [1, 3, 100, 4096, 65_535, 65_536, 1 << 20];
const CHUNKS: [usize; 5] = [1, 5, 4096, 65_536, usize::MAX];

fn payload(n: usize) -> Vec<u8> {
    // compressible but not trivial: text-like runs plus noise
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..n)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if i % 7 < 4 {
                b'a' + (i / 7 % 13) as u8
            } else {
                state as u8
            }
        })
        .collect()
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
fn zl(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
fn raw(data: &[u8]) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Hands out at most `chunk` bytes per call, then fails on every further call.
struct FailingSource {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}
impl Read for FailingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.data.len() {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "late failure"));
        }
        let n = buf.len().min(self.chunk).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn decoder() -> Decoder {
    let limits = Limits::new(1 << 30).disable_ratio_limit().max_layers(4);
    let builder = Decoder::builder(limits);
    #[cfg(feature = "br")]
    let builder = builder.codec(
        "br",
        spillgate::br::codec(spillgate::br::BrotliOptions::default()).unwrap(),
    );
    #[cfg(feature = "zstd")]
    let builder = builder.codec(
        "zstd",
        spillgate::zstd::codec(spillgate::zstd::ZstdOptions::default()).unwrap(),
    );
    builder.build().unwrap()
}

fn run(d: &Decoder, data: &[u8], header: &[&str], read_size: usize, chunk: usize) -> Outcome {
    let source = FailingSource {
        data: data.to_vec(),
        pos: 0,
        chunk,
    };
    let mut reader = d.reader(source, header).unwrap();
    let out = drain(&mut reader, read_size);
    reader.close();
    out
}

/// All read sizes x all chunkings give one and the same outcome; returns it.
fn assert_invariant(d: &Decoder, data: &[u8], header: &[&str], what: &str) -> Outcome {
    let reference = run(d, data, header, 4096, usize::MAX);
    for read_size in READ_SIZES {
        for chunk in CHUNKS {
            let o = run(d, data, header, read_size, chunk);
            assert_eq!(
                (o.kind, o.bytes.len()),
                (reference.kind, reference.bytes.len()),
                "{what} {header:?}: read {read_size} chunk {chunk}"
            );
            assert!(
                o.bytes == reference.bytes,
                "{what} {header:?}: bytes differ, read {read_size} chunk {chunk}"
            );
        }
    }
    reference
}

fn cuts(len: usize) -> Vec<usize> {
    let mut v = vec![len / 2, len * 9 / 10, len - 1, len - 5, len - 40, 20, 12];
    v.retain(|c| *c > 0 && *c < len);
    v.sort_unstable();
    v.dedup();
    v
}

#[test]
fn a_late_source_error_delivers_the_same_prefix_for_every_read_size_and_chunking() {
    // Covers: SG-I-09 SG-R-RDR-01 SG-R-RDR-05 SG-R-LAY-06
    let d = decoder();
    let p = payload(300_000);
    let mut streams: Vec<(&str, Vec<u8>)> = vec![("gzip", gz(&p)), ("deflate", zl(&p)), ("deflate", raw(&p))];
    #[cfg(feature = "br")]
    streams.push(("br", brotli_encode(&p)));
    #[cfg(feature = "zstd")]
    streams.push(("zstd", zstd::encode_all(&p[..], 3).unwrap()));
    for (name, stream) in &streams {
        for cut in cuts(stream.len()) {
            let o = assert_invariant(&d, &stream[..cut], &[name], &format!("cut {cut}/{}", stream.len()));
            assert_eq!(o.kind, Some(ErrorKind::SourceError), "{name} cut {cut}");
            assert!(p.starts_with(&o.bytes), "{name} cut {cut}: the prefix is wrong");
        }
    }
}

#[test]
fn a_late_source_error_through_a_chain_delivers_the_same_prefix() {
    // Covers: SG-I-09 SG-R-RDR-01 SG-R-RDR-05 SG-R-LAY-06
    let d = decoder();
    let p = payload(200_000);
    let inner = gz(&p);
    let outer = gz(&inner);
    let triple = zl(&outer);
    for (header, stream) in [
        (vec!["gzip", "gzip"], &outer),
        (vec!["gzip", "gzip", "deflate"], &triple),
        (vec!["identity", "gzip"], &inner),
    ] {
        for cut in cuts(stream.len()) {
            let o = assert_invariant(&d, &stream[..cut], &header, &format!("cut {cut}/{}", stream.len()));
            assert_eq!(o.kind, Some(ErrorKind::SourceError), "{header:?} cut {cut}");
            assert!(p.starts_with(&o.bytes), "{header:?} cut {cut}: the prefix is wrong");
        }
    }
}

#[test]
fn a_late_corruption_in_a_lower_layer_delivers_the_same_prefix() {
    // Covers: SG-I-09 SG-R-RDR-01 SG-R-LAY-06
    let d = decoder();
    let p = payload(200_000);
    let inner = gz(&p);
    for at in [
        inner.len() / 2,
        inner.len() * 9 / 10,
        inner.len() - 12,
        inner.len() - 8,
        inner.len() - 3,
    ] {
        // the lower (outer) layer is intact, the layer above it is damaged late
        let mut damaged = inner.clone();
        damaged[at] ^= 0x10;
        let stream = gz(&damaged);
        // the source error comes in on top of a damaged inner stream
        let o = assert_invariant(&d, &stream, &["gzip", "gzip"], &format!("flip at {at}"));
        assert!(o.kind.is_some(), "flip at {at} went through");
        // and a source that fails near the end of the damaged chain
        let cut = stream.len() - 3;
        let o = assert_invariant(
            &d,
            &stream[..cut],
            &["gzip", "gzip"],
            &format!("flip at {at}, cut {cut}"),
        );
        assert!(o.kind.is_some());
    }
}

#[cfg(feature = "br")]
fn brotli_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        w.write_all(data).unwrap();
    }
    out
}

#[cfg(feature = "br")]
#[test]
fn a_late_source_error_in_a_brotli_chain_delivers_the_same_prefix() {
    // Covers: SG-I-09 SG-R-RDR-01 SG-R-RDR-05 SG-R-LAY-06
    let d = decoder();
    let p = payload(200_000);
    let stream = gz(&brotli_encode(&p));
    for cut in cuts(stream.len()) {
        let o = assert_invariant(&d, &stream[..cut], &["br", "gzip"], &format!("cut {cut}"));
        assert_eq!(o.kind, Some(ErrorKind::SourceError), "cut {cut}");
        assert!(p.starts_with(&o.bytes));
    }
}
