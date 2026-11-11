//! SG-R-INP-01 as written (corpus 0.2.0): a codec TAKING the MaxInput+1-th byte is `input_limit`;
//! looking at it is not. Every case runs against several source shapes and read patterns.
//! See `docs/porting-inp-probe.md`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::cell::Cell;
use std::io::{self, BufRead, Read, Write};
use std::rc::Rc;

use common::kind_of;
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::Compression;
use spillgate::{Codec, CodecReader, Decoder, Error, ErrorKind, Limits};

// -- sources -------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Shape {
    Whole,
    OneByte,
    Half,
    Chunks7,
    /// Every second call fails with `Interrupted` (the meter retries).
    Interrupted,
}

const SHAPES: [Shape; 5] = [
    Shape::Whole,
    Shape::OneByte,
    Shape::Half,
    Shape::Chunks7,
    Shape::Interrupted,
];
const PATTERNS: [&[usize]; 5] = [&[1], &[3], &[4096], &[1 << 20], &[1, 7, 4096, 1]];

struct Source {
    data: Vec<u8>,
    pos: usize,
    shape: Shape,
    flip: bool,
    handed: Rc<Cell<usize>>,
}

impl Source {
    fn new(data: &[u8], shape: Shape) -> (Source, Rc<Cell<usize>>) {
        let handed = Rc::new(Cell::new(0));
        let source = Source {
            data: data.to_vec(),
            pos: 0,
            shape,
            flip: false,
            handed: handed.clone(),
        };
        (source, handed)
    }
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = self.data.len() - self.pos;
        let cap = match self.shape {
            Shape::Whole => usize::MAX,
            Shape::OneByte => 1,
            Shape::Half => buf.len().div_ceil(2),
            Shape::Chunks7 => 7,
            Shape::Interrupted => {
                self.flip = !self.flip;
                if self.flip {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                usize::MAX
            }
        };
        let n = buf.len().min(rest).min(cap);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.handed.set(self.handed.get() + n);
        Ok(n)
    }
}

// -- running -------------------------------------------------------------------------------------

fn decoder(max_input: u64) -> Decoder {
    let limits = Limits::new(1 << 30).disable_ratio_limit().max_input(max_input);
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

struct Run {
    kind: Option<ErrorKind>,
    bytes: Vec<u8>,
    handed: usize,
}

fn decode(input: &[u8], max_input: u64, shape: Shape, pattern: &[usize], header: &[&str]) -> Run {
    let (source, handed) = Source::new(input, shape);
    let mut reader = decoder(max_input).reader(source, header).unwrap();
    let mut bytes = Vec::new();
    let mut kind = None;
    for i in 0.. {
        let mut buf = vec![0u8; pattern[i % pattern.len()]];
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) => {
                kind = Some(kind_of(&e));
                // sticky
                assert_eq!(kind_of(&reader.read(&mut buf).unwrap_err()), kind.unwrap());
                break;
            }
        }
    }
    Run {
        kind,
        bytes,
        handed: handed.get(),
    }
}

fn each_run(mut f: impl FnMut(Shape, &[usize])) {
    for shape in SHAPES {
        for pattern in PATTERNS {
            f(shape, pattern);
        }
    }
}

// -- streams -------------------------------------------------------------------------------------

struct Stream {
    name: &'static str,
    header: &'static str,
    plain: Vec<u8>,
    bytes: Vec<u8>,
}

fn gz(data: &[u8], level: Compression) -> Vec<u8> {
    let mut w = GzEncoder::new(Vec::new(), level);
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

fn streams() -> Vec<Stream> {
    let text: Vec<u8> = b"probe the byte after the limit. ".repeat(100);
    let random: Vec<u8> = (0..700u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let zl = |d: &[u8], l| {
        let mut w = ZlibEncoder::new(Vec::new(), l);
        w.write_all(d).unwrap();
        w.finish().unwrap()
    };
    let raw = |d: &[u8], l| {
        let mut w = DeflateEncoder::new(Vec::new(), l);
        w.write_all(d).unwrap();
        w.finish().unwrap()
    };
    let mut two_plain = text.clone();
    two_plain.extend_from_slice(&random);
    let mut two = gz(&text, Compression::default());
    two.extend_from_slice(&gz(&random, Compression::none()));
    #[allow(unused_mut)]
    let mut all = vec![
        Stream {
            name: "gzip",
            header: "gzip",
            plain: text.clone(),
            bytes: gz(&text, Compression::default()),
        },
        Stream {
            name: "gzip stored",
            header: "gzip",
            plain: random.clone(),
            bytes: gz(&random, Compression::none()),
        },
        Stream {
            name: "gzip two members",
            header: "gzip",
            plain: two_plain,
            bytes: two,
        },
        Stream {
            name: "zlib",
            header: "deflate",
            plain: text.clone(),
            bytes: zl(&text, Compression::default()),
        },
        Stream {
            name: "zlib stored",
            header: "deflate",
            plain: random.clone(),
            bytes: zl(&random, Compression::none()),
        },
        Stream {
            name: "raw deflate",
            header: "deflate",
            plain: text.clone(),
            bytes: raw(&text, Compression::default()),
        },
        Stream {
            name: "raw stored",
            header: "deflate",
            plain: random.clone(),
            bytes: raw(&random, Compression::none()),
        },
    ];
    #[cfg(feature = "br")]
    {
        let mut out = Vec::new();
        let params = brotli::enc::BrotliEncoderParams {
            quality: 5,
            ..Default::default()
        };
        brotli::BrotliCompress(&mut &text[..], &mut out, &params).unwrap();
        all.push(Stream {
            name: "brotli",
            header: "br",
            plain: text.clone(),
            bytes: out,
        });
    }
    #[cfg(feature = "zstd")]
    {
        let bytes = ::zstd::bulk::compress(&text, 3).unwrap();
        all.push(Stream {
            name: "zstd",
            header: "zstd",
            plain: text.clone(),
            bytes,
        });
    }
    all
}

// -- tests ---------------------------------------------------------------------------------------

/// (1) and (3): a complete stream of exactly MaxInput bytes followed by data is `corrupt`, whatever
/// the data and wherever the first byte after the stream sits.
#[test]
fn the_byte_after_a_complete_stream_is_corrupt_not_input_limit() {
    // Covers: SG-R-INP-01 SG-R-INP-02 SG-R-CDC-02 SG-R-CDC-03 SG-R-CDC-04 SG-R-CDC-05
    for s in streams() {
        let l = s.bytes.len() as u64;
        let tails: [(&str, Vec<u8>); 3] = [
            ("one zero byte", vec![0]),
            ("1000 zero bytes", vec![0; 1000]),
            ("text", b"trailing garbage that is longer than the probe".to_vec()),
        ];
        for (tail_name, tail) in tails {
            let mut input = s.bytes.clone();
            input.extend_from_slice(&tail);
            each_run(|shape, pattern| {
                for max in [l, l + 1, l + 5] {
                    let r = decode(&input, max, shape, pattern, &[s.header]);
                    assert_eq!(
                        r.kind,
                        Some(ErrorKind::Corrupt),
                        "{} + {tail_name}, max {max} (stream {l}), {shape:?} {pattern:?}",
                        s.name
                    );
                    assert!(r.handed as u64 <= max + 1, "{}: source handed out {}", s.name, r.handed);
                }
            });
        }
    }
}

/// A stream of exactly MaxInput bytes with nothing after it is fine, and so is one byte of room.
#[test]
fn an_exact_stream_with_nothing_after_it_is_ok() {
    // Covers: SG-R-INP-01
    for s in streams() {
        let l = s.bytes.len() as u64;
        each_run(|shape, pattern| {
            for max in [l, l + 1] {
                let r = decode(&s.bytes, max, shape, pattern, &[s.header]);
                assert_eq!(
                    (r.kind, &r.bytes),
                    (None, &s.plain),
                    "{} max {max} {shape:?} {pattern:?}",
                    s.name
                );
            }
        });
    }
}

/// (2): a stream that needs more than MaxInput bytes, with more source behind it, is `input_limit`
/// at every cut point; if the source really ends there it is truncation (`corrupt`).
#[test]
fn a_stream_cut_at_the_limit_depends_on_whether_the_source_goes_on() {
    // Covers: SG-R-INP-01 SG-R-INP-02 SG-R-CDC-06
    for s in streams() {
        let l = s.bytes.len();
        let mut cuts = vec![1, 5, 9, 10, 11, l / 3, l / 2, l - 9, l - 5, l - 1];
        cuts.retain(|&k| k > 0 && k < l);
        cuts.dedup();
        each_run(|shape, pattern| {
            for &k in &cuts {
                let max = k as u64;
                let r = decode(&s.bytes[..k], max, shape, pattern, &[s.header]);
                assert_eq!(r.kind, Some(ErrorKind::Corrupt), "{}: source ends at {k} = max", s.name);

                let mut goes_on = s.bytes.clone();
                goes_on.extend_from_slice(&[0; 50]);
                let r = decode(&goes_on, max, shape, pattern, &[s.header]);
                assert_eq!(
                    r.kind,
                    Some(ErrorKind::InputLimit),
                    "{}: cut at {k} of {l}, {shape:?} {pattern:?}",
                    s.name
                );
                assert!(r.handed <= k + 1, "{}: max {k}, source handed out {}", s.name, r.handed);

                let mut garbage = s.bytes[..k].to_vec();
                garbage.extend_from_slice(&[0xA5; 50]);
                let r = decode(&garbage, max, shape, pattern, &[s.header]);
                assert_eq!(r.kind, Some(ErrorKind::InputLimit), "{}: garbage after {k}", s.name);
            }
        });
    }
}

/// The known edge: a first byte after the stream that could begin another structure is taken.
#[test]
fn a_probe_that_could_start_another_structure_is_taken() {
    // Covers: SG-R-INP-01
    let all = streams();
    let gzip = &all[0];
    let mut input = gzip.bytes.clone();
    input.push(0x1f);
    let l = gzip.bytes.len() as u64;
    each_run(|shape, pattern| {
        assert_eq!(
            decode(&input, l, shape, pattern, &["gzip"]).kind,
            Some(ErrorKind::InputLimit)
        );
        assert_eq!(
            decode(&input, l + 1, shape, pattern, &["gzip"]).kind,
            Some(ErrorKind::Corrupt)
        );
    });
    #[cfg(feature = "zstd")]
    for first in [0x28u8, 0x50, 0x5f] {
        let zstd = all.iter().find(|s| s.name == "zstd").unwrap();
        let mut input = zstd.bytes.clone();
        input.push(first);
        let l = zstd.bytes.len() as u64;
        each_run(|shape, pattern| {
            assert_eq!(
                decode(&input, l, shape, pattern, &["zstd"]).kind,
                Some(ErrorKind::InputLimit)
            );
            assert_eq!(
                decode(&input, l + 1, shape, pattern, &["zstd"]).kind,
                Some(ErrorKind::Corrupt)
            );
        });
    }
}

/// Identity consumes what it passes: one byte more than MaxInput is `input_limit` after exactly
/// MaxInput delivered bytes.
#[test]
fn identity_still_stops_at_the_limit() {
    // Covers: SG-R-INP-01 SG-R-CDC-10
    let body: Vec<u8> = (0..300u32).map(|i| (i * 7 + 1) as u8).collect();
    for header in [&[][..], &["identity"][..]] {
        each_run(|shape, pattern| {
            let l = body.len() - 1;
            let r = decode(&body, l as u64, shape, pattern, header);
            assert_eq!(
                (r.kind, r.bytes.as_slice()),
                (Some(ErrorKind::InputLimit), &body[..l]),
                "{header:?}"
            );
            assert!(r.handed <= l + 1);
            let mut long = body.clone();
            long.extend_from_slice(&[0; 1000]);
            let r = decode(&long, body.len() as u64, shape, pattern, header);
            assert_eq!((r.kind, r.bytes.len()), (Some(ErrorKind::InputLimit), body.len()));
            let r = decode(&body, body.len() as u64, shape, pattern, header);
            assert_eq!((r.kind, &r.bytes), (None, &body));
        });
    }
}

/// Only layer 1 carries MaxInput; trailing data after the outer stream is `corrupt`.
#[test]
fn only_layer_one_carries_max_input() {
    // Covers: SG-R-INP-01 SG-R-INP-02
    let zeros = vec![0u8; 100_000];
    let inner = gz(&zeros, Compression::none()); // about 100 KB
    let outer = gz(&inner, Compression::best()); // a few hundred bytes
    assert!(outer.len() * 10 < inner.len());
    let l = outer.len() as u64;
    each_run(|shape, pattern| {
        let r = decode(&outer, l, shape, pattern, &["gzip, gzip"]);
        assert_eq!((r.kind, r.bytes.len()), (None, zeros.len()));
        for tail in [vec![0u8], vec![0u8; 500]] {
            for max in [l, l + 1] {
                let mut input = outer.clone();
                input.extend_from_slice(&tail);
                let r = decode(&input, max, shape, pattern, &["gzip, gzip"]);
                assert_eq!(r.kind, Some(ErrorKind::Corrupt), "tail {} max {max}", tail.len());
                assert!(r.handed as u64 <= max + 1);
            }
        }
        assert_eq!(
            decode(&outer, l - 1, shape, pattern, &["gzip, gzip"]).kind,
            Some(ErrorKind::InputLimit)
        );
    });
}

// -- the end-of-step check with a custom codec -----------------------------------------------------

const MAX: u64 = 5;

/// Run one codec step on the input; the codec ends after that step.
type Step = fn(&mut dyn BufRead, &mut [u8]) -> Result<usize, Error>;

struct StepCodec(Step);
struct StepReader<'a>(Box<dyn BufRead + 'a>, Step);

impl Codec for StepCodec {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(StepReader(input, self.0))
    }
}
impl CodecReader for StepReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        (self.1)(&mut *self.0, buf)
    }
}

/// Take exactly `n` bytes with fill_buf/consume.
fn take(input: &mut dyn BufRead, mut n: usize) -> Result<(), Error> {
    while n > 0 {
        let view = input.fill_buf().map_err(Error::from_input)?;
        assert!(!view.is_empty(), "unexpected end of input");
        let k = view.len().min(n);
        input.consume(k);
        n -= k;
    }
    Ok(())
}

fn run_step(step: Step, shape: Shape) -> (Option<ErrorKind>, usize) {
    let limits = Limits::new(1 << 20).disable_ratio_limit().max_input(MAX);
    let d = Decoder::builder(limits).codec("x", StepCodec(step)).build().unwrap();
    let (source, handed) = Source::new(&[7u8; 100], shape);
    let mut reader = d.reader(source, &["x"]).unwrap();
    let mut sink = Vec::new();
    let kind = reader.read_to_end(&mut sink).err().map(|e| kind_of(&e));
    (kind, handed.get())
}

#[test]
fn taking_the_probe_is_checked_at_the_end_of_every_codec_step() {
    // Covers: SG-R-INP-01 SG-R-INP-02
    let steps: Vec<(&str, Step, Option<ErrorKind>)> = vec![
        (
            "takes MAX+1 bytes and returns data",
            |i, b| {
                take(i, 6)?;
                b[0] = 1;
                Ok(1)
            },
            Some(ErrorKind::InputLimit),
        ),
        (
            "takes MAX+1 bytes and ends cleanly",
            |i, _| {
                take(i, 6)?;
                Ok(0)
            },
            Some(ErrorKind::InputLimit),
        ),
        (
            "takes MAX+1 bytes and reports corrupt",
            |i, _| {
                take(i, 6)?;
                Err(Error::corrupt("made up"))
            },
            Some(ErrorKind::InputLimit),
        ),
        (
            "takes MAX+1 bytes and asks for more",
            |i, _| {
                take(i, 6)?;
                i.fill_buf().map_err(Error::from_input)?;
                Ok(0)
            },
            Some(ErrorKind::InputLimit),
        ),
        (
            "consumes every view it is shown (a pass-through)",
            |i, _| loop {
                let n = i.fill_buf().map_err(Error::from_input)?.len();
                if n == 0 {
                    return Ok(0);
                }
                i.consume(n);
            },
            Some(ErrorKind::InputLimit),
        ),
        (
            "takes MAX bytes and ends cleanly",
            |i, _| {
                take(i, 5)?;
                Ok(0)
            },
            None,
        ),
        (
            "looks at the probe without consuming it and ends cleanly",
            |i, _| {
                take(i, 5)?;
                assert_eq!(
                    i.fill_buf().map_err(Error::from_input)?.len(),
                    1,
                    "the probe is shown alone"
                );
                Ok(0)
            },
            None,
        ),
        (
            "looks at the probe and reports trailing data",
            |i, _| {
                take(i, 5)?;
                assert_eq!(i.fill_buf().map_err(Error::from_input)?.len(), 1);
                Err(Error::corrupt("trailing data"))
            },
            Some(ErrorKind::Corrupt),
        ),
        (
            "is shown at most MAX bytes before the probe",
            |i, _| {
                let n = i.fill_buf().map_err(Error::from_input)?.len();
                assert!(n <= 5, "the view holds {n} bytes");
                Ok(0)
            },
            None,
        ),
    ];
    for (name, step, want) in steps {
        for shape in SHAPES {
            let (kind, handed) = run_step(step, shape);
            assert_eq!(kind, want, "{name} ({shape:?})");
            assert!(handed as u64 <= MAX + 1, "{name}: source handed out {handed}");
        }
    }
}

/// A source that ends exactly where the stream does gives end of input, not a limit.
#[test]
fn a_source_ending_before_the_stream_does_is_truncation() {
    // Covers: SG-R-INP-01 SG-R-CDC-06
    let s = &streams()[0];
    let l = s.bytes.len();
    each_run(|shape, pattern| {
        let r = decode(&s.bytes[..l - 1], (l - 1) as u64, shape, pattern, &["gzip"]);
        assert_eq!(r.kind, Some(ErrorKind::Corrupt));
    });
}
