//! Shared helpers for the core tests: small test-only codecs and misbehaving sources.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::Cell;
use std::io::{self, BufRead, Read};
use std::rc::Rc;

use spillgate::{Codec, CodecReader, Decoder, Error, ErrorKind, Limits};

/// The typed kind inside an io error returned by a spillgate reader.
pub fn kind_of(error: &io::Error) -> ErrorKind {
    Error::from_io(error).unwrap_or_else(|| panic!("not a spillgate error: {error:?}")).kind()
}

// -- codecs -----------------------------------------------------------------------------------

/// Copies its input.
pub struct Pass;
struct PassReader<'a>(Box<dyn BufRead + 'a>);
impl CodecReader for PassReader<'_> {
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
impl Codec for Pass {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(PassReader(input))
    }
}

/// Maps every byte through `f`.
pub struct Transform(pub fn(u8) -> u8);
struct TransformReader<'a>(Box<dyn BufRead + 'a>, fn(u8) -> u8);
impl CodecReader for TransformReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = {
            let avail = self.0.fill_buf().map_err(Error::from_input)?;
            let n = avail.len().min(buf.len());
            for (o, i) in buf[..n].iter_mut().zip(&avail[..n]) {
                *o = (self.1)(*i);
            }
            n
        };
        self.0.consume(n);
        Ok(n)
    }
}
impl Codec for Transform {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(TransformReader(input, self.0))
    }
}

/// Emits `factor` copies of every input byte it consumes, lazily, one input byte at a time.
pub struct Expand(pub u64);
struct ExpandReader<'a> {
    input: Box<dyn BufRead + 'a>,
    factor: u64,
    byte: u8,
    left: u64,
}
impl CodecReader for ExpandReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.left == 0 {
            let b = {
                let avail = self.input.fill_buf().map_err(Error::from_input)?;
                match avail.first() {
                    None => return Ok(0),
                    Some(b) => *b,
                }
            };
            self.input.consume(1);
            self.byte = b;
            self.left = self.factor;
        }
        let n = buf.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        buf[..n].fill(self.byte);
        self.left -= n as u64;
        Ok(n)
    }
}
impl Codec for Expand {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(ExpandReader { input, factor: self.0, byte: 0, left: 0 })
    }
}

/// A bomb: ignores its input and emits `total` zero bytes, then ends cleanly. Consumes nothing.
pub struct Zeros(pub u64);
struct ZerosReader {
    left: u64,
}
impl CodecReader for ZerosReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = buf.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        buf[..n].fill(0);
        self.left -= n as u64;
        Ok(n)
    }
}
impl Codec for Zeros {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(ZerosReader { left: self.0 })
    }
}

/// Panics after delivering `after` bytes of zeros.
pub struct Panicker(pub usize);
struct PanicReader {
    left: usize,
}
impl CodecReader for PanicReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.left == 0 {
            panic!("test codec panics on purpose");
        }
        let n = buf.len().min(self.left);
        buf[..n].fill(7);
        self.left -= n;
        Ok(n)
    }
}
impl Codec for Panicker {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(PanicReader { left: self.0 })
    }
}

/// Panics while it is constructed.
pub struct PanicOnNew;
impl Codec for PanicOnNew {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        panic!("test codec cannot be constructed");
    }
}

/// Claims to have written `buf.len() + extra` bytes.
pub struct OverReport(pub usize);
struct OverReportReader(usize);
impl CodecReader for OverReportReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        buf.fill(1);
        Ok(buf.len() + self.0)
    }
}
impl Codec for OverReport {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(OverReportReader(self.0))
    }
}

/// Always fails with the given kind.
pub struct Fails(pub ErrorKind);
struct FailsReader(ErrorKind);
impl CodecReader for FailsReader {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::new(self.0, "the test codec fails"))
    }
}
impl Codec for Fails {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(FailsReader(self.0))
    }
}

/// Consumes `n` input bytes (fewer at the end) and emits the first of them: a shrinking layer.
pub struct Shrink(pub usize);
struct ShrinkReader<'a>(Box<dyn BufRead + 'a>, usize);
impl CodecReader for ShrinkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut got = 0;
        let mut first = 0;
        while got < self.1 {
            let take = {
                let avail = self.0.fill_buf().map_err(Error::from_input)?;
                if avail.is_empty() {
                    break;
                }
                if got == 0 {
                    first = avail[0];
                }
                avail.len().min(self.1 - got)
            };
            self.0.consume(take);
            got += take;
        }
        if got == 0 {
            return Ok(0);
        }
        buf[0] = first;
        Ok(1)
    }
}
impl Codec for Shrink {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(ShrinkReader(input, self.0))
    }
}

/// Copies exactly `n` input bytes and then ends without looking at the input again (so it never
/// probes beyond its stream). Fewer than `n` bytes in the input are `corrupt`.
pub struct TakeN(pub usize);
struct TakeNReader<'a>(Box<dyn BufRead + 'a>, usize);
impl CodecReader for TakeNReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.1 == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = {
            let avail = self.0.fill_buf().map_err(Error::from_input)?;
            if avail.is_empty() {
                return Err(Error::corrupt("take: the stream ends too early"));
            }
            let n = avail.len().min(buf.len()).min(self.1);
            buf[..n].copy_from_slice(&avail[..n]);
            n
        };
        self.0.consume(n);
        self.1 -= n;
        Ok(n)
    }
}
impl Codec for TakeN {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(TakeNReader(input, self.0))
    }
}

/// Reads and consumes its input one byte at a time and returns one byte per call, and reports every
/// input failure as `corrupt` (it swallows the real cause).
pub struct ByteByByte;
struct ByteReader<'a>(Box<dyn BufRead + 'a>);
impl CodecReader for ByteReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let b = match self.0.fill_buf() {
            Err(_) => return Err(Error::corrupt("input failed (swallowed)")),
            Ok(avail) => match avail.first() {
                None => return Ok(0),
                Some(b) => *b,
            },
        };
        self.0.consume(1);
        buf[0] = b;
        Ok(1)
    }
}
impl Codec for ByteByByte {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(ByteReader(input))
    }
}

/// The stored-only mini format: chunks of `[len: u16 LE][len bytes]`, a chunk of length 0 ends the
/// data, then the four trailer bytes `END!`, then nothing. A missing byte anywhere, a wrong trailer
/// and trailing bytes are `corrupt`.
pub struct Stored;
pub const TRAILER: &[u8; 4] = b"END!";

/// Encode `payload` in the stored format with chunks of at most `chunk` bytes.
pub fn stored(payload: &[u8], chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for part in payload.chunks(chunk.clamp(1, 65535)) {
        out.extend_from_slice(&(part.len() as u16).to_le_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(TRAILER);
    out
}

enum StoredState {
    Len,
    Body(usize),
    Trailer,
    Done,
}
struct StoredReader<'a> {
    input: Box<dyn BufRead + 'a>,
    state: StoredState,
}
impl StoredReader<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        let b = {
            let avail = self.input.fill_buf().map_err(Error::from_input)?;
            *avail.first().ok_or_else(|| Error::corrupt("stored: the stream ends too early"))?
        };
        self.input.consume(1);
        Ok(b)
    }
}
impl CodecReader for StoredReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            match self.state {
                StoredState::Len => {
                    let lo = self.byte()?;
                    let hi = self.byte()?;
                    let len = usize::from(u16::from_le_bytes([lo, hi]));
                    self.state = if len == 0 { StoredState::Trailer } else { StoredState::Body(len) };
                }
                StoredState::Body(left) => {
                    let n = {
                        let avail = self.input.fill_buf().map_err(Error::from_input)?;
                        if avail.is_empty() {
                            return Err(Error::corrupt("stored: the stream ends too early"));
                        }
                        let n = avail.len().min(buf.len()).min(left);
                        buf[..n].copy_from_slice(&avail[..n]);
                        n
                    };
                    self.input.consume(n);
                    self.state = if n == left { StoredState::Len } else { StoredState::Body(left - n) };
                    return Ok(n);
                }
                StoredState::Trailer => {
                    for expected in TRAILER {
                        if self.byte()? != *expected {
                            return Err(Error::corrupt("stored: bad trailer"));
                        }
                    }
                    let extra = !self.input.fill_buf().map_err(Error::from_input)?.is_empty();
                    if extra {
                        return Err(Error::corrupt("stored: bytes after the trailer"));
                    }
                    self.state = StoredState::Done;
                }
                StoredState::Done => return Ok(0),
            }
        }
    }
}
impl Codec for Stored {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(StoredReader { input, state: StoredState::Len })
    }
}

// -- sources ----------------------------------------------------------------------------------

/// Counters shared with a source after it has been moved into a reader.
#[derive(Clone, Default)]
pub struct Counters {
    pub bytes: Rc<Cell<usize>>,
    pub calls: Rc<Cell<usize>>,
    pub largest_request: Rc<Cell<usize>>,
    pub requested: Rc<Cell<usize>>,
}

/// Hands out at most `step` bytes per call and counts what it gave.
pub struct Chunked {
    data: Vec<u8>,
    pos: usize,
    step: usize,
    pub counters: Counters,
}
impl Chunked {
    pub fn new(data: impl Into<Vec<u8>>, step: usize) -> Chunked {
        Chunked { data: data.into(), pos: 0, step: step.max(1), counters: Counters::default() }
    }
}
impl Read for Chunked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let c = &self.counters;
        c.calls.set(c.calls.get() + 1);
        c.largest_request.set(c.largest_request.get().max(buf.len()));
        c.requested.set(c.requested.get() + buf.len());
        let n = buf.len().min(self.step).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        c.bytes.set(c.bytes.get() + n);
        Ok(n)
    }
}

/// Delivers `data`, then fails with `error` on every further call.
pub struct FailAfter {
    data: Vec<u8>,
    pos: usize,
    make: fn() -> io::Error,
    pub calls: Rc<Cell<usize>>,
}
impl FailAfter {
    pub fn new(data: impl Into<Vec<u8>>, make: fn() -> io::Error) -> FailAfter {
        FailAfter { data: data.into(), pos: 0, make, calls: Rc::default() }
    }
}
impl Read for FailAfter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        if self.pos >= self.data.len() {
            return Err((self.make)());
        }
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Is interrupted `times` times before every real read.
pub struct Interrupted<R> {
    inner: R,
    times: usize,
    left: usize,
}
impl<R> Interrupted<R> {
    pub fn new(inner: R, times: usize) -> Interrupted<R> {
        Interrupted { inner, times, left: times }
    }
}
impl<R: Read> Read for Interrupted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left > 0 {
            self.left -= 1;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.left = self.times;
        self.inner.read(buf)
    }
}

/// Claims `extra` more bytes than the buffer holds.
pub struct OverReportingSource(pub usize);
impl Read for OverReportingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(9);
        Ok(buf.len() + self.0)
    }
}

/// Never makes progress: every call is interrupted.
pub struct AlwaysInterrupted(pub Rc<Cell<usize>>);
impl Read for AlwaysInterrupted {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        self.0.set(self.0.get() + 1);
        Err(io::Error::from(io::ErrorKind::Interrupted))
    }
}

/// An endless source of `byte`s that counts what it gave.
pub struct Endless(pub u8, pub Rc<Cell<u64>>);
impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(self.0);
        self.1.set(self.1.get() + buf.len() as u64);
        Ok(buf.len())
    }
}

// -- running ----------------------------------------------------------------------------------

/// A decoder with the test codecs registered: `pass`, `up` (+1), `dbl` (x2), `stored`, `expand10`,
/// `expand1000`, `expand2000`, `br` and `zstd` (both pass-through), under `limits`.
pub fn decoder(limits: Limits) -> Decoder {
    Decoder::builder(limits)
        .codec("pass", Pass)
        .codec("up", Transform(|b| b.wrapping_add(1)))
        .codec("dbl", Transform(|b| b.wrapping_mul(2)))
        .codec("stored", Stored)
        .codec("expand10", Expand(10))
        .codec("expand1000", Expand(1000))
        .codec("expand2000", Expand(2000))
        .codec("bytes", ByteByByte)
        .codec("shrink10", Shrink(10))
        .codec("shrink1000", Shrink(1000))
        .codec("br", Pass)
        .codec("zstd", Pass)
        .build()
        .unwrap()
}

/// Loose limits that never get in the way: 1 GiB output, no ratio check.
pub fn loose() -> Limits {
    Limits::new(1 << 30).disable_ratio_limit()
}

/// The outcome of reading to the end with a fixed read size: the bytes delivered before the
/// outcome, and the error kind if any. A construction error counts as an outcome with no bytes.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Outcome {
    pub bytes: Vec<u8>,
    pub kind: Option<ErrorKind>,
}

pub fn drain<R: Read>(reader: &mut R, read_size: usize) -> Outcome {
    let mut bytes = Vec::new();
    let mut buf = vec![0u8; read_size.min(1 << 20)];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Outcome { bytes, kind: None },
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(e) => return Outcome { bytes, kind: Some(kind_of(&e)) },
        }
    }
}

/// Decode `data` through `header` with `decoder` and the given read size.
pub fn run(decoder: &Decoder, data: &[u8], header: &[&str], read_size: usize) -> Outcome {
    match decoder.reader(data, header) {
        Err(e) => Outcome { bytes: Vec::new(), kind: Some(e.kind()) },
        Ok(mut reader) => {
            let out = drain(&mut reader, read_size);
            reader.close();
            out
        }
    }
}

/// Deterministic xorshift generator.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}
