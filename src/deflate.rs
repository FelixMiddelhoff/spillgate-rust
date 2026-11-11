//! HTTP `deflate` (RFC 9110 section 8.4.1.2), SG-R-CDC-03.
//!
//! `deflate` in HTTP means the zlib format (RFC 1950 around RFC 1951 data), but some senders omit
//! the wrapper. The first two bytes decide: a valid zlib header means zlib, anything else is raw
//! DEFLATE, unless `strict_zlib` forbids the fallback.

use std::io::{self, BufRead, Read};

use crate::codec::{Codec, CodecReader};
use crate::error::Error;
use crate::gzip::{fill, read_exact};
use crate::inflate::Inflater;

const CM_DEFLATE: u8 = 8;
const MAX_CINFO: u8 = 7;
const FLAG_DICT: u8 = 1 << 5;
const CHECK_MODULUS: u16 = 31;
/// Adler-32, big endian.
const TRAILER: usize = 4;

/// RFC 1950: CM = 8, CINFO <= 7 and (CMF * 256 + FLG) divisible by 31.
pub(crate) fn is_zlib_header(cmf: u8, flg: u8) -> bool {
    cmf & 0x0f == CM_DEFLATE && cmf >> 4 <= MAX_CINFO && ((u16::from(cmf) << 8) | u16::from(flg)) % CHECK_MODULUS == 0
}

/// The built-in `deflate` codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeflateCodec {
    strict_zlib: bool,
}

impl DeflateCodec {
    /// With `strict_zlib` the raw DEFLATE fallback is disabled: a stream without a valid zlib
    /// header is `corrupt`.
    pub fn new(strict_zlib: bool) -> DeflateCodec {
        DeflateCodec { strict_zlib }
    }
}

impl Codec for DeflateCodec {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(DeflateReader {
            input,
            strict: self.strict_zlib,
            inflater: None,
            adler: None,
            prefix: [0; 2],
            prefix_pos: 2,
            phase: Phase::Start,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Start,
    Body,
    Finished,
    Failed,
}

struct DeflateReader<'a> {
    input: Box<dyn BufRead + 'a>,
    strict: bool,
    inflater: Option<Box<Inflater>>,
    /// The Adler-32 state; `None` for raw DEFLATE.
    adler: Option<u32>,
    /// The two header bytes of a raw stream: they are data, but were already consumed.
    prefix: [u8; 2],
    prefix_pos: usize,
    phase: Phase,
}

/// The input of the decoder: the unused part of the sniffed prefix, then the real input.
struct Prefixed<'r> {
    prefix: &'r [u8],
    pos: &'r mut usize,
    inner: &'r mut dyn BufRead,
}

impl Read for Prefixed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = self.prefix.get(*self.pos..).unwrap_or(&[]);
        if rest.is_empty() {
            return self.inner.read(buf);
        }
        let n = rest.len().min(buf.len());
        if let (Some(src), Some(dst)) = (rest.get(..n), buf.get_mut(..n)) {
            dst.copy_from_slice(src);
        }
        *self.pos += n;
        Ok(n)
    }
}

impl BufRead for Prefixed<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let rest = self.prefix.get(*self.pos..).unwrap_or(&[]);
        if rest.is_empty() {
            return self.inner.fill_buf();
        }
        Ok(rest)
    }

    fn consume(&mut self, amount: usize) {
        if self.prefix.get(*self.pos..).is_some_and(|rest| !rest.is_empty()) {
            *self.pos = (*self.pos + amount).min(self.prefix.len());
        } else {
            self.inner.consume(amount);
        }
    }
}

impl CodecReader for DeflateReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.phase {
                Phase::Finished => return Ok(0),
                Phase::Failed => return Err(Error::corrupt("deflate: the stream is already known to be invalid")),
                Phase::Start => {
                    if let Err(e) = self.start() {
                        self.phase = Phase::Failed;
                        return Err(e);
                    }
                }
                Phase::Body => {
                    let Some(inflater) = self.inflater.as_mut() else {
                        self.phase = Phase::Failed;
                        return Err(Error::corrupt("deflate: no decoder"));
                    };
                    let mut input = Prefixed {
                        prefix: &self.prefix,
                        pos: &mut self.prefix_pos,
                        inner: &mut *self.input,
                    };
                    match inflater.read(&mut input, buf) {
                        Ok(0) => {
                            let result = self.finish();
                            self.phase = if result.is_ok() { Phase::Finished } else { Phase::Failed };
                            return result.map(|()| 0);
                        }
                        Ok(n) => {
                            if let (Some(adler), Some(data)) = (self.adler.as_mut(), buf.get(..n)) {
                                *adler = adler32(data, *adler);
                            }
                            return Ok(n);
                        }
                        Err(e) => {
                            self.phase = Phase::Failed;
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

impl DeflateReader<'_> {
    fn start(&mut self) -> Result<(), Error> {
        let mut header = [0u8; 2];
        read_exact(&mut *self.input, &mut header, "deflate header")?;
        let [cmf, flg] = header;
        if is_zlib_header(cmf, flg) {
            if flg & FLAG_DICT != 0 {
                return Err(Error::corrupt("deflate: preset dictionaries are not supported"));
            }
            self.adler = Some(1); // the Adler-32 of no data
            self.prefix_pos = 2; // nothing to replay
        } else if self.strict {
            return Err(Error::corrupt("deflate: not a zlib stream"));
        } else {
            // Raw DEFLATE: the two bytes are data.
            self.prefix = header;
            self.prefix_pos = 0;
        }
        self.inflater = Some(Box::new(Inflater::new()));
        self.phase = Phase::Body;
        Ok(())
    }

    /// The DEFLATE data ended: verify the Adler-32 and that nothing follows.
    fn finish(&mut self) -> Result<(), Error> {
        if self.prefix_pos < self.prefix.len() {
            return Err(Error::corrupt("deflate: unexpected data after the end of the stream"));
        }
        if let Some(adler) = self.adler {
            let mut trailer = [0u8; TRAILER];
            read_exact(&mut *self.input, &mut trailer, "deflate trailer")?;
            if u32::from_be_bytes(trailer) != adler {
                return Err(Error::corrupt("deflate: checksum mismatch"));
            }
        }
        if !fill(&mut *self.input)?.is_empty() {
            return Err(Error::corrupt("deflate: unexpected data after the end of the stream"));
        }
        Ok(())
    }
}

const ADLER_MOD: u32 = 65521;
/// The largest block that cannot overflow 2^32 in the sums.
const ADLER_NMAX: usize = 5552;

/// Adler-32 of `data` continuing from `previous` (1 to start).
pub(crate) fn adler32(data: &[u8], previous: u32) -> u32 {
    let mut a = previous & 0xffff;
    let mut b = previous >> 16;
    for block in data.chunks(ADLER_NMAX) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= ADLER_MOD;
        b %= ADLER_MOD;
    }
    (b << 16) | a
}
