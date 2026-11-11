//! gzip (RFC 1952), SG-R-CDC-02.
//!
//! The framing is parsed here, so every size is bounded and every rule of the specification is
//! explicit; the DEFLATE body is decoded by [`Inflater`]. Input is taken through `fill_buf` and
//! `consume` only, and only what is used is consumed.

use std::io::BufRead;

use crate::codec::{Codec, CodecReader};
use crate::error::Error;
use crate::inflate::Inflater;

const ID1: u8 = 0x1f;
const ID2: u8 = 0x8b;
const CM_DEFLATE: u8 = 8;
const FLAG_HCRC: u8 = 1 << 1;
const FLAG_EXTRA: u8 = 1 << 2;
const FLAG_NAME: u8 = 1 << 3;
const FLAG_COMMENT: u8 = 1 << 4;
const RESERVED_FLAGS: u8 = 0xe0; // RFC 1952 requires an error if any is set
const FIXED_HEADER: usize = 10;
const TRAILER: usize = 8;
/// FNAME and FCOMMENT, terminator included.
const MAX_STRING: usize = 512;

/// The built-in `gzip` codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct GzipCodec;

impl Codec for GzipCodec {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(GzipReader {
            input,
            inflater: None,
            crc: 0,
            size: 0,
            phase: Phase::FirstHeader,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// The first member is mandatory.
    FirstHeader,
    /// After a trailer: end of input is a clean end, anything else must be a member.
    NextHeader,
    Body,
    Trailer,
    Finished,
    Failed,
}

struct GzipReader<'a> {
    input: Box<dyn BufRead + 'a>,
    inflater: Option<Box<Inflater>>,
    crc: u32,
    /// Bytes produced in this member, modulo 2^32.
    size: u32,
    phase: Phase,
}

impl CodecReader for GzipReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.phase {
                Phase::Finished => return Ok(0),
                Phase::Failed => return Err(Error::corrupt("gzip: the stream is already known to be invalid")),
                Phase::FirstHeader | Phase::NextHeader => {
                    if let Err(e) = self.start_member() {
                        self.phase = Phase::Failed;
                        return Err(e);
                    }
                    if self.phase == Phase::Finished {
                        return Ok(0);
                    }
                }
                Phase::Body => {
                    let Some(inflater) = self.inflater.as_mut() else {
                        self.phase = Phase::Failed;
                        return Err(Error::corrupt("gzip: no decoder"));
                    };
                    match inflater.read(&mut *self.input, buf) {
                        Ok(0) => self.phase = Phase::Trailer,
                        Ok(n) => {
                            if let Some(data) = buf.get(..n) {
                                self.crc = crc32(data, self.crc);
                            }
                            self.size = self.size.wrapping_add(n as u32);
                            return Ok(n);
                        }
                        Err(e) => {
                            self.phase = Phase::Failed;
                            return Err(e);
                        }
                    }
                }
                Phase::Trailer => {
                    // Bytes already produced were delivered first; the trailer is checked now.
                    if let Err(e) = self.finish_member() {
                        self.phase = Phase::Failed;
                        return Err(e);
                    }
                    self.phase = Phase::NextHeader;
                }
            }
        }
    }
}

impl GzipReader<'_> {
    fn finish_member(&mut self) -> Result<(), Error> {
        let mut trailer = [0u8; TRAILER];
        read_exact(&mut *self.input, &mut trailer, "gzip trailer")?;
        check_trailer(&trailer, self.crc, self.size)
    }

    /// Parse a member header; at `NextHeader` the end of the input is a clean end of the stream.
    fn start_member(&mut self) -> Result<(), Error> {
        if self.phase == Phase::NextHeader {
            match fill(&mut *self.input)?.first() {
                None => {
                    self.phase = Phase::Finished;
                    return Ok(());
                }
                // Cannot start another member: trailing data. The byte was only looked at, it is
                // not consumed (SG-R-INP-01).
                Some(&first) if first != ID1 => return Err(Error::corrupt("gzip: invalid header")),
                Some(_) => {}
            }
        }
        let mut fixed = [0u8; FIXED_HEADER];
        read_exact(&mut *self.input, &mut fixed, "gzip header")?;
        let [id1, id2, method, flags, ..] = fixed;
        if id1 != ID1 || id2 != ID2 || method != CM_DEFLATE {
            return Err(Error::corrupt("gzip: invalid header"));
        }
        if flags & RESERVED_FLAGS != 0 {
            return Err(Error::corrupt("gzip: reserved header flags are set"));
        }
        let mut header_crc = crc32(&fixed, 0);
        if flags & FLAG_EXTRA != 0 {
            header_crc = self.skip_extra(header_crc)?;
        }
        if flags & FLAG_NAME != 0 {
            header_crc = self.skip_string(header_crc, "name")?;
        }
        if flags & FLAG_COMMENT != 0 {
            header_crc = self.skip_string(header_crc, "comment")?;
        }
        if flags & FLAG_HCRC != 0 {
            let mut stored = [0u8; 2];
            read_exact(&mut *self.input, &mut stored, "gzip header checksum")?;
            if u32::from(u16::from_le_bytes(stored)) != header_crc & 0xffff {
                return Err(Error::corrupt("gzip: header checksum mismatch"));
            }
        }
        // One decoder serves all members of the stream: a fresh one per member would allocate its
        // window and tables again for every tiny member.
        match self.inflater.as_mut() {
            Some(inflater) => inflater.reset(),
            None => self.inflater = Some(Box::new(Inflater::new())),
        }
        self.crc = 0;
        self.size = 0;
        self.phase = Phase::Body;
        Ok(())
    }

    /// FEXTRA: at most 65535 bytes by format, skipped without keeping them (SG-R-MEM-01).
    fn skip_extra(&mut self, mut header_crc: u32) -> Result<u32, Error> {
        let mut length_bytes = [0u8; 2];
        read_exact(&mut *self.input, &mut length_bytes, "gzip extra field")?;
        header_crc = crc32(&length_bytes, header_crc);
        let mut remaining = usize::from(u16::from_le_bytes(length_bytes));
        while remaining > 0 {
            let buf = fill(&mut *self.input)?;
            if buf.is_empty() {
                return Err(Error::corrupt("gzip: the extra field ends too early"));
            }
            let n = remaining.min(buf.len());
            if let Some(part) = buf.get(..n) {
                header_crc = crc32(part, header_crc);
            }
            self.input.consume(n);
            remaining -= n;
        }
        Ok(header_crc)
    }

    /// FNAME / FCOMMENT: zero-terminated, at most 512 bytes including the terminator.
    fn skip_string(&mut self, mut header_crc: u32, what: &str) -> Result<u32, Error> {
        let mut left = MAX_STRING;
        while left > 0 {
            let buf = fill(&mut *self.input)?;
            if buf.is_empty() {
                return Err(Error::corrupt(format!("gzip: header {what} ends too early")));
            }
            let window = buf.get(..left.min(buf.len())).unwrap_or(&[]);
            match window.iter().position(|&b| b == 0) {
                Some(end) => {
                    header_crc = crc32(window.get(..=end).unwrap_or(&[]), header_crc);
                    self.input.consume(end + 1);
                    return Ok(header_crc);
                }
                None => {
                    header_crc = crc32(window, header_crc);
                    let n = window.len();
                    self.input.consume(n);
                    left -= n;
                }
            }
        }
        Err(Error::corrupt(format!(
            "gzip: header {what} is longer than {} bytes",
            MAX_STRING - 1
        )))
    }
}

/// Compare the trailer (CRC32, ISIZE; little endian) with what was produced. ISIZE is compared
/// modulo 2^32 and never used as an allowance (SG-R-CDC-07).
pub(crate) fn check_trailer(trailer: &[u8; TRAILER], crc: u32, size: u32) -> Result<(), Error> {
    let [c0, c1, c2, c3, s0, s1, s2, s3] = *trailer;
    if u32::from_le_bytes([c0, c1, c2, c3]) != crc {
        return Err(Error::corrupt("gzip: checksum mismatch"));
    }
    if u32::from_le_bytes([s0, s1, s2, s3]) != size {
        return Err(Error::corrupt("gzip: size mismatch"));
    }
    Ok(())
}

/// `fill_buf` with a failure of the input turned into an [`Error`] (the input meter retries
/// interruptions itself).
pub(crate) fn fill<'b>(input: &'b mut (dyn BufRead + '_)) -> Result<&'b [u8], Error> {
    input.fill_buf().map_err(Error::from_input)
}

/// Fill `dst` from the input, consuming exactly `dst.len()` bytes; a short input is `corrupt`.
pub(crate) fn read_exact(input: &mut (dyn BufRead + '_), dst: &mut [u8], what: &str) -> Result<(), Error> {
    let mut filled = 0usize;
    while filled < dst.len() {
        let buf = fill(&mut *input)?;
        if buf.is_empty() {
            return Err(Error::corrupt(format!("{what} ends too early")));
        }
        let n = buf.len().min(dst.len() - filled);
        if let (Some(src), Some(target)) = (buf.get(..n), dst.get_mut(filled..filled + n)) {
            target.copy_from_slice(src);
        }
        input.consume(n);
        filled += n;
    }
    Ok(())
}

// Const evaluation: every index is below 256 (or 8) by the loop conditions; a mistake fails the build.
#[allow(clippy::indexing_slicing)]
const fn crc_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        tables[0][n] = c;
        n += 1;
    }
    let mut n = 0;
    while n < 256 {
        let mut c = tables[0][n];
        let mut t = 1;
        while t < 8 {
            c = tables[0][(c & 0xff) as usize] ^ (c >> 8);
            tables[t][n] = c;
            t += 1;
        }
        n += 1;
    }
    tables
}

static CRC_TABLES: [[u32; 256]; 8] = crc_tables();

// Every index below is a byte (0..=255) into a table of 256 entries, or a constant into a chunk of
// exactly 8 bytes.
#[allow(clippy::indexing_slicing)]
/// CRC-32 (IEEE, as in gzip) of `data` continuing from `previous` (0 to start).
pub(crate) fn crc32(data: &[u8], previous: u32) -> u32 {
    let mut c = !previous;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let lo = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ c;
        let hi = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        c = CRC_TABLES[7][(lo & 0xff) as usize]
            ^ CRC_TABLES[6][((lo >> 8) & 0xff) as usize]
            ^ CRC_TABLES[5][((lo >> 16) & 0xff) as usize]
            ^ CRC_TABLES[4][(lo >> 24) as usize]
            ^ CRC_TABLES[3][(hi & 0xff) as usize]
            ^ CRC_TABLES[2][((hi >> 8) & 0xff) as usize]
            ^ CRC_TABLES[1][((hi >> 16) & 0xff) as usize]
            ^ CRC_TABLES[0][(hi >> 24) as usize];
    }
    for &b in chunks.remainder() {
        c = CRC_TABLES[0][((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod probe_tests {
    use super::*;
    use crate::deflate::DeflateCodec;
    use crate::error::ErrorKind;

    /// An empty gzip member.
    const GZIP: [u8; 20] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    /// An empty zlib stream.
    const ZLIB: [u8; 8] = [0x78, 0x9c, 3, 0, 0, 0, 0, 1];

    fn run(codec: &dyn Codec, stream: &[u8]) -> (Result<usize, Error>, usize) {
        let mut rest = stream;
        let result = {
            let mut reader = codec.new_reader(Box::new(&mut rest));
            reader.read(&mut [0u8; 16])
        };
        (result, rest.len())
    }

    // Covers: SG-R-INP-01 SG-R-CDC-02 SG-R-CDC-03
    #[test]
    fn trailing_data_is_reported_without_consuming_its_first_byte() {
        let mut input = GZIP.to_vec();
        input.extend_from_slice(&[0, 1, 2]);
        let (result, left) = run(&GzipCodec, &input);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Corrupt);
        assert_eq!(left, 3, "the trailing bytes are all still there");

        let mut input = ZLIB.to_vec();
        input.extend_from_slice(&[0, 1, 2]);
        let (result, left) = run(&DeflateCodec::new(false), &input);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Corrupt);
        assert_eq!(left, 3);

        // a byte that could start another member is taken as such
        let mut input = GZIP.to_vec();
        input.push(0x1f);
        let (result, left) = run(&GzipCodec, &input);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Corrupt);
        assert_eq!(left, 0);
    }
}
