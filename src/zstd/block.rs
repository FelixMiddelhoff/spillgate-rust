//! One zstd frame body: blocks, literals, sequences (RFC 8878 sections 3.1.1.2 to 3.1.1.4).
//!
//! The decoder keeps what the format lets blocks share: the window of recent output, the three
//! repeat offsets, the last Huffman table and the last sequence tables. It decodes one block at a
//! time into a scratch buffer, and a block never regenerates more than 128 KiB, so memory per step
//! is constant. The window is only written when a block is complete, so a match reads either the
//! block under construction or the history in the ring.

use std::sync::OnceLock;

use super::bits::BackwardBits;
use super::fse::{build_table, read_table, rle_table, FseTable};
use super::huffman::{decode_stream, read_huffman_table, HuffmanTable};
use crate::error::{Error, ErrorKind};

/// The largest block of any frame.
pub(crate) const BLOCK_MAX: usize = 128 * 1024;

const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

const LL_DEFAULT: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
];
const ML_DEFAULT: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

struct Defaults {
    ll: FseTable,
    ml: FseTable,
    of: FseTable,
}

fn predefined() -> Result<&'static Defaults, Error> {
    static DEFAULTS: OnceLock<Option<Defaults>> = OnceLock::new();
    DEFAULTS
        .get_or_init(|| {
            Some(Defaults {
                ll: build_table(&LL_DEFAULT, 6).ok()?,
                ml: build_table(&ML_DEFAULT, 6).ok()?,
                of: build_table(&OF_DEFAULT, 5).ok()?,
            })
        })
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::Internal, "zstd: the predefined tables are invalid"))
}

fn corrupt(message: &'static str) -> Error {
    Error::corrupt(message)
}

/// The window of recent output, a ring of the declared size that grows with the output.
pub(crate) struct Window {
    /// Grows with the output up to `ring`, so a frame that produces little costs little.
    buf: Vec<u8>,
    /// The ring size (the declared window, at least 1). Positions wrap here, not at `buf.len()`.
    ring: usize,
    /// Write position, always `< ring`. Until the ring is full this is the number of bytes written.
    pos: usize,
    /// Bytes produced by the frame so far.
    total: u64,
}

impl Window {
    pub(crate) fn new(window_size: usize) -> Window {
        Window {
            buf: Vec::new(),
            ring: window_size.max(1),
            pos: 0,
            total: 0,
        }
    }

    /// Bytes produced by the frame so far.
    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    /// Bytes of heap held by the window (test accounting).
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[cfg(test)]
    pub(crate) fn pos_for_test(&self) -> usize {
        self.pos
    }

    #[cfg(test)]
    pub(crate) fn copy_history_for_test(&self, d: usize, n: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        self.copy_history(d, n, out)
    }

    /// Make room for `extra` more bytes without allocating the declared window up front: a hostile
    /// header must not turn a few input bytes into a large allocation (SG-R-RAT-02). Until the
    /// window is full, nothing has wrapped, so the position equals the bytes produced.
    fn ensure(&mut self, extra: usize) -> Result<(), Error> {
        let wanted = self.total.saturating_add(extra as u64).min(self.ring as u64);
        let target = usize::try_from(wanted).unwrap_or(self.ring).max(1);
        let len = self.buf.len();
        if len >= target {
            return Ok(());
        }
        let grown = target.max(len.saturating_mul(2)).min(self.ring);
        self.buf
            .try_reserve_exact(grown - len)
            .map_err(|_| Error::new(ErrorKind::MemoryLimit, "zstd: the window could not be allocated"))?;
        self.buf.resize(grown, 0);
        Ok(())
    }

    /// Append a finished block to the window.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.ensure(bytes.len())?;
        let n = self.buf.len();
        let internal = || Error::new(ErrorKind::Internal, "zstd: the window ring is inconsistent");
        if bytes.len() >= n && n == self.ring {
            // the newest n bytes fill the whole ring; the oldest of them sits at index 0
            let newest = bytes.get(bytes.len() - n..).ok_or_else(internal)?;
            self.buf.copy_from_slice(newest);
            self.pos = 0;
        } else {
            let start = self.pos;
            let first = bytes.len().min(n.checked_sub(start).ok_or_else(internal)?);
            let (head, rest) = bytes.split_at(first);
            self.buf
                .get_mut(start..start + first)
                .ok_or_else(internal)?
                .copy_from_slice(head);
            self.buf
                .get_mut(..rest.len())
                .ok_or_else(internal)?
                .copy_from_slice(rest);
            self.pos = (start + bytes.len()) % self.ring;
        }
        self.total = self.total.saturating_add(bytes.len() as u64);
        Ok(())
    }

    /// Append `n` bytes to `out`, taken from the history `d` bytes before the write position.
    /// The caller guarantees `n <= d <= min(total, ring)`.
    fn copy_history(&self, d: usize, n: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let internal = || Error::new(ErrorKind::Internal, "zstd: the window ring is inconsistent");
        let idx = if d <= self.pos {
            self.pos - d
        } else {
            (self.pos + self.ring).checked_sub(d).ok_or_else(internal)?
        };
        let first = n.min(self.buf.len().checked_sub(idx).ok_or_else(internal)?);
        out.extend_from_slice(self.buf.get(idx..idx + first).ok_or_else(internal)?);
        let rest = n - first;
        if rest > 0 {
            out.extend_from_slice(self.buf.get(..rest).ok_or_else(internal)?);
        }
        Ok(())
    }
}

/// The state of one frame: window, repeat offsets and the tables later blocks may reuse.
pub(crate) struct Frame {
    window_size: usize,
    window: Window,
    repeat: [u64; 3],
    huffman: Option<HuffmanTable>,
    ll: Option<FseTable>,
    of: Option<FseTable>,
    ml: Option<FseTable>,
}

impl Frame {
    /// `window_size` is the window the frame declared (already checked against the cap).
    pub(crate) fn new(window_size: usize) -> Frame {
        Frame {
            window_size,
            window: Window::new(window_size),
            repeat: [1, 4, 8],
            huffman: None,
            ll: None,
            of: None,
            ml: None,
        }
    }

    /// Bytes regenerated so far in this frame.
    pub(crate) fn total(&self) -> u64 {
        self.window.total()
    }

    #[cfg(test)]
    pub(crate) fn window_capacity(&self) -> usize {
        self.window.capacity()
    }

    /// Largest block this frame may contain: min(window, 128 KiB) (RFC 8878 3.1.1.2.3).
    pub(crate) fn block_max(&self) -> usize {
        self.window_size.min(BLOCK_MAX)
    }

    /// A finished block joins the window.
    pub(crate) fn push(&mut self, block: &[u8]) -> Result<(), Error> {
        self.window.push(block)
    }

    /// Decode a compressed block (type 2) into `out`. `lits` is scratch for the literals section.
    pub(crate) fn compressed(&mut self, content: &[u8], lits: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<(), Error> {
        let used = self.read_literals(content, lits)?;
        let section = content
            .get(used..)
            .ok_or_else(|| corrupt("zstd: a sequences section is missing"))?;
        self.read_sequences(section, lits, out)
    }

    // -- literals -------------------------------------------------------------------

    fn read_literals(&mut self, block: &[u8], lits: &mut Vec<u8>) -> Result<usize, Error> {
        let b0 = *block
            .first()
            .ok_or_else(|| corrupt("zstd: an empty compressed block"))?;
        let kind = b0 & 3;
        let size_format = (b0 >> 2) & 3;
        let byte = |i: usize| -> Result<u32, Error> {
            block
                .get(i)
                .map(|&b| u32::from(b))
                .ok_or_else(|| corrupt("zstd: a literals section ends too early"))
        };
        let b0 = u32::from(b0);
        let block_max = self.block_max();
        lits.clear();

        if kind == 0 || kind == 1 {
            let (regen, header) = match size_format {
                0 | 2 => (b0 >> 3, 1usize),
                1 => ((b0 >> 4) + (byte(1)? << 4), 2),
                _ => ((b0 >> 4) + (byte(1)? << 4) + (byte(2)? << 12), 3),
            };
            let regen = regen as usize;
            if regen > block_max {
                return Err(corrupt("zstd: a literals section is larger than a block"));
            }
            if kind == 0 {
                let end = header + regen;
                let raw = block
                    .get(header..end)
                    .ok_or_else(|| corrupt("zstd: a literals section ends too early"))?;
                lits.extend_from_slice(raw);
                return Ok(end);
            }
            let fill = byte(header)? as u8;
            lits.resize(regen, fill);
            return Ok(header + 1);
        }

        // compressed (2) or treeless (3): sizes of 10, 10, 14 or 18 bits
        let (regen, compressed_size, header, streams) = match size_format {
            0 | 1 => {
                let v = b0 + (byte(1)? << 8) + (byte(2)? << 16);
                (
                    (v >> 4) & 0x3ff,
                    (v >> 14) & 0x3ff,
                    3usize,
                    if size_format == 0 { 1 } else { 4 },
                )
            }
            2 => {
                let v = u64::from(b0)
                    + (u64::from(byte(1)?) << 8)
                    + (u64::from(byte(2)?) << 16)
                    + (u64::from(byte(3)?) << 24);
                (((v >> 4) & 0x3fff) as u32, (v >> 18) as u32, 4, 4)
            }
            _ => {
                let v = u64::from(b0)
                    + (u64::from(byte(1)?) << 8)
                    + (u64::from(byte(2)?) << 16)
                    + (u64::from(byte(3)?) << 24)
                    + (u64::from(byte(4)?) << 32);
                (((v >> 4) & 0x3ffff) as u32, ((v >> 22) & 0x3ffff) as u32, 5, 4)
            }
        };
        let regen = regen as usize;
        let compressed_size = compressed_size as usize;
        if regen > block_max {
            return Err(corrupt("zstd: a literals section is larger than a block"));
        }
        let end = header + compressed_size;
        let mut body = block
            .get(header..end)
            .ok_or_else(|| corrupt("zstd: a literals section ends too early"))?;

        if kind == 2 {
            let (table, used) = read_huffman_table(body)?;
            self.huffman = Some(table);
            body = body
                .get(used..)
                .ok_or_else(|| corrupt("zstd: a Huffman tree description ends too early"))?;
        }
        let table = self
            .huffman
            .as_ref()
            .ok_or_else(|| corrupt("zstd: treeless literals without an earlier Huffman table"))?;
        lits.resize(regen, 0);
        if streams == 1 {
            decode_stream(table, body, lits)?;
        } else {
            let jump = body
                .get(..6)
                .ok_or_else(|| corrupt("zstd: a literals jump table ends too early"))?;
            let size = |i: usize| -> usize {
                let lo = jump.get(2 * i).copied().unwrap_or(0);
                let hi = jump.get(2 * i + 1).copied().unwrap_or(0);
                usize::from(lo) | (usize::from(hi) << 8)
            };
            let (s1, s2, s3) = (size(0), size(1), size(2));
            let rest = (body.len() - 6)
                .checked_sub(s1 + s2 + s3)
                .ok_or_else(|| corrupt("zstd: literal stream sizes exceed the section"))?;
            let part = regen.div_ceil(4);
            let last = regen
                .checked_sub(3 * part)
                .ok_or_else(|| corrupt("zstd: a literals section is too small for four streams"))?;
            let mut data = body.get(6..).unwrap_or(&[]);
            let mut out: &mut [u8] = lits.as_mut_slice();
            for (stream_size, count) in [(s1, part), (s2, part), (s3, part), (rest, last)] {
                let (stream, remaining) = data
                    .split_at_checked(stream_size)
                    .ok_or_else(|| corrupt("zstd: literal stream sizes exceed the section"))?;
                data = remaining;
                let (dst, tail) = std::mem::take(&mut out)
                    .split_at_mut_checked(count)
                    .ok_or_else(|| corrupt("zstd: a literals section is too small for four streams"))?;
                out = tail;
                decode_stream(table, stream, dst)?;
            }
        }
        Ok(end)
    }

    // -- sequences ------------------------------------------------------------------

    fn read_sequences(&mut self, section: &[u8], lits: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.clear();
        let early = || corrupt("zstd: a sequences header ends too early");
        let byte = |i: usize| -> Result<u32, Error> { section.get(i).map(|&b| u32::from(b)).ok_or_else(early) };
        let b0 = byte(0).map_err(|_| corrupt("zstd: a sequences section is missing"))?;
        let mut at = 1usize;
        let count;
        if b0 == 0 {
            // no sequences: the literals are the whole block, and nothing may follow the count
            if section.len() != 1 {
                return Err(corrupt("zstd: bytes follow a sequences section without sequences"));
            }
            out.extend_from_slice(lits);
            return Ok(());
        } else if b0 < 128 {
            count = b0;
        } else if b0 < 255 {
            count = ((b0 - 128) << 8) + byte(1)?;
            at = 2;
        } else {
            count = byte(1)? + (byte(2)? << 8) + 0x7f00;
            at = 3;
        }
        let modes = byte(at)?;
        at += 1;
        if modes & 3 != 0 {
            return Err(corrupt("zstd: reserved bits are set in the symbol compression modes"));
        }

        let defaults = predefined()?;
        let mut read = |mode: u32,
                        max_log: u32,
                        max_symbol: usize,
                        fallback: &FseTable,
                        previous: Option<FseTable>|
         -> Result<FseTable, Error> {
            match mode {
                0 => Ok(fallback.clone()),
                1 => {
                    let symbol = *section
                        .get(at)
                        .ok_or_else(|| corrupt("zstd: an RLE table ends too early"))?;
                    at += 1;
                    if usize::from(symbol) > max_symbol {
                        return Err(corrupt("zstd: an RLE table names an impossible symbol"));
                    }
                    Ok(rle_table(symbol))
                }
                2 => {
                    let rest = section.get(at..).ok_or_else(early)?;
                    let (table, used) = read_table(rest, max_log, max_symbol)?;
                    at += used;
                    Ok(table)
                }
                _ => previous.ok_or_else(|| corrupt("zstd: a repeated table without an earlier one")),
            }
        };
        let ll = read(modes >> 6, 9, 35, &defaults.ll, self.ll.take())?;
        let of = read((modes >> 4) & 3, 8, 31, &defaults.of, self.of.take())?;
        let ml = read((modes >> 2) & 3, 9, 52, &defaults.ml, self.ml.take())?;
        let stream = section.get(at..).ok_or_else(early)?;
        let result = self.execute(stream, count, lits, out, &ll, &of, &ml);
        self.ll = Some(ll);
        self.of = Some(of);
        self.ml = Some(ml);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn execute(
        &mut self,
        stream: &[u8],
        count: u32,
        lits: &[u8],
        out: &mut Vec<u8>,
        ll: &FseTable,
        of: &FseTable,
        ml: &FseTable,
    ) -> Result<(), Error> {
        let mut bits = BackwardBits::new(stream)?;
        let mut ll_state = bits.read(ll.accuracy_log);
        let mut of_state = bits.read(of.accuracy_log);
        let mut ml_state = bits.read(ml.accuracy_log);

        let limit = self.block_max() as u64;
        let window_size = self.window_size as u64;
        let history = self.window.total();
        let mut lit_pos = 0usize;
        let too_big = || corrupt("zstd: a block regenerates more than its maximum");

        for i in 0..count {
            let ll_e = ll.entry(ll_state)?;
            let of_e = of.entry(of_state)?;
            let ml_e = ml.entry(ml_state)?;
            let (of_code, ml_code, ll_code) = (
                usize::from(of_e.symbol),
                usize::from(ml_e.symbol),
                usize::from(ll_e.symbol),
            );
            if of_code > 31 || ml_code > 52 || ll_code > 35 {
                return Err(corrupt("zstd: a sequence names an impossible code"));
            }
            let offset_value = (1u64 << of_code) + bits.read(of_code as u32);
            let ml_bits = u32::from(ML_BITS.get(ml_code).copied().unwrap_or(0));
            let match_length = u64::from(ML_BASE.get(ml_code).copied().unwrap_or(0)) + bits.read(ml_bits);
            let ll_bits = u32::from(LL_BITS.get(ll_code).copied().unwrap_or(0));
            let literal_length = u64::from(LL_BASE.get(ll_code).copied().unwrap_or(0)) + bits.read(ll_bits);

            // repeat offsets (RFC 8878 3.1.1.5)
            let offset;
            let [r0, r1, r2] = self.repeat;
            if offset_value > 3 {
                offset = offset_value - 3;
                self.repeat = [offset, r0, r1];
            } else {
                let mut index = offset_value;
                if literal_length == 0 {
                    index += 1;
                }
                match index {
                    1 => offset = r0,
                    2 => {
                        offset = r1;
                        self.repeat = [r1, r0, r2];
                    }
                    3 => {
                        offset = r2;
                        self.repeat = [r2, r0, r1];
                    }
                    _ => {
                        offset = r0 - 1;
                        if offset == 0 {
                            return Err(corrupt("zstd: a repeat offset of zero"));
                        }
                        self.repeat = [offset, r0, r1];
                    }
                }
            }

            if (out.len() as u64) + literal_length + match_length > limit {
                return Err(too_big());
            }
            let ll_len = literal_length as usize;
            let lit_end = lit_pos + ll_len;
            let chunk = lits
                .get(lit_pos..lit_end)
                .ok_or_else(|| corrupt("zstd: a sequence uses more literals than the block has"))?;
            out.extend_from_slice(chunk);
            lit_pos = lit_end;

            // match
            if offset == 0 || offset > history + out.len() as u64 || offset > window_size {
                return Err(corrupt("zstd: a match reaches before the start of the window"));
            }
            self.copy_match(offset as usize, match_length as usize, out)?;

            if i + 1 < count {
                ll_state = u64::from(ll_e.baseline) + bits.read(u32::from(ll_e.nb_bits));
                ml_state = u64::from(ml_e.baseline) + bits.read(u32::from(ml_e.nb_bits));
                of_state = u64::from(of_e.baseline) + bits.read(u32::from(of_e.nb_bits));
            }
        }
        if bits.remaining != 0 {
            return Err(corrupt("zstd: the sequence bit stream was not consumed exactly"));
        }

        // the literals that no sequence used come last
        let tail = lits.get(lit_pos..).ok_or_else(too_big)?;
        if (out.len() as u64) + tail.len() as u64 > limit {
            return Err(too_big());
        }
        out.extend_from_slice(tail);
        Ok(())
    }

    /// Append a match of `len` bytes at distance `offset` to the block under construction. The
    /// caller checked `offset <= window + out.len()` and `offset <= window_size`.
    fn copy_match(&self, offset: usize, len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut remaining = len;
        let bad = || corrupt("zstd: a match reaches before the start of the window");
        while remaining > 0 {
            if offset <= out.len() {
                let start = out.len() - offset;
                if offset == 1 {
                    let b = *out.get(start).ok_or_else(bad)?;
                    out.resize(out.len() + remaining, b);
                    remaining = 0;
                } else {
                    let n = remaining.min(offset);
                    out.extend_from_within(start..start + n);
                    remaining -= n;
                }
            } else {
                // `d` bytes of the match lie in the history before this block
                let d = offset - out.len();
                let n = remaining.min(d);
                self.window.copy_history(d, n, out)?;
                remaining -= n;
            }
        }
        Ok(())
    }
}
