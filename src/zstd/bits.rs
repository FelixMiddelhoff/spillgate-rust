//! Bit readers for zstd (RFC 8878): forward for table descriptions, backward for the data.

use crate::error::Error;

/// Little-endian value of `n <= 32` bits starting at bit `pos` of `bytes`; bits past the end read as 0.
fn bits_at(bytes: &[u8], pos: u64, n: u32) -> u64 {
    if n == 0 {
        return 0;
    }
    let shift = (pos & 7) as u32;
    let first = match usize::try_from(pos >> 3) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // at most 5 bytes: 40 bits
    let count = ((shift + n - 1) >> 3) as usize + 1;
    let mut value = 0u64;
    for k in 0..count {
        let byte = first.checked_add(k).and_then(|i| bytes.get(i)).copied().unwrap_or(0);
        value |= u64::from(byte) << (8 * k as u32);
    }
    (value >> shift) & ((1u64 << n) - 1)
}

/// Reads bits starting at the least significant bit of the first byte (FSE table descriptions).
pub(crate) struct ForwardBits<'a> {
    bytes: &'a [u8],
    pos: u64,
}

impl<'a> ForwardBits<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> ForwardBits<'a> {
        ForwardBits { bytes, pos: 0 }
    }

    pub(crate) fn read(&mut self, n: u32) -> u32 {
        let value = bits_at(self.bytes, self.pos, n);
        self.pos += u64::from(n);
        // n <= 32 so the value fits
        u32::try_from(value).unwrap_or(0)
    }

    /// Put back `n` bits just read.
    pub(crate) fn unread(&mut self, n: u32) {
        self.pos = self.pos.saturating_sub(u64::from(n));
    }

    /// The number of bytes touched so far (the position rounded up to a whole byte).
    pub(crate) fn bytes_used(&self) -> usize {
        usize::try_from(self.pos.div_ceil(8)).unwrap_or(usize::MAX)
    }

    /// True if more bits were read than the buffer holds.
    pub(crate) fn overrun(&self) -> bool {
        self.pos > (self.bytes.len() as u64).saturating_mul(8)
    }
}

/// Reads bits from the end of a buffer towards its start (Huffman streams and sequences). The last
/// byte holds a padding sentinel: its highest set bit marks where the data ends. Reading past the
/// start yields zero bits, and `remaining` goes negative so the caller can tell.
pub(crate) struct BackwardBits<'a> {
    bytes: &'a [u8],
    /// Bits left to read. Negative after reading past the start.
    pub(crate) remaining: i64,
}

impl<'a> BackwardBits<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<BackwardBits<'a>, Error> {
        let last = match bytes.last() {
            Some(&b) if b != 0 => b,
            _ => return Err(Error::corrupt("zstd: a bit stream ends without its end mark")),
        };
        let full = i64::try_from(bytes.len() - 1)
            .unwrap_or(i64::MAX / 16)
            .saturating_mul(8);
        Ok(BackwardBits {
            bytes,
            remaining: full + i64::from(7 - last.leading_zeros()),
        })
    }

    /// Read `n <= 32` bits and move back.
    pub(crate) fn read(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let pos = self.remaining - i64::from(n);
        self.remaining = pos;
        match u64::try_from(pos) {
            Ok(p) => bits_at(self.bytes, p, n),
            Err(_) => {
                // some of the bits lie before the start: they read as zeros at the low end
                let short = pos.unsigned_abs();
                if short >= u64::from(n) {
                    0
                } else {
                    bits_at(self.bytes, 0, n - short as u32) << short
                }
            }
        }
    }

    /// Look at the next `n` bits without moving.
    pub(crate) fn peek(&mut self, n: u32) -> u64 {
        let saved = self.remaining;
        let value = self.read(n);
        self.remaining = saved;
        value
    }
}
