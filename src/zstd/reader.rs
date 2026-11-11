//! The zstd stream: frames, skippable frames and the block loop.

use std::io::BufRead;

use super::block::{Frame, BLOCK_MAX};
use super::xxhash64::Xxh64;
use crate::codec::CodecReader;
use crate::error::{Error, ErrorKind};

const FRAME_MAGIC: u32 = 0xfd2f_b528;
const SKIPPABLE_MAGIC: u32 = 0x184d_2a50;
const SKIPPABLE_MASK: u32 = 0xffff_fff0;
/// Skippable frames are skipped and metered in steps of at most this many bytes.
const SKIP_STEP: usize = 4096;

fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

fn truncated(what: &str) -> Error {
    Error::corrupt(format!("zstd: the input ends inside the {what}"))
}

/// The compressed input with the three operations the decoder needs. Everything it takes is consumed.
struct Input<'a> {
    inner: Box<dyn BufRead + 'a>,
}

impl Input<'_> {
    /// The next byte, not consumed; `None` at the end of the input.
    fn peek(&mut self) -> Result<Option<u8>, Error> {
        let buf = self.inner.fill_buf().map_err(Error::from_input)?;
        Ok(buf.first().copied())
    }

    /// Fill `dst` completely; the end of the input first is `corrupt`.
    fn read_exact(&mut self, dst: &mut [u8], what: &str) -> Result<(), Error> {
        let mut filled = 0usize;
        while filled < dst.len() {
            let buf = self.inner.fill_buf().map_err(Error::from_input)?;
            if buf.is_empty() {
                return Err(truncated(what));
            }
            let want = dst.len() - filled;
            let n = buf.len().min(want);
            let (Some(from), Some(to)) = (buf.get(..n), dst.get_mut(filled..filled + n)) else {
                return Err(Error::new(ErrorKind::Internal, "zstd: input bookkeeping failed"));
            };
            to.copy_from_slice(from);
            self.inner.consume(n);
            filled += n;
        }
        Ok(())
    }

    /// Replace the content of `dst` with the next `n` bytes (`n` was bounded by the caller).
    fn read_vec(&mut self, n: usize, dst: &mut Vec<u8>, what: &str) -> Result<(), Error> {
        dst.clear();
        while dst.len() < n {
            let buf = self.inner.fill_buf().map_err(Error::from_input)?;
            if buf.is_empty() {
                return Err(truncated(what));
            }
            let take = buf.len().min(n - dst.len());
            match buf.get(..take) {
                Some(part) => dst.extend_from_slice(part),
                None => return Err(Error::new(ErrorKind::Internal, "zstd: input bookkeeping failed")),
            }
            self.inner.consume(take);
        }
        Ok(())
    }

    /// Skip `n` bytes in steps of at most [`SKIP_STEP`].
    fn skip(&mut self, mut n: u64, what: &str) -> Result<(), Error> {
        while n > 0 {
            let buf = self.inner.fill_buf().map_err(Error::from_input)?;
            if buf.is_empty() {
                return Err(truncated(what));
            }
            let step = buf.len().min(SKIP_STEP).min(usize::try_from(n).unwrap_or(SKIP_STEP));
            self.inner.consume(step);
            n -= step as u64;
        }
        Ok(())
    }
}

pub(crate) struct ZstdReader<'a> {
    input: Input<'a>,
    max_window: u64,
    frames: u64,
    frame: Option<Frame>,
    hasher: Option<Xxh64>,
    declared: Option<u64>,
    /// Compressed content of the current block.
    content: Vec<u8>,
    /// The regenerated block waiting to be delivered, from `out_pos`.
    out: Vec<u8>,
    out_pos: usize,
    /// Scratch for the literals section.
    lits: Vec<u8>,
    /// An error found at the end of a frame, raised after the bytes of its last block.
    deferred: Option<Error>,
    failed: Option<Error>,
}

impl<'a> ZstdReader<'a> {
    pub(crate) fn new(input: Box<dyn BufRead + 'a>, max_window: u64) -> ZstdReader<'a> {
        ZstdReader {
            input: Input { inner: input },
            max_window,
            frames: 0,
            frame: None,
            hasher: None,
            declared: None,
            content: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            lits: Vec::new(),
            deferred: None,
            failed: None,
        }
    }

    /// Heap held by this reader (test accounting).
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.content.capacity()
            + self.out.capacity()
            + self.lits.capacity()
            + self.frame.as_ref().map_or(0, Frame::window_capacity)
    }

    fn release(&mut self) {
        self.frame = None;
        self.hasher = None;
        self.content = Vec::new();
        self.out = Vec::new();
        self.out_pos = 0;
        self.lits = Vec::new();
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(pending) = self.out.get(self.out_pos..).filter(|p| !p.is_empty()) {
                let n = pending.len().min(buf.len());
                if let (Some(from), Some(to)) = (pending.get(..n), buf.get_mut(..n)) {
                    to.copy_from_slice(from);
                }
                self.out_pos += n;
                return Ok(n);
            }
            if let Some(error) = self.deferred.take() {
                return Err(error);
            }
            if self.frame.is_none() {
                if !self.next_frame()? {
                    return Ok(0);
                }
            } else {
                self.block()?;
            }
        }
    }

    // -- frames ---------------------------------------------------------------------

    /// Start the next frame. False means a clean end of the input.
    fn next_frame(&mut self) -> Result<bool, Error> {
        if self.input.peek()?.is_none() {
            if self.frames > 0 {
                return Ok(false);
            }
            return Err(Error::corrupt("zstd: an empty input is not a zstd stream"));
        }
        let mut magic = [0u8; 4];
        self.input.read_exact(&mut magic, "zstd magic number")?;
        let full = le(&magic) as u32;
        if full == FRAME_MAGIC {
            self.start_frame()?;
        } else if full & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
            let mut size = [0u8; 4];
            self.input.read_exact(&mut size, "skippable frame header")?;
            self.input.skip(le(&size), "skippable frame")?;
            self.frames += 1; // a skippable frame is a frame: the input may end after it
        } else {
            return Err(Error::corrupt("zstd: data that is not a zstd frame follows the stream"));
        }
        Ok(true)
    }

    fn start_frame(&mut self) -> Result<(), Error> {
        let mut descriptor = [0u8; 1];
        self.input.read_exact(&mut descriptor, "frame header")?;
        let descriptor = descriptor[0];
        let single_segment = descriptor & (1 << 5) != 0;
        let checksum = descriptor & (1 << 2) != 0;
        if descriptor & (1 << 3) != 0 {
            return Err(Error::corrupt("zstd: reserved bit set in the frame header"));
        }

        let mut window = 0u64;
        if !single_segment {
            let mut wd = [0u8; 1];
            self.input.read_exact(&mut wd, "frame header")?;
            let wd = u64::from(wd[0]);
            let base = 1u64 << (10 + (wd >> 3));
            window = base + (base / 8) * (wd & 7);
        }
        let mut dictionary = [0u8; 4];
        let dictionary_len = [0usize, 1, 2, 4].get(usize::from(descriptor & 3)).copied().unwrap_or(0);
        let dictionary = dictionary.get_mut(..dictionary_len).unwrap_or(&mut []);
        self.input.read_exact(dictionary, "frame header")?;
        if dictionary.iter().any(|&b| b != 0) {
            return Err(Error::corrupt("zstd: the frame needs a dictionary"));
        }

        let flag = descriptor >> 6;
        let fcs_len = if flag == 0 && single_segment {
            1
        } else {
            [0usize, 2, 4, 8].get(usize::from(flag)).copied().unwrap_or(0)
        };
        let mut fcs = [0u8; 8];
        let fcs = fcs.get_mut(..fcs_len).unwrap_or(&mut []);
        self.input.read_exact(fcs, "frame header")?;
        self.declared = if fcs.is_empty() {
            None
        } else {
            Some(le(fcs) + if fcs.len() == 2 { 256 } else { 0 })
        };
        if single_segment {
            window = self.declared.unwrap_or(0);
        }

        // the memory declaration of the frame is checked before anything is allocated (SG-R-CDC-05)
        let window = match usize::try_from(window) {
            Ok(w) if window <= self.max_window => w,
            _ => {
                return Err(Error::new(
                    ErrorKind::MemoryLimit,
                    format!(
                        "zstd frame asks for a window of {window} bytes (the cap is {})",
                        self.max_window
                    ),
                )
                .with_limit(self.max_window))
            }
        };
        self.frame = Some(Frame::new(window));
        self.hasher = checksum.then(Xxh64::new);
        Ok(())
    }

    // -- blocks ---------------------------------------------------------------------

    fn block(&mut self) -> Result<(), Error> {
        let ZstdReader {
            input,
            frame,
            hasher,
            content,
            out,
            out_pos,
            lits,
            ..
        } = self;
        let Some(frame) = frame.as_mut() else {
            return Err(Error::new(ErrorKind::Internal, "zstd: no frame"));
        };
        let mut raw = [0u8; 3];
        input.read_exact(&mut raw, "block header")?;
        let header = le(&raw);
        let last = header & 1 != 0;
        let kind = (header >> 1) & 3;
        let size = usize::try_from(header >> 3).unwrap_or(usize::MAX);
        if kind == 3 {
            return Err(Error::corrupt("zstd: reserved block type"));
        }
        if size > BLOCK_MAX || size > frame.block_max() {
            return Err(Error::corrupt(format!(
                "zstd: block of {size} bytes, the maximum is {}",
                frame.block_max()
            )));
        }
        match kind {
            1 => {
                // the size field is the regenerated size
                let mut byte = [0u8; 1];
                input.read_exact(&mut byte, "block")?;
                out.clear();
                out.resize(size, byte[0]);
            }
            0 => {
                input.read_vec(size, content, "block")?;
                std::mem::swap(content, out);
            }
            _ => {
                input.read_vec(size, content, "block")?;
                frame.compressed(content, lits, out)?;
            }
        }
        frame.push(out)?;
        if let Some(h) = hasher.as_mut() {
            h.update(out);
        }
        *out_pos = 0;
        if last {
            self.end_frame();
        }
        Ok(())
    }

    /// The last block was decoded. A failure found here (checksum, declared size) is kept and raised
    /// after the bytes of this block were delivered, as the output limit comes first in stream order
    /// (SG-R-LAY-07).
    fn end_frame(&mut self) {
        self.deferred = self.check_end().err();
        self.frame = None;
        self.hasher = None;
        self.frames += 1;
    }

    fn check_end(&mut self) -> Result<(), Error> {
        if let Some(hasher) = self.hasher.as_ref() {
            let mut stored = [0u8; 4];
            self.input.read_exact(&mut stored, "content checksum")?;
            if le(&stored) != u64::from(hasher.digest32()) {
                return Err(Error::corrupt("zstd: content checksum mismatch"));
            }
        }
        let produced = self.frame.as_ref().map_or(0, Frame::total);
        if self.declared.is_some_and(|d| d != produced) {
            // Only an integrity check; the declared size is never an allowance (SG-R-CDC-07).
            return Err(Error::corrupt("zstd: the frame size differs from its declared size"));
        }
        Ok(())
    }
}

impl CodecReader for ZstdReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(error) = &self.failed {
            return Err(error.duplicate());
        }
        match self.read_inner(buf) {
            Ok(n) => Ok(n),
            Err(error) => {
                self.failed = Some(error.duplicate());
                self.release();
                Err(error)
            }
        }
    }
}
