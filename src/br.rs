//! Brotli (RFC 7932) for spillgate, behind the crate feature `br`.
//!
//! ```
//! # #[cfg(feature = "br")] {
//! use spillgate::{br, Decoder, Limits};
//!
//! let decoder = Decoder::builder(Limits::new(8 * 1024 * 1024))
//!     .codec("br", br::codec(br::BrotliOptions::default())?)
//!     .build()?;
//! # let _ = decoder;
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The decoder is the pure Rust `brotli-decompressor` crate (safe code, no FFI), pinned to an
//! exact version. What this module adds is what a hostile stream needs around it:
//!
//! - The window is read from the first byte of the stream and checked against the cap before the
//!   decoder allocates anything (SG-R-CDC-04). The default cap is 24 bits (16 MiB - 16 bytes). The
//!   large-window marker is refused as `memory_limit` whatever the cap.
//! - The decoder is driven in output steps of at most 64 KiB, and the input it reports as used is
//!   what the meter counts.
//! - A stream that ends early is `corrupt`, and so are bytes after the last meta-block.
//! - Memory per stream is the window plus the decoder's tables: about 0.1 MiB for an ordinary stream and
//!   up to about 3.3 MiB for a hostile one that asks for 256 block types and 256 trees of every kind
//!   (measured in `tools/alloc-check/tests/br_memory.rs`), whatever the window cap.

use std::io::BufRead;

use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};

use crate::codec::{Codec, CodecReader};
use crate::error::{Error, ErrorKind};

/// The default window cap in bits: the largest window of RFC 7932, `2^24 - 16` bytes.
pub const DEFAULT_MAX_WINDOW_BITS: u32 = 24;
/// The smallest valid cap in bits.
pub const MIN_WINDOW_BITS: u32 = 10;
/// The most output one decoder call may produce.
const MAX_OUTPUT_STEP: usize = 64 * 1024;

type State = BrotliState<StandardAlloc, StandardAlloc, StandardAlloc>;

/// Options of the brotli codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrotliOptions {
    /// The largest window as bits (`2^bits - 16` bytes), `10 ..= 24`. Default 24.
    pub max_window_bits: u32,
}

impl Default for BrotliOptions {
    fn default() -> Self {
        BrotliOptions {
            max_window_bits: DEFAULT_MAX_WINDOW_BITS,
        }
    }
}

/// The brotli codec. Streams needing a larger window than the cap are refused as `memory_limit`.
#[derive(Debug, Clone, Copy)]
pub struct BrotliCodec {
    max_window_bits: u32,
}

/// Create the brotli codec.
///
/// # Errors
/// `invalid_option` if `max_window_bits` is outside `10 ..= 24`.
pub fn codec(options: BrotliOptions) -> Result<BrotliCodec, Error> {
    if !(MIN_WINDOW_BITS..=DEFAULT_MAX_WINDOW_BITS).contains(&options.max_window_bits) {
        return Err(Error::new(
            ErrorKind::InvalidOption,
            format!("max_window_bits must be in {MIN_WINDOW_BITS}..={DEFAULT_MAX_WINDOW_BITS}"),
        ));
    }
    Ok(BrotliCodec {
        max_window_bits: options.max_window_bits,
    })
}

impl Codec for BrotliCodec {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(BrotliReader {
            input,
            max_window_bits: self.max_window_bits,
            state: None,
            finished: false,
            failure: None,
        })
    }
}

/// RFC 7932 section 9.1: the window bits announced by the first byte, and whether the stream uses
/// the reserved large-window marker (WBITS pattern 1000001).
pub fn window_bits(first: u8) -> (u32, bool) {
    if first & 1 == 0 {
        return (16, false);
    }
    let n = u32::from((first >> 1) & 7);
    if n != 0 {
        return (17 + n, false);
    }
    match (first >> 4) & 7 {
        0 => (17, false),
        1 => (0, true),
        m => (8 + u32::from(m), false),
    }
}

struct BrotliReader<'a> {
    input: Box<dyn BufRead + 'a>,
    max_window_bits: u32,
    state: Option<Box<State>>,
    finished: bool,
    /// The error that ended the stream; later reads repeat it and the decoder state is gone.
    failure: Option<Error>,
}

impl BrotliReader<'_> {
    fn start(&mut self) -> Result<(), Error> {
        let first = {
            let view = self.input.fill_buf().map_err(Error::from_input)?;
            match view.first() {
                Some(&byte) => byte,
                None => return Err(Error::corrupt("brotli: an empty input is not a brotli stream")),
            }
        };
        let (bits, large_window) = window_bits(first);
        if large_window {
            return Err(Error::new(
                ErrorKind::MemoryLimit,
                "brotli stream asks for a large window (not supported)",
            ));
        }
        if bits > self.max_window_bits {
            return Err(Error::new(
                ErrorKind::MemoryLimit,
                format!(
                    "brotli stream asks for a window of 2^{bits} bytes (the cap is 2^{})",
                    self.max_window_bits
                ),
            )
            .with_limit(1u64 << self.max_window_bits));
        }
        // `new_strict` refuses the large-window extension inside the decoder as well.
        self.state = Some(Box::new(State::new_strict(
            StandardAlloc::default(),
            StandardAlloc::default(),
            StandardAlloc::default(),
        )));
        Ok(())
    }
}

impl CodecReader for BrotliReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(failure) = &self.failure {
            return Err(failure.duplicate());
        }
        let result = self.read_step(buf);
        if let Err(error) = &result {
            // Release the window now rather than when the reader is closed, and never turn the
            // failure into a clean end on a later call.
            self.state = None;
            self.failure = Some(error.duplicate());
        }
        result
    }
}

impl BrotliReader<'_> {
    fn read_step(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.finished || buf.is_empty() {
            return Ok(0);
        }
        if self.state.is_none() {
            self.start()?;
        }
        let step = buf.len().min(MAX_OUTPUT_STEP);
        loop {
            let view = self.input.fill_buf().map_err(Error::from_input)?;
            let source_ended = view.is_empty();
            let mut available_in = view.len();
            let mut input_offset = 0usize;
            let mut available_out = step;
            let mut output_offset = 0usize;
            let mut total_out = 0usize;
            let Some(state) = self.state.as_mut() else {
                return Err(Error::new(ErrorKind::Internal, "brotli: the decoder state is missing"));
            };
            let result = BrotliDecompressStream(
                &mut available_in,
                &mut input_offset,
                view,
                &mut available_out,
                &mut output_offset,
                buf,
                &mut total_out,
                state,
            );
            if input_offset > view.len() || output_offset > step {
                return Err(Error::new(
                    ErrorKind::Internal,
                    "brotli: the decoder reported an impossible position",
                ));
            }
            self.input.consume(input_offset);
            match result {
                BrotliResult::ResultFailure => return Err(Error::corrupt("brotli: invalid data")),
                BrotliResult::ResultSuccess => {
                    self.finished = true;
                    self.state = None;
                    // The final meta-block is complete: nothing may follow it.
                    let more = !self.input.fill_buf().map_err(Error::from_input)?.is_empty();
                    if more {
                        return Err(Error::corrupt("brotli: unexpected data after the end of the stream"));
                    }
                    return Ok(output_offset);
                }
                BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {
                    if output_offset > 0 {
                        return Ok(output_offset);
                    }
                    if matches!(result, BrotliResult::NeedsMoreInput) && source_ended {
                        return Err(Error::corrupt("brotli: the stream ends too early"));
                    }
                    if input_offset == 0 {
                        // Nothing was used and nothing came out: no progress. (With the source at
                        // its end this can only be `NeedsMoreOutput`; looping would never end.)
                        return Err(Error::new(ErrorKind::Internal, "brotli: the decoder made no progress"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::codec::Codec;

    /// A valid stream: 5 bytes "hello" in one uncompressed meta-block, window 2^16.
    fn hello() -> Vec<u8> {
        // WBITS 16 = bit 0; ISLAST 0; MNIBBLES 0 (4 nibbles); MLEN-1 = 4 (16 bits); ISUNCOMPRESSED 1;
        // padding to a byte; the 5 bytes; then ISLAST 1, ISLASTEMPTY 1.
        // bits: 0 | 0 | 00 | 0010 0000 0000 0000 | 1 -> bytes, built by hand below.
        let mut bits: Vec<bool> = Vec::new();
        let mut put = |value: u32, n: u32| {
            for i in 0..n {
                bits.push((value >> i) & 1 == 1);
            }
        };
        put(0, 1); // WBITS = 16
        put(0, 1); // ISLAST
        put(0, 2); // MNIBBLES = 4
        put(4, 16); // MLEN - 1
        put(1, 1); // ISUNCOMPRESSED
        while bits.len() % 8 != 0 {
            bits.push(false);
        }
        let mut out: Vec<u8> = bits
            .chunks(8)
            .map(|c| c.iter().enumerate().fold(0u8, |acc, (i, &b)| acc | (u8::from(b) << i)))
            .collect();
        out.extend_from_slice(b"hello");
        out.push(0b11); // ISLAST = 1, ISLASTEMPTY = 1
        out
    }

    fn reader(data: Vec<u8>) -> Box<dyn CodecReader + 'static> {
        codec(BrotliOptions::default())
            .unwrap()
            .new_reader(Box::new(std::io::Cursor::new(data)))
    }

    #[test]
    fn the_hand_built_stream_decodes() {
        // Covers: SG-R-CDC-04
        let mut r = reader(hello());
        let mut buf = [0u8; 64];
        assert_eq!(r.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(r.read(&mut buf).unwrap(), 0);
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_failure_is_repeated_and_releases_the_decoder_state() {
        // Covers: SG-R-CDC-04 SG-R-CDC-06 SG-R-MEM-02
        // Regression: after the trailing-data error a later read returned Ok(0), a clean end, and
        // the window stayed allocated until the reader was dropped.
        let mut data = hello();
        data.push(0xff);
        let mut r = BrotliReader {
            input: Box::new(std::io::Cursor::new(data)),
            max_window_bits: 24,
            state: None,
            finished: false,
            failure: None,
        };
        let mut buf = [0u8; 64];
        let first = r.read(&mut buf);
        assert_eq!(first.unwrap_err().kind(), ErrorKind::Corrupt);
        assert!(r.state.is_none());
        for _ in 0..3 {
            assert_eq!(r.read(&mut buf).unwrap_err().kind(), ErrorKind::Corrupt);
        }
    }

    #[test]
    fn a_decoder_failure_releases_the_state_too() {
        // Covers: SG-R-CDC-06 SG-R-MEM-02
        let mut data = hello();
        data[2] ^= 0xff; // damage the meta-block header
        let mut r = BrotliReader {
            input: Box::new(std::io::Cursor::new(data)),
            max_window_bits: 24,
            state: None,
            finished: false,
            failure: None,
        };
        let mut buf = [0u8; 64];
        let kind = loop {
            match r.read(&mut buf) {
                Ok(0) => panic!("a damaged stream ended cleanly"),
                Ok(_) => {}
                Err(e) => break e.kind(),
            }
        };
        assert_eq!(kind, ErrorKind::Corrupt);
        assert!(r.state.is_none());
        assert_eq!(r.read(&mut buf).unwrap_err().kind(), ErrorKind::Corrupt);
    }

    #[test]
    fn a_refused_window_creates_no_decoder_state() {
        // Covers: SG-R-CDC-04 SG-R-CDC-07
        let mut r = BrotliReader {
            input: Box::new(std::io::Cursor::new(vec![0x0b, 0, 0])), // WBITS 22
            max_window_bits: 21,
            state: None,
            finished: false,
            failure: None,
        };
        assert_eq!(r.read(&mut [0u8; 8]).unwrap_err().kind(), ErrorKind::MemoryLimit);
        assert!(r.state.is_none());
        assert_eq!(r.read(&mut [0u8; 8]).unwrap_err().kind(), ErrorKind::MemoryLimit);
    }
}
