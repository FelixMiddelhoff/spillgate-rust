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
//! - Memory per stream is the window plus the decoder's tables (a few hundred KiB).

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
                    if input_offset == 0 && !source_ended {
                        // Input was offered, nothing was used and nothing came out: no progress.
                        return Err(Error::new(ErrorKind::Internal, "brotli: the decoder made no progress"));
                    }
                }
            }
        }
    }
}
