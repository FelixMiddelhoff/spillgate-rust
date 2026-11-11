//! Zstandard (RFC 8878, RFC 9659) for spillgate, feature `zstd`.
//!
//! ```no_run
//! use spillgate::zstd::{codec, ZstdOptions};
//!
//! let codec = codec(ZstdOptions::default())?;
//! # let _ = codec;
//! # Ok::<(), spillgate::Error>(())
//! ```
//!
//! This is an own decoder in Rust, written for hostile input and without dependencies:
//!
//! - The frame header is validated before anything is allocated: the reserved bit, a dictionary
//!   (refused as `corrupt`), and the window, including the window a single-segment frame gets from
//!   its declared content size, against the cap (SG-R-CDC-05). The default cap is 8 MiB, the 8 MB
//!   that RFC 9659 requires decoders to support.
//! - The decoder works one block at a time. A block regenerates at most 128 KiB, so memory per
//!   step is constant: the window (it grows with the output, never eagerly to the declared size)
//!   plus three block-sized buffers per reader.
//! - A block larger than the window or 128 KiB, and the reserved block type, are `corrupt`.
//! - Skippable frames are skipped and count as consumed input only. Bytes that do not start a frame
//!   are `corrupt`. The content checksum is verified; a declared content size must match. Both
//!   failures are raised after the bytes of the last block were delivered.
//! - Declared sizes are never used for any decision or allocation, except the window (SG-R-CDC-07).

use std::io::BufRead;

use crate::codec::{Codec, CodecReader};
use crate::error::{Error, ErrorKind};

mod bits;
mod block;
mod fse;
mod huffman;
mod reader;
mod xxhash64;

#[cfg(test)]
mod tests;

/// The default window cap: 8 MiB, the 8 MB that RFC 9659 requires decoders to support.
pub const DEFAULT_MAX_WINDOW: u64 = 8 * 1024 * 1024;
const MIN_WINDOW: u64 = 1 << 10;
const MAX_WINDOW: u64 = 1 << 30;

/// Options of the zstd codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZstdOptions {
    /// The largest window in bytes, `1 KiB ..= 1 GiB`. Default [`DEFAULT_MAX_WINDOW`]. Memory per
    /// stream is this much at most (plus a few block-sized buffers).
    pub max_window_bytes: u64,
}

impl Default for ZstdOptions {
    fn default() -> ZstdOptions {
        ZstdOptions {
            max_window_bytes: DEFAULT_MAX_WINDOW,
        }
    }
}

/// The zstd codec: register it on a decoder with
/// [`DecoderBuilder::codec`](crate::DecoderBuilder::codec). Frames whose window exceeds the cap are
/// refused as `memory_limit` before any memory is allocated for them.
#[derive(Debug, Clone, Copy)]
pub struct ZstdCodec {
    max_window: u64,
}

/// Build the zstd codec.
///
/// # Errors
///
/// `max_window_bytes` outside `1 KiB ..= 1 GiB` (reported as `invalid_limits` until the core part
/// adds `invalid_option`).
pub fn codec(options: ZstdOptions) -> Result<ZstdCodec, Error> {
    let cap = options.max_window_bytes;
    if !(MIN_WINDOW..=MAX_WINDOW).contains(&cap) {
        return Err(Error::new(
            ErrorKind::InvalidOption,
            format!("zstd: max_window_bytes must be in {MIN_WINDOW}..={MAX_WINDOW}"),
        ));
    }
    Ok(ZstdCodec { max_window: cap })
}

impl ZstdCodec {
    /// The window cap of this codec.
    pub fn max_window_bytes(&self) -> u64 {
        self.max_window
    }
}

impl Codec for ZstdCodec {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(reader::ZstdReader::new(input, self.max_window))
    }
}
