//! The codec interface, for the built-in codecs and for extensions such as brotli and zstd
//! (SG-R-CDC-09).
//!
//! A codec is registered on one decoder instance ([`DecoderBuilder::codec`](crate::DecoderBuilder::codec));
//! there is no global registry. Every codec, built in or not, runs behind the same limiter, ratio
//! meter and input meter (SG-R-CDC-01), so a sloppy codec is still bounded.
//!
//! Contract of a [`CodecReader`]:
//!
//! - `read(buf)` returns between 1 and `buf.len()` bytes, or `Ok(0)` at the clean end of the
//!   stream (and only then, for a non-empty `buf`). It never writes more than `buf.len()` bytes.
//! - It takes compressed input only from the `input` it was given, through `fill_buf`/`consume`.
//!   The number of bytes it *consumes* is what the ratio meter counts (SG-R-RAT-02), so a codec
//!   consumes only what it has used. It never calls `consume` with more than `fill_buf` returned.
//! - An `Ok(0)` from `fill_buf` is the end of the input. A stream that ends before its end marker
//!   or trailer is [`Error::corrupt`] (SG-R-CDC-06), never a clean end.
//! - An `io::Error` from the input is passed through [`Error::from_input`].
//! - To report a broken stream it returns [`Error::corrupt`] (or another [`Error`] for a limit of
//!   its own: a window cap is [`ErrorKind::MemoryLimit`](crate::ErrorKind::MemoryLimit)). A panic
//!   is a bug in the codec and becomes `internal` (SG-R-CDC-08).
//! - It must not allocate from a value read from the stream, except its decoder window within the
//!   cap (SG-R-CDC-07, SG-R-MEM-01).

use std::io::BufRead;

use crate::error::Error;

/// A decoding step for one layer.
pub trait CodecReader {
    /// Decode into `buf`. `Ok(0)` is the clean end of the stream.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

/// A factory for the readers of one content coding.
pub trait Codec: Send + Sync {
    /// A reader that takes its compressed input from `input`.
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a>;
}
