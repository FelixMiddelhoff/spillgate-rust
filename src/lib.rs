//! # spillgate
//!
//! Decode untrusted compressed data (HTTP `Content-Encoding` chains: gzip, deflate, brotli, zstd)
//! with mandatory limits, so that a decompression bomb ends in a typed [`Error`] instead of
//! exhausting memory. The specification is `spec/SPEC.md`; this crate is one of several ports and
//! passes the shared conformance corpus.
//!
//! ```
//! use spillgate::{Decoder, Limits};
//! use std::io::Read;
//!
//! # let body: &[u8] = &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//! let decoder = Decoder::new(Limits::new(8 * 1024 * 1024))?;
//! let mut reader = decoder.reader(body, &["gzip"])?;
//! let mut out = Vec::new();
//! reader.read_to_end(&mut out)?; // an error here is a refusal; discard `out` then
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Optional codecs are crate features: `br` (brotli, through the pure Rust `brotli-decompressor`)
//! and `zstd` (an own decoder in this crate).

mod cancel;
mod codec;
mod decoder;
mod deflate;
mod error;
mod guard;
mod gzip;
mod header;
mod inflate;
mod limits;
mod meter;
mod reader;

#[cfg(feature = "br")]
pub mod br;
#[cfg(feature = "zstd")]
pub mod zstd;

pub use cancel::CancelToken;
pub use codec::{Codec, CodecReader};
pub use decoder::{decode_all, Decoder, DecoderBuilder};
pub use error::{quote_untrusted, Error, ErrorKind};
pub use limits::{EffectiveLimits, Limits};
pub use reader::SpillgateReader;

// The how-to guide is compiled as documentation tests (`cargo test --all-features --doc`).
#[cfg(doctest)]
#[doc = include_str!("../docs/how-to.md")]
struct HowTo;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;
