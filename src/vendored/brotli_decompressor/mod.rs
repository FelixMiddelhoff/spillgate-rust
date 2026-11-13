//! Vendored `brotli-decompressor` 6.3.1 (see VENDORED.md in this directory for the upstream
//! version, the license and the list of local changes). Third-party code: lints are relaxed here
//! and nowhere else; the crate-wide `forbid(unsafe_code)` still applies.
#![allow(
    warnings,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals
)]

pub(crate) use alloc_no_stdlib as alloc;
pub use alloc_stdlib::StandardAlloc;

#[macro_use]
mod memory;
mod dictionary;
#[macro_use]
mod bit_reader;
mod huffman;
mod state;
mod prefix;
mod context;
mod transform;
mod shared_dictionary;
mod decode;

pub use huffman::HuffmanCode;
pub use state::BrotliState;
pub use decode::{BrotliDecompressStream, BrotliResult};

#[cfg(test)]
mod differential_tests;
