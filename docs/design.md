# Design of spillgate-rust

This is the contract between the parts of the port. The specification (`spec/SPEC.md`) and the
conformance corpus (`conformance/`) are normative. The closest model for every part is the
TypeScript port in `packages/core/src` of FelixMiddelhoff/spillgate-js (and its tests in
`packages/core/tests`); the Go reference is FelixMiddelhoff/spillgate. Port the **semantics and the
tests**, not the async structure: Rust is synchronous and pull based (`std::io::Read`).

## Principles

- `#![forbid(unsafe_code)]` (Cargo lint). No `unwrap`, `expect`, `panic!`, or unchecked indexing on
  data derived from the input (clippy lints are set in `Cargo.toml`; tests may use them with
  `#[allow]`). Arithmetic on sizes from the stream is checked or saturating.
- Core has **no dependencies**. Feature `br` adds `brotli-decompressor` (pinned exactly). Feature
  `zstd` adds nothing (own decoder).
- Whole input accounting is exact: codecs read through `BufRead` and `consume` only what they used.
- Every part has unit tests that name the rules they cover as `// Covers: SG-R-...` comments or in
  the test name (`fn sg_r_lay_03_...`); `tools`-style rule tracing will scan for `SG-R-`/`SG-I-`.

## Public API (owned by the core part)

```rust
pub struct Limits;                     // src/limits.rs (done)  Limits::new(max_output).max_layers(..)...
pub struct Decoder;                    // immutable, Send + Sync, share one per process
impl Decoder {
    pub fn new(limits: Limits) -> Result<Decoder, Error>;            // = builder(limits).build()
    pub fn builder(limits: Limits) -> DecoderBuilder;
    pub fn reader<'a, R: std::io::Read + 'a>(&self, source: R, content_encoding: &[&str])
        -> Result<SpillgateReader<'a>, Error>;                        // header parsed at construction
    pub fn decode_all<R: std::io::Read>(&self, source: R, content_encoding: &[&str]) -> Result<Vec<u8>, Error>;
}
pub struct DecoderBuilder;
impl DecoderBuilder {
    pub fn strict_zlib(self, on: bool) -> Self;                       // SG-R-CDC-03
    pub fn codec(self, name: &str, codec: impl Codec + 'static) -> Self; // SG-R-CDC-09; errors surface in build()
    pub fn build(self) -> Result<Decoder, Error>;                     // invalid_limits, invalid_option
}
pub fn decode_all<R: Read>(source: R, content_encoding: &[&str], limits: Limits) -> Result<Vec<u8>, Error>;
pub struct SpillgateReader<'a>;       // impl std::io::Read; errors are io::Error wrapping spillgate::Error
impl SpillgateReader<'_> { pub fn close(&mut self); /* idempotent, SG-R-RDR-06 */ }
```

- A reader's `Read::read` returns `Err(io::Error::from(spillgate::Error))`; callers recover the
  typed error with `Error::from_io(&e)`. Errors are **sticky**: every later `read` returns an
  error of the same kind (use `Error::duplicate`). A clean end is sticky too.
- `content_encoding` is a slice of header field values as received (`&["gzip, br", "zstd"]`).
- Codec registration errors (SG-R-CDC-09: ill-formed, reserved or duplicate name) are reported by
  `build()` as the new variant `ErrorKind::InvalidOption` (`as_str` = `"invalid_option"`, HTTP 500);
  bad limits stay `ErrorKind::InvalidLimits`. The core part adds the variant to `error.rs`.
- Cancellation (SG-R-API-04): `CancelToken` + `Decoder::reader_with_cancel`; checked on every read and every input fetch (src/cancel.rs).
- Source errors: an `io::Error` from the caller's source is `source_error` with the original as
  `Error::source()`; `ErrorKind::Interrupted` is retried by the meter like `read_exact` does.

## Parts and file ownership

| Part | Files | Interface it provides |
| --- | --- | --- |
| core | `decoder.rs header.rs meter.rs guard.rs reader.rs`, `error.rs` additions, `README`, tests `tests/core_*.rs` | the public API above |
| inflate | `inflate.rs gzip.rs deflate.rs` | `gzip::GzipCodec` (unit struct, `Codec`), `deflate::DeflateCodec::new(strict_zlib: bool)` (`Codec`) |
| zstd | `zstd/*.rs` | `zstd::codec(ZstdOptions) -> Result<ZstdCodec, Error>`, `zstd::ZstdOptions { max_window_bytes }`, `DEFAULT_MAX_WINDOW` |
| support | `crates/test-support`, `tests/conformance.rs`, `tests/spectrace.rs` | corpus generators and the conformance runner |
| br | `br.rs` | `br::codec(BrotliOptions) -> Result<BrotliCodec, Error>` |

### core

- `header.rs`: `parse_content_encoding(&[&str]) -> Result<Vec<Token>, Error>` per SPEC section 4
  (evaluation order is normative: length, element grammar left to right, element count, then the
  support check and layer count which `decoder.rs` does against its codec table).
- `meter.rs`: `InputMeter<R>` wraps the raw source for layer 1 and a lower layer's reader for the
  others. It implements `BufRead` and counts consumed bytes exactly (`consume`). It fetches at
  most 4 KiB at a time from a pull source, enforces `max_input` with the one probe byte
  (SG-R-INP-01/02) on layer 1: a codec's `fill_buf` shows the probe (alone, never together with
  earlier bytes) and only consuming it counts; `LayerGuard::call` checks `consumed > max_input` at
  the end of every codec step and overrides what the codec returned; identity gets the strict view
  (`InputMeter::strict`) which never shows the probe; codecs that find trailing data only peek
  (gzip first byte != 0x1f, zstd first byte cannot start a frame, deflate and brotli peek after the
  end), applies SG-R-RDR-03 (100 empty reads in a row = `internal`) and
  SG-R-RDR-04 (source reports more than requested = `internal`; with `Read` this is a source
  returning `n > buf.len()`), converts source `io::Error` to `source_error`, retries `Interrupted`.
  After a terminal condition it never reads the source again (SG-R-LAY-09).
- `guard.rs`: `LayerGuard` wraps a `CodecReader` per layer: output budget `max_output`
  (SG-R-LAY-01..03, the probe byte for the exact boundary, a bad trailer after exactly
  `max_output` bytes is `corrupt`), ratio (`ratio_exceeded(produced, consumed)` once per codec
  step), `MAX_STEP` = 64 KiB per codec call whatever the caller's buffer, sticky errors, panic
  containment with `std::panic::catch_unwind(AssertUnwindSafe(..))` -> `internal` (SG-R-CDC-08),
  a codec returning more than `buf.len()` -> `internal`, layer index on errors.
- `reader.rs`: `SpillgateReader` (chain of guards, end-to-end ratio SG-R-RAT-03, identity layers
  are no-ops that still pass through the limiter SG-R-CDC-10).
- Memory: no allocation sized from the stream; whole-body `decode_all` grows incrementally.

### inflate

An own resumable DEFLATE decoder (do not use `flate2`/`miniz_oxide` in the crate; they are
dev-dependencies for differential tests only): `Inflater` with `read(&mut self, input: &mut dyn
BufRead, out: &mut [u8]) -> Result<usize, Error>`; 32 KiB window, exact input accounting (leave
unused bit-buffer bytes unconsumed at the end of the final block: `leftover`), checked tables
(incomplete/oversubscribed codes, bad distances, header limits) as in `inflate.ts`. gzip framing
(SG-R-CDC-02) with CRC32 and ISIZE, FNAME/FCOMMENT <= 512 bytes, FHCRC, concatenated members;
zlib framing and raw fallback (SG-R-CDC-03) with Adler-32, `strict_zlib`.

### zstd

Port `packages/zstd/src` (decoder: frame header validation and window cap before allocation,
dictionaries refused, <= 128 KiB blocks, FSE/Huffman/sequences, XXH64, deferred checksum and size
errors, **lazy window growth**, one scratch buffer per reader, ring position kept modulo the
declared window). The three bugs found in review of the TS port (window ring after a window-sized
block, eager window allocation, 128 KiB zero fill per block) must have regression tests here.

### support and conformance runner

`crates/test-support` ports `packages/test-support/src/corpus.ts` (generators from
`spec/generators.md`, no compression library). `tests/conformance.rs` ports
`packages/core/tests/runner.ts`: reads `conformance/manifest.json`, builds inputs, runs every
vector with the base read pattern and the five alternative patterns, checks sticky behavior and
`max_input`, and skips vectors whose codec feature is not enabled unless `SPILLGATE_NO_SKIPS` is
set (CI runs `--all-features` with no skips: 354/354). `tests/spectrace.rs` checks that every
`SG-R-*`/`SG-I-*` ID of `spec/SPEC.md` is named by a vector's `rules` or in a test.

## Decisions fixed here

- MSRV 1.85, edition 2021. Rust 1.98 is installed locally.
- Limits are `u64`; there is no narrower platform problem (SG-R-LIM-02).
- `Decoder` is `Send + Sync`; a reader is not shared across threads (SG-R-RDR-07).
- Extension codecs implement `Codec` (see `src/codec.rs`); built-in names `identity`, `gzip`,
  `deflate`, `x-gzip` are reserved.
