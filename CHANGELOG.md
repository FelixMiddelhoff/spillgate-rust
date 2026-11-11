# Changelog

Versions below 1.0 may still change the API.

## Unreleased (intended as 0.1.0)

- SG-R-INP-01 is exact (corpus 0.2.0, vectors `SG-V-BND-0041..0057`): looking at the byte after `max_input` (to find trailing data) is no longer `input_limit`, taking it is. A complete stream of `max_input` bytes followed by data is `corrupt`; a stream cut at the limit with more source behind it is `input_limit`. The layer guard checks the taken count at the end of every codec step; identity keeps the strict view.

First version. The Rust implementation of the spillgate specification.

- `Limits` with a required `max_output`, ratio, layer and input limits; typed, sticky errors (`ErrorKind`, `Error::from_io` to recover the typed error from an `io::Error`); `ErrorKind::http_status` for HTTP servers.
- `Decoder` (immutable, `Send + Sync`) with `reader`, `reader_with_cancel` and `decode_all`; `CancelToken` for cooperative cancellation; `Codec` and `CodecReader` for extension codecs, run behind the same limiter, with panic containment.
- gzip, deflate and identity with an own resumable DEFLATE decoder (exact input accounting, bounded steps, no dependencies, no `unsafe`).
- Feature `br`: brotli through `brotli-decompressor` (pinned exactly); window parsed from the first byte and capped before allocation, large-window streams refused as `memory_limit`.
- Feature `zstd`: own decoder; header, window and dictionary checks before allocation, 128 KiB block steps, XXH64 checksum, window that grows with the output.
- Passes the full conformance corpus of the reference implementation with `--all-features` and no skips.
- Integration guide in `docs/how-to.md` (compiled as doc tests), memory bounds in `docs/memory.md`.
- Fuzz targets in `fuzz/`; CI, CodeQL, Scorecard, nightly fuzzing and a release workflow with crates.io trusted publishing.
