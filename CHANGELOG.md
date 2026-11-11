# Changelog

Versions below 1.0 may still change the API.

## Unreleased (intended as 0.1.0)

First version. The Rust implementation of the spillgate specification.

- `Limits` with a required `max_output`, ratio, layer and input limits; typed, sticky errors (`ErrorKind`, `Error::from_io` to recover the typed error from an `io::Error`); `ErrorKind::http_status` for HTTP servers.
- `Decoder` (immutable, `Send + Sync`) with `reader`, `reader_with_cancel` and `decode_all`; `CancelToken` for cooperative cancellation; `Codec` and `CodecReader` for extension codecs, run behind the same limiter, with panic containment.
- gzip, deflate and identity with an own resumable DEFLATE decoder (exact input accounting, bounded steps, no dependencies, no `unsafe`).
- Feature `br`: brotli through `brotli-decompressor` (pinned exactly); window parsed from the first byte and capped before allocation, large-window streams refused as `memory_limit`.
- Feature `zstd`: own decoder; header, window and dictionary checks before allocation, 128 KiB block steps, XXH64 checksum, window that grows with the output.
- Passes the full conformance corpus of the reference implementation with `--all-features` and no skips.
- Integration guide in `docs/how-to.md` (compiled as doc tests), memory bounds in `docs/memory.md`.
- Fuzz targets in `fuzz/`; CI, CodeQL, Scorecard, nightly fuzzing and a release workflow with crates.io trusted publishing.
