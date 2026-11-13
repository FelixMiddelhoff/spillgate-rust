# Changelog

Versions below 1.0 may still change the API.

## 0.1.1 - 2026-11-13

- Feature `br`: the vendored brotli decoder is rebased from `brotli-decompressor` 5.0.0 to 6.3.1 (tag `6.3.1`, commit 26c38e2). It is now **unpatched**: 6.x contains the two strictness fixes that were backported (upstream 8ed0d7d and 693a4a1), and its Huffman tree groups grow on demand, so the table-retention CPU patch is gone (4000 meta-blocks of 256 + 256 trees: 0.23 s on 6.3.1 with or without the patch, 0.28-0.49 s with the old patch on 5.0.0, 2.5-3.0 s on unpatched 5.0.0). Output of every valid stream is bit-identical to 5.0.0 and to 6.3.1; verdicts on damaged streams equal 6.3.1 (differential tests against 6.3.1 and 5.0.0, and 36 055 external streams against a separate 6.3.1 build: no accept/reject difference except the trailing-data rule spillgate applies itself).
- Feature `br`: the exact pins of the allocator crates move with it: `alloc-no-stdlib =3.0.0` (was `=2.0.4`) and `alloc-stdlib =0.3.0` (was `=0.2.4`). MSRV stays 1.85. Memory of the hostile table-hog stream (256 block types, 256 trees of each kind) drops from about 3.3 MiB to about 1.2 MiB.

## 0.1.0 - 2026-11-12

- SG-R-INP-01 is exact (corpus 0.2.0, vectors `SG-V-BND-0041..0057`): looking at the byte after `max_input` (to find trailing data) is no longer `input_limit`, taking it is. A complete stream of `max_input` bytes followed by data is `corrupt`; a stream cut at the limit with more source behind it is `input_limit`. The layer guard checks the taken count at the end of every codec step; identity keeps the strict view.

First version. The Rust implementation of the spillgate specification.

- `Limits` with a required `max_output`, ratio, layer and input limits; typed, sticky errors (`ErrorKind`, `Error::from_io` to recover the typed error from an `io::Error`); `ErrorKind::http_status` for HTTP servers.
- `Decoder` (immutable, `Send + Sync`) with `reader`, `reader_with_cancel` and `decode_all`; `CancelToken` for cooperative cancellation; `Codec` and `CodecReader` for extension codecs, run behind the same limiter, with panic containment.
- gzip, deflate and identity with an own resumable DEFLATE decoder (exact input accounting, bounded steps, no dependencies, no `unsafe`).
- Feature `br`: brotli through a vendored copy of `brotli-decompressor` 5.0.0 (`src/vendored`, license BSD-3-Clause, see `VENDORED.md` there); window parsed from the first byte and capped before allocation, large-window streams refused as `memory_limit`.
- Feature `br` CPU fix: the vendored decoder keeps its Huffman table memory between meta-blocks, so a stream of tiny meta-blocks that each declare 256 + 256 trees costs about 100 ns per input byte instead of about 900-1000 ns (4000 such meta-blocks: 2.5 s to 0.28 s). Output is bit-identical (differential tests against unpatched upstream).
- Feature `br` strictness: two upstream `brotli-decompressor` fixes made after 5.0.0 are backported into the vendored copy (upstream 8ed0d7d: non-zero padding bits after the last meta-block are `corrupt`, error code PADDING_2; upstream 693a4a1: a non-last meta-block whose insert, copy or dictionary word goes beyond its declared MLEN is `corrupt`, BLOCK_LENGTH_2). Streams that 5.0.0 accepted wrongly (more bytes than declared, or garbage in the padding) are now rejected, like the C reference, andybalholm/brotli and upstream 6.3.1 do.
- Feature `zstd`: own decoder; header, window and dictionary checks before allocation, 128 KiB block steps, XXH64 checksum, window that grows with the output.
- Passes the full conformance corpus of the reference implementation with `--all-features` and no skips.
- Integration guide in `docs/how-to.md` (compiled as doc tests), memory bounds in `docs/memory.md`.
- Fuzz targets in `fuzz/`; CI, CodeQL, Scorecard, nightly fuzzing and a release workflow with crates.io trusted publishing.
