# Vendored: brotli-decompressor

| | |
|---|---|
| Upstream | `brotli-decompressor` on crates.io, repository https://github.com/dropbox/rust-brotli-decompressor |
| Version | **5.0.0** (the version spillgate pinned before: `=5.0.0`); crates.io archive commit `a91c112180789502cdb9bf9e87f9546dd9a970fd` (from the crate's `.cargo_vcs_info.json`) |
| License | BSD-3-Clause (upstream's `LICENSE`, copied here unchanged as `LICENSE`; upstream declares `BSD-3-Clause/MIT`). The header comments of the source files are untouched. |
| Used as | the module `spillgate::vendored::brotli_decompressor` (private), behind the feature `br` |
| Dependencies kept | `alloc-no-stdlib =2.0.4`, `alloc-stdlib =0.2.4` (the versions in `Cargo.lock` before vendoring; upstream asked for `2.0` and `~0.2`) |

## Why

The decoder rebuilt and zeroed about 3.3 MiB of Huffman tables for every meta-block that declares
256 literal and 256 distance trees (see the patch below), so a stream of tiny hostile meta-blocks cost
about 1 us per input byte that no output or ratio limit can see. Fixing it needs a change inside the
decoder; spillgate does not wait for upstream and does not give up valid streams.
The code is vendored into the crate (not a path dependency) so that `cargo package` and `cargo publish`
ship it.

## What was taken, what was left out

Taken, as files: `decode.rs`, `state.rs`, `prefix.rs`, `context.rs`, `transform.rs`, `memory.rs`,
`bit_reader/mod.rs`, `dictionary/mod.rs`, `huffman/mod.rs`.

Left out: the `Read`/`Write` adapters (`reader.rs`, `writer.rs`, `io_wrappers.rs`), the allocator helper
`brotli_alloc.rs`, the C API (`ffi/`), the binary (`bin/`), the upstream tests (`test.rs`,
`huffman/tests.rs`), and `lib.rs` (replaced by `mod.rs`, which exports only
`BrotliDecompressStream`, `BrotliResult`, `BrotliState`, `HuffmanCode` and `StandardAlloc`).

## Changes that do not alter behavior

- Edition 2015 paths made 2021 paths (`use state::X` became `use super::state::X`, and so on). The code
  is compiled as part of an edition 2021 crate.
- The `unsafe` cargo feature of upstream is not carried over: the items that exist only with
  `feature = "unsafe"` (the `get_unchecked` macros in `memory.rs`, one `ptr::copy_nonoverlapping`
  variant of `memcpy_within_slice` in `decode.rs`) are deleted and the `cfg(not(feature = "unsafe"))`
  attributes on the safe variants are removed. The `ffi-api` only function `BrotliDecoderIsUsed` is
  deleted. **The vendored code contains no `unsafe` at all** (upstream has some, only behind the
  `unsafe` feature and in `ffi/` and `bin/`, none of which is vendored). The crate-wide
  `#![forbid(unsafe_code)]` holds for it.
- `mod tests;` removed from `huffman/mod.rs` (the test file is not vendored).
- `mod.rs`: relaxed lints for this module only (third-party style: `warnings`, `clippy::*`,
  `missing_docs`).

## The patch (behavior-preserving, CPU)

`huffman/mod.rs` (`HuffmanTreeGroup::init`, new `retire`) and `state.rs` (`BrotliStateMetablockBegin`,
`BrotliStateCleanupAfterMetablock`, `BrotliStateCleanup`): at the end of a meta-block the three tree
groups are no longer freed. The `htrees` offsets are still reallocated (at most 1 KiB), but the table
memory `codes` is kept and reused by the next meta-block when it is large enough (otherwise freed and
allocated as before). It is released when the decoder state is dropped (`BrotliStateCleanup`) and no
later than before on every error path, because the state itself is dropped. No `unsafe`, no new API.

Why the output stays bit-identical: every tree builder writes the whole table of its tree before the
table is read, so a reused table's stale entries are never observed; the memory is plain initialized
memory (safe Rust), so a bug there could change output but never read uninitialized bytes. Peak memory
is unchanged (the tables of a meta-block were already live while it was decoded; they now stay allocated
between meta-blocks, at most the size of the largest meta-block's tables, about 3.3 MiB).

Measured, 4000 meta-blocks that each declare 256 literal and 256 distance trees (2.86 MB in, 4000
bytes out), release profile on the development machine: 2.47-2.96 s before (about 860-1030 ns per input
byte), 0.28 s after (98 ns per input byte), 9x. Dev profile: 0.41 s (was 14.9 s with the unpatched
decoder in an optimized dev profile).

Regression test: `tests/br_hostile.rs`, `many_tiny_meta_blocks_with_256_trees_each_cost_bounded_cpu`
(bound 1.5 s, best of three). Not done (kept to the minimum that removes the cost): the context maps are
still allocated and cleared per meta-block (two 16 KiB blocks), and the trees themselves are still built
per meta-block, which is real work the stream asks for.

## Differential test

`differential_tests.rs` (new, not upstream) runs this copy and the unpatched upstream crate (a
dev-dependency, `upstream-brotli-decompressor`, `=5.0.0`) side by side on the same input with the same
input chunking and output buffer sizes and requires the same verdict, the same output bytes and the same
input consumption: 400 encoder streams (4 payload kinds, 5 sizes, qualities 0/1/5/9/11, windows
10/16/22/24), multi-megabyte multi-meta-block streams, hostile meta-block streams of free shapes
(including a large table set followed by small ones), 2400 damaged streams (bit flips, byte
overwrites, truncation, insertion) and random bytes.
