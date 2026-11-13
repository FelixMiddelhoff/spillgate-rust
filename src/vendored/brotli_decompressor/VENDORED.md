# Vendored: brotli-decompressor

| | |
|---|---|
| Upstream | `brotli-decompressor` on crates.io, repository https://github.com/dropbox/rust-brotli-decompressor |
| Version | **6.3.1**, git tag `6.3.1` = commit `26c38e2def3ad84f41a28d182d9ba41779a613c7` (equal to the `sha1` in the crates.io archive's `.cargo_vcs_info.json`; `decode.rs`, `state.rs`, `huffman/mod.rs` and `prefix.rs` of the crates.io archive were compared with the tag and are identical) |
| Previous version | 5.0.0 (+ spillgate patches), replaced by this rebase |
| License | BSD-3-Clause (upstream's `LICENSE`, copied here unchanged as `LICENSE`; upstream declares `BSD-3-Clause/MIT`). The header comments of the source files are untouched. |
| Used as | the module `spillgate::vendored::brotli_decompressor` (private), behind the feature `br` |
| Dependencies kept | `alloc-no-stdlib =3.0.0`, `alloc-stdlib =0.3.0` (the generation upstream 6.3.1 asks for: `>=3.0.0, <4.0.0` and `>=0.3.0, <0.4`; spillgate pins exactly) |

## Why vendored

Until the rebase the decoder was patched (hostile-meta-block CPU, two strictness backports). The code stays
vendored (not a dependency) so that spillgate controls the exact decoder bytes, the pins of the allocator
crates and the absence of `unsafe`, and so that `cargo package` and `cargo publish` ship it.

## What was taken, what was left out

Taken, as files: `decode.rs`, `state.rs`, `prefix.rs`, `context.rs`, `transform.rs`, `memory.rs`,
`bit_reader/mod.rs`, `dictionary/mod.rs`, `huffman/mod.rs`, `shared_dictionary.rs` (new since 5.0.0; the
state and the decode loop refer to it).

Left out: the `Read`/`Write` adapters (`reader.rs`, `writer.rs`, `io_wrappers.rs`), the allocator helper
`brotli_alloc.rs`, the C API (`ffi/`), the binary (`bin/`), the upstream tests (`test.rs`,
`test_metadata.rs`, `bit_reader/regression_tests.rs`, `huffman/tests.rs`), and `lib.rs` (replaced by `mod.rs`,
which exports only `BrotliDecompressStream`, `BrotliResult`, `BrotliState`, `HuffmanCode` and
`StandardAlloc`). `BrotliDecompressStreamWithDictionary` and the shared-dictionary code are part of the
vendored files but not reachable from the spillgate API.

## Changes that do not alter behavior (diff to the tag: 12 lines added in `decode.rs`, 9 in `state.rs`, 5 in `huffman/mod.rs`, the rest are deletions)

- Edition 2015 paths made 2021 paths (`use state::X` became `use super::state::X`, `&::shared_dictionary::` became
  `&super::shared_dictionary::`, `use core;` deleted). The code is compiled as part of an edition 2021 crate.
- The `unsafe` cargo feature of upstream is not carried over: the items that exist only with
  `feature = "unsafe"` (the `get_unchecked` macros in `memory.rs`, the `copy_nonoverlapping` variant in
  `memcpy_within_slice` in `decode.rs`) are deleted and the `cfg(not(feature = "unsafe"))` attributes on the safe
  variants are removed. The `ffi-api` only function `BrotliDecoderIsUsed` is deleted. **The vendored code
  contains no `unsafe` at all** (upstream has some only behind the `unsafe` feature and in `ffi/` and `bin/`,
  none of which is vendored). The crate-wide `#![forbid(unsafe_code)]` holds for it.
- The `#[cfg(test)]` / `#[cfg(all(test, feature = "std"))]` test modules inside the vendored files
  (`decode.rs`: `tests`, `safeguard_tests`, `state_guard_tests`, `metadata_block_tests`; `shared_dictionary.rs`,
  `transform.rs`, `bit_reader/mod.rs`: `tests`; `mod regression_tests;`; `mod tests;` in `huffman/mod.rs`) are removed:
  they use edition 2015 paths and an `std` feature this crate does not have. Their coverage is replaced by the
  differential test and the spillgate test suites.
- `mod.rs`: relaxed lints for this module only (third-party style: `warnings`, `clippy::*`,
  `missing_docs`).

## Behavior patches

None in this state (a plain 6.3.1; see the section below once a patch is applied).

## Differential test

`differential_tests.rs` (new, not upstream) runs this copy and the unpatched upstream crate (a
dev-dependency, `upstream-brotli-decompressor`, `=6.3.1`) side by side on the same input with the same input
chunking and output buffer sizes and requires the same verdict, the same output bytes and the same input
consumption, with no allowed difference: 400 encoder streams (4 payload kinds, 5 sizes, qualities 0/1/5/9/11,
windows 10/16/22/24), multi-megabyte multi-meta-block streams, hostile meta-block streams of free shapes
(including a large table set followed by small ones), 2400 damaged streams (bit flips, byte overwrites,
truncation, insertion) and random bytes.

Second reference, the previous vendored version (`upstream-brotli-decompressor-5`, `=5.0.0`, unpatched): on all
valid streams (encoder streams, multi-megabyte stream, hostile free shapes) the output, verdict and input
consumption must be identical to 5.0.0 (no regression). On damaged and random input 5.0.0 may differ (it lacks
the two fixes below that 6.x contains); only the output of streams both accept must be equal.
