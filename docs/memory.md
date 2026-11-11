# Memory bounds (SG-R-MEM-03)

spillgate never sizes an allocation from a value in the data (declared sizes, header fields,
lengths in the stream). What it does allocate is bounded by constants. The sizes below come from
the constants in `src/` (named in the table) and are checked by the tests named at the end.

| Part | Bound | Source |
| --- | --- | --- |
| Input meter buffer, per layer | 4 KiB fetched at a time from the source (`BUFFER_SIZE`) | `src/meter.rs` |
| One decode step, per layer | at most 64 KiB of output per codec call (`MAX_STEP`), whatever buffer size the caller reads with | `src/guard.rs` |
| DEFLATE decoder state (gzip, deflate), per layer | about 160 KiB: 32 KiB window (`WINDOW_SIZE`), two 2^15-entry `u16` code tables (64 KiB each), a few small tables | `src/inflate.rs` |
| gzip header fields | FNAME and FCOMMENT are refused above 512 bytes (`MAX_STRING`); the extra field is skipped, not buffered | `src/gzip.rs` |
| `Content-Encoding` header | at most 1024 bytes, 16 elements, tokens of at most 32 bytes | `src/header.rs` |
| Whole-body function (`decode_all`) | grows with the bytes actually produced; never preallocated from `max_output` or from a declared size | `src/decoder.rs` |

Per layer that is well under 1 MiB; a chain of 16 layers stays under 16 MiB plus the output
buffer of the caller. The DEFLATE state is allocated when a layer is created and freed when the
reader is closed or dropped (`SpillgateReader::close`). Streaming through `Decoder::reader` holds
no output: memory is constant whatever the decoded size. `decode_all` holds the bytes produced so
far, so its peak is the decoded size (at most `max_output`) plus the spare capacity of the growing
`Vec` (up to a factor of 2 while it reallocates); it returns no data if the decode fails, and the
partial buffer is freed.

The optional codecs add their decoder window, bounded by the window cap of the codec, not by
`max_output`:

| Codec | Default cap | Per stream |
| --- | --- | --- |
| feature `br` (`br::BrotliOptions::max_window_bits`) | 24 window bits (`2^24 - 16` bytes, about 16 MiB); range 10..=24 | the window, allocated by `brotli-decompressor` after the cap check, plus the decoder's tables (a few hundred KiB) |
| feature `zstd` (`zstd::ZstdOptions::max_window_bytes`) | 8 MiB (`DEFAULT_MAX_WINDOW`); range 1 KiB..=1 GiB | the window (grows with the output, never eagerly to the declared size) plus three block-sized buffers of at most 128 KiB (compressed block, regenerated block, literals) |

The cap is checked from the frame or stream header before anything is allocated: a hostile header
allocates nothing. A stream that asks for more is refused as `memory_limit`. Budget concurrent
streams: for example 64 open brotli streams at the default cap are about 1 GiB. Lower
`max_window_bits` / `max_window_bytes` on busy servers.

## What the tests measure

- `tests/core_memory.rs`: a 4 GiB bomb under a 100 MiB budget ends with `output_limit` after
  exactly 100 MiB; every read is at most 64 KiB; `decode_all` with `max_output` up to 2^63-1 does
  not preallocate (a preallocation of 2^45 bytes would abort); a failed `decode_all` returns no
  data; 2000 chains of 16 layers can be built and dropped.
- `tools/alloc-check` (own workspace, counting `#[global_allocator]`; `cargo test --manifest-path
  tools/alloc-check/Cargo.toml`): decoding a 4 GiB bomb peaks below 512 KiB of allocation above the
  baseline; the same through 16 pass-through layers peaks below 2 MiB; one-byte reads below
  256 KiB; `decode_all` of 3 MiB peaks at no more than twice the output plus 1 MiB, and of 4 bytes
  under `max_output` 2^63-1 below 256 KiB; after a failed `decode_all` less than 64 KiB is
  retained; after `close()` less than 16 KiB is held by a 16-layer reader.
- `src/zstd/tests.rs` and `src/inflate_tests.rs`: regression tests for lazy window growth, the
  window ring after a window-sized block, and block-sized scratch.

These test codecs are pass-through and zero generators, so the per-layer DEFLATE and window
figures above are derived from the allocation sizes in the source rather than measured by the
counting allocator; the bounds in the tests are the measured, enforced part.
