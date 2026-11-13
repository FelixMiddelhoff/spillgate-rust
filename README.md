# spillgate

Decode untrusted compressed data under mandatory limits. A decompression bomb ends in a typed
`Error` instead of exhausting memory. Rust port of [spillgate](https://github.com/FelixMiddelhoff/spillgate):
it implements the shared specification (`spec/SPEC.md`) and passes the shared conformance corpus.

**New here? Read the [how-to guide](docs/how-to.md)**: choosing limits, wiring spillgate into
`reqwest`, `ureq`, `axum` and other data paths, mapping results to HTTP statuses, and finding the
places in your service that decompress today.

```rust
use spillgate::{Decoder, ErrorKind, Limits};
use std::io::Read;

fn handle(body: impl Read, content_encoding: &[&str]) -> Result<Vec<u8>, spillgate::Error> {
    // max_output is required; there is no unlimited mode.
    let decoder = Decoder::new(Limits::new(8 * 1024 * 1024))?;
    decoder.decode_all(body, content_encoding)
}

fn stream(body: impl Read) -> Result<(), Box<dyn std::error::Error>> {
    let decoder = Decoder::new(Limits::new(8 * 1024 * 1024).max_input(1 << 20))?;
    let mut reader = decoder.reader(body, &["gzip"])?; // header problems fail here
    let mut buf = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_n) => { /* use the bytes; discard everything if a later read fails */ }
            Err(e) => {
                let kind = spillgate::Error::from_io(&e).map(|e| e.kind());
                if kind == Some(ErrorKind::OutputLimit) { /* answer 413 */ }
                return Err(e.into());
            }
        }
    }
}
```

The API is synchronous (`std::io::Read`). In async code run it on a blocking thread
(`tokio::task::spawn_blocking`); the how-to shows how.

## Features

| Feature | Adds | Dependency |
| --- | --- | --- |
| (default) | `identity`, `gzip`, `deflate` (zlib and raw), own DEFLATE decoder | none |
| `br` | brotli, `spillgate::br` | vendored `brotli-decompressor` 6.3.1, unpatched (pure Rust, no `unsafe`), allocator crates `alloc-no-stdlib`, `alloc-stdlib` pinned exactly |
| `zstd` | zstd, `spillgate::zstd` (own decoder, no dictionaries) | none |

Register `br` and `zstd` with `Decoder::builder(limits).codec("br", br::codec(..)?)`; see the
how-to, section 3.8. Minimum supported Rust version: 1.85. `unsafe` is forbidden in the crate.

## Limits

| Setter | What it bounds | Default |
| --- | --- | --- |
| `Limits::new(max_output)` | bytes each layer may produce (required) | none |
| `max_layers` | non-identity encodings in a chain, 1..=16 | 5 |
| `max_ratio` | output bytes per consumed input byte | 1000 |
| `ratio_grace` | output size below which the ratio is not checked | 64 KiB |
| `max_input` | compressed bytes taken from the source (looking at the next byte does not count) | none |
| `disable_ratio_limit` | the one named opt-out of the ratio check | off |

Memory is bounded whatever the output size: a few hundred KiB per layer, plus the window of brotli
and zstd within their caps; `decode_all` additionally holds the bytes it produced (at most
`max_output`). See [docs/memory.md](docs/memory.md).

## Security model

- Every limit is checked before the bytes are handed out; no allocation is sized from a value in
  the data (declared sizes, headers, stream lengths).
- `Content-Encoding` is parsed strictly; a chain is limited in length and every layer has its own
  output and ratio budget, so a chain cannot multiply a bomb.
- Errors are typed (`ErrorKind`), sticky, and carry at most 32 bytes of quoted attacker data.
  `ErrorKind::http_status()` gives the status a server should answer.
- A panic in an extension codec becomes `ErrorKind::Internal`; the crate itself avoids `unwrap`,
  `expect`, `panic!` and unchecked indexing on input-derived data.
- `Decoder` is immutable and `Send + Sync`: share one per process. Readers are independent and not
  meant to be shared between threads. `CancelToken` + `Decoder::reader_with_cancel` stop a reader
  from another thread.

Not covered: the size of the compressed request you accept before spillgate, timeouts, archive
formats. See [SECURITY.md](SECURITY.md) to report a bypass.

## Status

Version 0.1 (not yet released); the API may still change before 1.0. All vectors of the shared
conformance corpus pass with `--all-features` and no skips; every rule of the specification is
named by a vector or a test (`tests/spectrace.rs`).

## Development

```text
cargo test --all-features
cargo test --manifest-path tools/alloc-check/Cargo.toml   # counting-allocator memory test
```

See [CONTRIBUTING.md](CONTRIBUTING.md). The design is in `docs/design.md`.

## License

MIT, see [LICENSE](LICENSE). The vendored brotli decoder (`src/vendored/brotli_decompressor`) is BSD-3-Clause, see the `LICENSE` file there.
