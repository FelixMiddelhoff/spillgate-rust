# spillgate-rust

Decode untrusted compressed data (HTTP `Content-Encoding` chains: gzip, deflate, and with crate
features brotli and zstd) under mandatory limits. A decompression bomb ends in a typed
[`Error`](https://docs.rs/spillgate) instead of exhausting memory. This crate is the Rust port of
spillgate; it implements `spec/SPEC.md` and passes the shared conformance corpus.

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

What it enforces: `max_output` per layer (required), an expansion ratio (default 1000 after a
64 KiB grace), an optional `max_input`, at most 5 layers (16 hard), strict `Content-Encoding`
parsing, bounded memory whatever the output size, sticky typed errors, and panic containment for
extension codecs.

- `Decoder` is immutable and `Send + Sync`: share one per process. Readers are independent and not
  meant to be shared between threads.
- Errors are `spillgate::Error` with `kind()`, `layer()`, `limit()`; from a reader they arrive as
  `io::Error` and `Error::from_io` gives the typed error back. A failing source is `source_error`
  with the original error as `source()`.
- Cancellation is not supported in 0.1; use timeouts on the source.

See [docs/how-to.md](docs/how-to.md) for the how-to guide, `docs/design.md` for the design and
`spec/SPEC.md` for the specification.

Tests: `cargo test`; the allocation checks need their own crate:
`cargo test --manifest-path tools/alloc-check/Cargo.toml`.

License: MIT.
