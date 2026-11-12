# How to use spillgate in your Rust service

This guide is for the developers who build the service: where to put spillgate, how to choose the
limits, how to wire it into HTTP clients, web frameworks and other data paths, and what to do
with the results. The rules behind the library are in [spec/SPEC.md](../spec/SPEC.md); the API is
documented on [docs.rs](https://docs.rs/spillgate).

Code blocks marked `rust` are compiled as doc tests (`cargo test --all-features --doc`); the
behavior they describe is tested in `tests/howto_snippets.rs`. Blocks marked `rust,ignore` need a
crate that this repository does not depend on (named in the first comment line); they follow the
public APIs of those crates and are not compiled here, so check them against the versions you use.

**spillgate is a synchronous, `std::io::Read` based API.** It never spawns threads and never
awaits. In async code you run it on a blocking thread (section 3.3).

## 1. What spillgate protects you from

Any code that decompresses bytes someone else controls can be made to allocate gigabytes from a
few kilobytes (a decompression bomb): by one layer, by a chain of encodings
(`Content-Encoding: gzip, gzip, gzip, ...`), by lying size fields, or by exotic codecs. spillgate
sits in front of the decompressor and turns each of those into a typed [`Error`] with bounded
memory. It does not replace limits on the compressed size, timeouts or authentication (see "What
is not covered" at the end of section 3).

The rule of thumb: **every place where your service turns compressed bytes into plain bytes must
go through spillgate**. Section 6 shows how to find those places.

Rust makes this easy to get wrong in ways that are specific to the language:

- **`read_to_end` on a decoder has no bound.** `flate2::read::GzDecoder::new(r).read_to_end(&mut v)`
  (and `MultiGzDecoder`, `ZlibDecoder`, `DeflateDecoder`, the `bufread` and `write` variants,
  `brotli::Decompressor`, `zstd::Decoder`, `zstd::stream::decode_all`,
  `async-compression` decoders with `AsyncReadExt::read_to_end`) grows the `Vec` until the
  machine is out of memory. **Running out of memory aborts the process**: it is not a panic,
  `catch_unwind` does not see it, and no supervisor thread can recover it.
- **`Read::take(n)` truncates instead of failing.** `decoder.take(10 << 20).read_to_end(&mut v)`
  stops at the limit and returns `Ok`: a bomb and a legitimate 10 MiB body look the same, and the
  truncated data is processed as if complete. spillgate returns `ErrorKind::OutputLimit` and no
  data.
- **Allocation from a declared size.** The gzip trailer holds the size mod 2^32, a zstd frame
  header may declare up to 2^64 bytes, `Content-Length` is a claim. `Vec::with_capacity(declared)`,
  `zstd::bulk::decompress(data, capacity)` with a declared capacity and `BytesMut::with_capacity`
  from a header all let the sender choose your allocation. spillgate never sizes anything from
  such a value.
- **HTTP clients decode for you.** `reqwest` with its `gzip`, `brotli`, `zstd` or `deflate`
  features decodes automatically, adds those encodings to `Accept-Encoding`, and removes
  `Content-Encoding` and `Content-Length` from the response, so `bytes()`, `text()` and `json()`
  expand without a bound. `ureq` decodes gzip by default (cargo feature `gzip`). Other crates
  that bring these features in through your dependency tree turn them on for you, because cargo
  features are additive: check `cargo tree -e features -i reqwest`.
- **Server middleware decodes request bodies.** `tower-http`'s `RequestDecompressionLayer`
  (and `DecompressionLayer` on the client side) and `actix-web` (its `Payload` is decoded
  according to `Content-Encoding` when its `compress-*` features are on, which they are by
  default) hand your handler plain bytes. If such a layer sits before spillgate, spillgate only
  bounds data that has already been expanded.
- **Panics across threads.** A panic inside a decoder running on a worker thread ends that thread;
  `JoinHandle::join` or tokio's `JoinError` is the only trace, and with `panic = "abort"` the
  process dies. spillgate contains panics of codecs (also of your own, section 3.9) and returns
  `ErrorKind::Internal`.

[`Error`]: https://docs.rs/spillgate/latest/spillgate/struct.Error.html

## 2. Choose the limits

```rust
use spillgate::Limits;

let limits = Limits::new(8 * 1024 * 1024) // required: bytes each layer may produce
    .max_layers(3)                        // default 5, range 1..=16
    .max_ratio(1000)                      // default 1000
    .ratio_grace(64 * 1024)               // default 64 KiB
    .max_input(2 * 1024 * 1024);          // optional: compressed bytes taken from the source
# let _ = limits;
```

| Setter | What it bounds | Default |
| --- | --- | --- |
| `Limits::new(max_output)` | bytes **each layer** may produce (required, `1 ..= 2^63-1`) | none |
| `max_layers` | non-identity encodings in one chain (1..=16) | 5 |
| `max_ratio` | output bytes per input byte the decoder consumed (1..=2^31-1) | 1000 |
| `ratio_grace` | output size below which the ratio is not checked | 64 KiB |
| `max_input` | compressed bytes taken from the source | none |
| `disable_ratio_limit` | named opt-out of the ratio check; cannot be combined with `max_ratio` | off |

Limits are validated completely when the decoder is built: a missing, zero or out-of-range value
is `ErrorKind::InvalidLimits` from `Decoder::new` / `build`, never during traffic. There is no
unlimited mode and no default for `max_output`.

### max_output: the memory you are willing to spend

Think of it as "the largest legitimate body this endpoint should ever see, after decompression".
Do not use one global number:

| Data path | Starting point |
| --- | --- |
| JSON API request bodies | 1 to 10 MiB |
| HTML or JSON fetched from third parties | 8 to 32 MiB |
| File upload processed in memory (`decode_all`) | the largest file you accept, and no more |
| File upload streamed to disk | your storage quota per object |
| Message queue payloads | the broker's maximum message size times a small factor |

Look at the 99.9th percentile of real decoded sizes in production and add headroom. A limit 100
times larger than anything legitimate only helps the attacker. `decode_all` holds the whole body
in memory, so `max_output` is also its peak memory per call (it grows with the bytes produced and
is never preallocated from `max_output`); multiply by your concurrency (threads, tasks in
`spawn_blocking`).

### max_ratio and ratio_grace

The ratio is checked per layer and end to end. The default of 1000 stops the classic bombs (zeros
compress to about 1030:1 in DEFLATE at best) while ordinary data stays far below it. Raise it
only if a measured, legitimate data type needs it. Brotli and zstd can reach much higher ratios
on sparse data, so an endpoint that accepts, for example, large sparse arrays may need a higher
`max_ratio`. Prefer raising it for one endpoint over `disable_ratio_limit()`, which leaves only
`max_output` between you and a bomb. Leave `ratio_grace` alone; it keeps tiny messages from being
refused.

### max_layers

Real traffic uses one layer, rarely two. The default of 5 is generous; use 2 or 3 for public
endpoints. Chains of more than 16 elements are refused whatever you set.

### max_input

If the compressed size is not already bounded by your web server, framework or broker, add
`max_input`. spillgate bounds the output; it is not a substitute for limiting how many bytes you
accept. Do both.

`max_input` counts the bytes a codec takes, not the bytes it merely looks at. A stream of exactly
`max_input` bytes is fine even if the source holds more behind it; if there is data behind a
complete stream the result is `Corrupt` (trailing data), not `InputLimit`. `InputLimit` means the
decoder needed byte `max_input + 1` to go on. spillgate never asks the source for more than
`max_input + 1` bytes in total. (SG-R-INP-01, see `docs/porting-inp-probe.md` in the reference
repository.)

## 3. Wire it in

Create one `Decoder` at start-up and share it. It is immutable, `Send + Sync`, and holds no
buffers; the readers it returns are independent of each other and not meant to be shared between
threads.

```rust
use std::sync::OnceLock;
use spillgate::{Decoder, Limits};

static DECODER: OnceLock<Decoder> = OnceLock::new();

/// Call once in `main`, before serving. A bad configuration fails here, not on the first request.
pub fn init_decoder() -> Result<(), spillgate::Error> {
    let decoder = Decoder::new(Limits::new(8 * 1024 * 1024).max_layers(3).max_input(2 * 1024 * 1024))?;
    let _ = DECODER.set(decoder);
    Ok(())
}

pub fn decoder() -> &'static Decoder {
    DECODER.get().expect("init_decoder() runs at start-up")
}
# init_decoder().unwrap();
# assert!(decoder().decode_all(&b"plain"[..], &[]).is_ok());
```

(`Arc<Decoder>` in your application state works as well.)

`source` is anything that implements `std::io::Read`: `&[u8]`, a `File`, a `TcpStream`, a
`Cursor`. spillgate takes it by value (pass `&mut r` to keep yours) and never closes it. The
encodings are the `Content-Encoding` header field values **as received**, one `&str` per field
line: `&["gzip, br", "zstd"]`. Pass `&[]` for a body without the header; it is still bounded.

### 3.1 `reqwest`

`reqwest` decodes `Content-Encoding` for you when its `gzip`, `brotli`, `zstd` or `deflate`
features are on. Switch automatic decoding off per client, set `Accept-Encoding` yourself (so you
only ask for what the decoder supports), bound the compressed bytes while you collect them, and
decode on a blocking thread:

```rust,ignore
// needs: reqwest (with or without its decoding features), tokio, spillgate
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING};

const MAX_COMPRESSED: usize = 4 * 1024 * 1024;

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut resp = client
        .get(url)
        .header(ACCEPT_ENCODING, "gzip, deflate") // add br, zstd only if you registered them
        .send()
        .await?
        .error_for_status()?;
    let encodings: Vec<String> = resp
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .map(|v| v.to_str().map(str::to_owned))
        .collect::<Result<_, _>>()?; // a non-ASCII header value is a refusal, not "no encoding"
    let mut compressed = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if compressed.len() + chunk.len() > MAX_COMPRESSED {
            return Err("compressed body too large".into());
        }
        compressed.extend_from_slice(&chunk);
    }
    // decode_body is the function from section 3.3
    Ok(tokio::task::spawn_blocking(move || decode_body(&compressed, &encodings)).await??)
}

fn build_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_gzip() // these four exist when the matching cargo feature is on; they are
        .no_brotli() // the per-client switch. If a feature is off, delete its line:
        .no_zstd() // an off feature decodes nothing.
        .no_deflate()
        .build()
}
```

Better: build `reqwest` with `default-features = false` and none of the four decoding features
(`cargo tree -e features -i reqwest` shows who enabled them). Never call `resp.text()` or
`resp.json()` on a response whose body has not gone through spillgate.

### 3.2 `ureq`

`ureq` is blocking, so it fits spillgate directly. Build it without its decoding feature
(`ureq = { version = "...", default-features = false, features = ["tls"] }`; check the feature
names of the version you use) and set `Accept-Encoding` yourself; then the reader of the response
body yields the still-compressed bytes:

```rust,ignore
// needs: ureq (decoding features off), spillgate
use std::io::Read;

fn fetch(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let resp = ureq::get(url).set("Accept-Encoding", "gzip, deflate").call()?;
    let encodings: Vec<String> = resp.all("Content-Encoding").into_iter().map(str::to_owned).collect();
    let refs: Vec<&str> = encodings.iter().map(String::as_str).collect();
    // ureq 2 API shown; in ureq 3 take the body reader of `resp.into_body()`.
    Ok(decoder().decode_all(resp.into_reader().take(4 * 1024 * 1024), &refs)?)
}
```

The `take(4 MiB)` here bounds the *compressed* bytes and is the right use of `take`: a cut-off
compressed stream is `corrupt`, not a clean end. For a stricter and typed refusal use
`Limits::max_input` instead.

### 3.3 Web servers: request bodies (hyper, axum, actix-web, warp)

None of `hyper`, `axum` or `warp` decodes request bodies by itself; `tower-http`'s
`RequestDecompressionLayer` and `actix-web`'s automatic payload decoding do. **Do not use those
for untrusted clients**; remove the layer, or turn the `compress-*` features of actix-web off,
and let spillgate do the decoding.

The reliable pattern: bound the compressed bytes while collecting the body (`axum::body::to_bytes`
with a limit, `hyper`'s `http_body_util::Limited`, `DefaultBodyLimit`, a size check on `Content-Length`
and while streaming), then decode on a blocking thread. The synchronous part, which is compiled
and tested here:

```rust
use spillgate::{Decoder, Limits};

/// Decode a collected request body. The error is the HTTP status to answer and a fixed message.
pub fn decode_body(
    decoder: &Decoder,
    compressed: &[u8],
    content_encoding: &[&str],
) -> Result<Vec<u8>, (u16, &'static str)> {
    decoder
        .decode_all(compressed, content_encoding)
        .map_err(|e| (e.kind().http_status(), "request body refused"))
}
# let d = Decoder::new(Limits::new(1024)).unwrap();
# assert_eq!(decode_body(&d, b"hi", &[]).unwrap(), b"hi");
# assert_eq!(decode_body(&d, b"hi", &["compress"]).unwrap_err().0, 415);
```

axum, with that function (the handler never decodes in the async task, because decoding is CPU
work that would block the executor):

```rust,ignore
// needs: axum 0.8, tokio, spillgate
use axum::{body::Body, http::{header::CONTENT_ENCODING, HeaderMap, StatusCode}, response::IntoResponse};

async fn ingest(headers: HeaderMap, body: Body) -> impl IntoResponse {
    let Ok(compressed) = axum::body::to_bytes(body, 2 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response(); // bounds the compressed size
    };
    let mut encodings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        match value.to_str() {
            Ok(v) => encodings.push(v.to_owned()),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    }
    let result = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = encodings.iter().map(String::as_str).collect();
        decode_body(decoder(), &compressed, &refs)
    })
    .await;
    match result {
        Ok(Ok(plain)) => process(plain).into_response(),
        Ok(Err((status, msg))) => (StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), msg).into_response(),
        Err(_join_error) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
```

actix-web and warp follow the same shape: collect the (still compressed) bytes with a limit, read
the `Content-Encoding` values, run `decode_body` in `web::block` / `tokio::task::spawn_blocking`.
For actix-web, take the raw payload without the automatic decoder (for example by compiling it
without the `compress-*` features); with them on, the extractor already returned plain bytes.

**Streaming a large body without collecting it** needs a bridge between the async body and the
synchronous reader. `tokio_util::io::SyncIoBridge` turns an `AsyncRead` into a blocking `Read`; it
must be used on a thread where blocking is allowed, i.e. inside `spawn_blocking`:

```rust,ignore
// needs: tokio, tokio-util (feature "io-util"), futures-util, spillgate
use futures_util::TryStreamExt;
use std::io::Read;
use tokio_util::io::{StreamReader, SyncIoBridge};

async fn stream_to_file(body: axum::body::Body, encodings: Vec<String>, path: std::path::PathBuf) -> std::io::Result<()> {
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let async_read = StreamReader::new(stream);
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _enter = handle.enter(); // SyncIoBridge::new needs a runtime handle
        let source = SyncIoBridge::new(async_read).take(2 * 1024 * 1024); // bound compressed bytes
        let refs: Vec<&str> = encodings.iter().map(String::as_str).collect();
        copy_atomically(decoder(), source, &refs, &path) // section 3.5
    })
    .await
    .map_err(std::io::Error::other)?
}
```

It is a sync API on a blocking thread: each in-flight request occupies one thread of the blocking
pool for as long as the client sends, so a slow-loris client holds a thread. Put a timeout on the
body read in front of it, and cap the pool (`max_blocking_threads`).

### 3.4 `hyper` directly

With `hyper` 1.x use `http_body_util::BodyExt::collect` on a `http_body_util::Limited` body and
proceed as above. Do not add `tower_http::decompression` to the service stack.

### 3.5 Any other source: files, object storage, queues

Anything that is `Read` works. For a file, copy to a temporary file and rename it only on success
(the partial-data rule, section 3.6):

```rust
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use spillgate::Decoder;

pub fn copy_atomically<R: Read>(
    decoder: &Decoder,
    source: R,
    content_encoding: &[&str],
    final_path: &Path,
) -> io::Result<()> {
    let tmp = final_path.with_extension("part");
    let result = (|| {
        let mut reader = decoder.reader(source, content_encoding).map_err(io::Error::from)?;
        let mut out = File::create(&tmp)?;
        io::copy(&mut reader, &mut out)?; // an error here is a refusal; nothing is committed
        out.sync_all()
    })();
    match result {
        Ok(()) => fs::rename(&tmp, final_path),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}
```

For object storage (S3, GCS, Azure) take the body as a `Read` if the SDK offers one, or collect
the bytes with a size limit and pass `&bytes[..]`; async SDKs need the same `spawn_blocking`
pattern as above. For queues, the payload is a `&[u8]` and the encoding usually travels in a
message attribute. For content stored with a known encoding pass it yourself (`&["gzip"]`).
`flate2` and friends have no place in these paths.

### 3.6 Whole body versus streaming

- `decode_all` / `Decoder::decode_all`: simplest. You get the complete body or an error and **no
  data**. Peak memory is the decoded size, at most `max_output`, plus a copy while the buffer
  grows.
- `Decoder::reader`: streaming, a normal `Read` (`read`, `read_to_end`, `io::copy`, `BufReader`).
  **Bytes can be delivered before a later error.** Whatever you did with them (wrote to a file,
  fed a parser, stored in a database) must be undone when an error comes. Write to a temporary
  file and move it on success; never commit a partial body.

A single `read` returns at most 64 KiB whatever the size of your buffer, so a huge buffer does not
make spillgate allocate a huge buffer. Read until `Ok(0)`. Errors are sticky: after one, every
read returns an error of the same kind.

```rust
use std::io::{self, Read};
use spillgate::{Decoder, Error, ErrorKind, Limits};

/// Feed chunks to `sink`; the caller must discard what `sink` did if this returns an error.
pub fn pump(decoder: &Decoder, body: &[u8], mut sink: impl FnMut(&[u8])) -> io::Result<()> {
    let mut reader = decoder.reader(body, &["gzip"]).map_err(io::Error::from)?; // header problems fail here
    let mut buf = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf)? {
            0 => return Ok(()),
            n => sink(&buf[..n]),
        }
    }
}
# let d = Decoder::new(Limits::new(1024)).unwrap();
# let e = pump(&d, b"not gzip", |_| {}).unwrap_err();
# // the typed error is inside the io::Error
# assert_eq!(Error::from_io(&e).map(Error::kind), Some(ErrorKind::Corrupt));
```

The typed error survives `?` into a function that returns `io::Result`: at the edge of your
service, `Error::from_io(&e)` gives it back, and `Error::from_io(&e).map(Error::kind)` is enough
when you only branch on the kind.

### 3.7 Cancellation

`Decoder::reader_with_cancel(source, encodings, &token)` stops the reader with
`ErrorKind::Canceled` (sticky) once the `CancelToken` is canceled. The token is a clonable flag:
cancel it from a timer, a shutdown handler or another thread. It is looked at on every `read` and
whenever a layer fetches more input (at least once per 4 KiB of compressed input). It cannot
interrupt one codec step (at most 64 KiB of output), and it does **not** interrupt a blocking
`read` of your source: a stalled socket needs its own read timeout.

```rust
use std::io::Read;
use spillgate::{CancelToken, Decoder, Error, ErrorKind, Limits};

let decoder = Decoder::new(Limits::new(1 << 20))?;
let token = CancelToken::new();
let mut reader = decoder.reader_with_cancel(&b"plain bytes"[..], &[], &token)?;
token.clone().cancel(); // for example from a timeout thread
let mut buf = [0u8; 4096];
let error = loop {
    match reader.read(&mut buf) {
        Ok(0) => unreachable!("the token was canceled"),
        Ok(_) => {}
        Err(e) => break e,
    }
};
assert_eq!(Error::from_io(&error).map(Error::kind), Some(ErrorKind::Canceled));
# Ok::<(), Box<dyn std::error::Error>>(())
```

A canceled reader fails with `ErrorKind::Canceled` (an `io::ErrorKind::Other` wrapping the typed error), sticky, so `read_to_end`, `io::copy` and `BufReader` stop at once.

`spawn_blocking` tasks cannot be aborted once running; the token is how you stop one.

### 3.8 Brotli and zstd

Enable the crate features and register the codecs. Offer in `Accept-Encoding` only what you
registered:

```toml
spillgate = { version = "0.1", features = ["br", "zstd"] }
```

```rust
# #[cfg(all(feature = "br", feature = "zstd"))] {
use spillgate::{br, zstd, Decoder, Limits};

let decoder = Decoder::builder(Limits::new(8 * 1024 * 1024))
    .codec("br", br::codec(br::BrotliOptions { max_window_bits: 22 })?)
    .codec("zstd", zstd::codec(zstd::ZstdOptions { max_window_bytes: 4 * 1024 * 1024 })?)
    .build()?;
let accept_encoding = "gzip, deflate, br, zstd";
# let _ = (decoder, accept_encoding);
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

A stream that asks for a larger window than the cap fails with `ErrorKind::MemoryLimit` before a
byte is decoded (the window is read from the header; the large-window brotli extension is always
refused). The window is memory per in-flight request (see [memory.md](memory.md)): lower the caps
on busy servers. `br` uses a vendored copy of the pure Rust `brotli-decompressor` crate (no C, no
`unsafe`); `zstd` is an own decoder in this crate with no dependencies and no dictionary support
(a dictionary frame is `corrupt`).

Zstd has one more cost the output limits cannot see: frames that produce no output (empty frames,
skippable frames) cost CPU per input byte but no output. Always set `max_input` (or a body size
limit) on endpoints that accept zstd.

### 3.9 Your own codec

Implement `Codec` (a factory) and `CodecReader` (a decoding step) and register it on one decoder:

```rust
use std::io::BufRead;
use spillgate::{Codec, CodecReader, Decoder, Error, Limits};

/// Example: "rot" is the identity on bytes, XOR 0x20 (swaps ASCII case).
struct Rot;
struct RotReader<'a>(Box<dyn BufRead + 'a>);

impl CodecReader for RotReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = {
            let available = self.0.fill_buf().map_err(Error::from_input)?;
            let n = available.len().min(buf.len());
            for (out, byte) in buf.iter_mut().zip(&available[..n]) {
                *out = byte ^ 0x20;
            }
            n
        };
        self.0.consume(n); // consume only what was used: the ratio meter counts it
        Ok(n) // Ok(0) is the clean end, only when the input is at its end
    }
}

impl Codec for Rot {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(RotReader(input))
    }
}

let decoder = Decoder::builder(Limits::new(1 << 20)).codec("rot", Rot).build()?;
assert_eq!(decoder.decode_all(&b"hELLO"[..], &["rot"])?, b"Hello");
# Ok::<(), Box<dyn std::error::Error>>(())
```

The codec runs behind the same limiter, ratio meter and input meter as the built-in ones, so
even a careless codec cannot exceed `max_output`; a panic in it becomes `ErrorKind::Internal`.
Names must be lower-case tokens and must not reuse `identity`, `gzip`, `deflate` or `x-gzip`
(`build()` returns `ErrorKind::InvalidOption`). A codec must not allocate from values read from
the stream except its window within a cap; the contract is in the `codec` module docs.

### What is not covered

spillgate bounds the **decompressed** bytes, the ratio, the layers, memory and (optionally) the
compressed bytes it reads. It does not bound the size of the request you accept before it (use
your server's body limit), time (a client that sends one byte per minute; use timeouts on the
socket and on the whole request), CPU of work after decoding (parsers, schema validation), or
archive formats (`tar`, `zip`: bound entry counts and sizes separately). It does not check
authentication or content types.

## 4. Handle the results

Every refusal is a `spillgate::Error` with a `kind()` (`ErrorKind`, `#[non_exhaustive]`: keep a
wildcard arm), the `layer()` that failed (1 reads from the source) and the `limit()` that was
exceeded. From `decode_all` and `reader` you get it directly; from a reader's `read` you get an
`io::Error` and `Error::from_io(&e)` gives the typed error back (`None` means a plain I/O error
that did not come from spillgate). `kind().http_status()` is the mapping below.

```rust
use spillgate::{Error, ErrorKind};

/// Log, count and answer; returns the HTTP status for a server.
pub fn refusal(error: &Error) -> u16 {
    match error.kind() {
        ErrorKind::Internal | ErrorKind::MemoryLimit => {
            eprintln!("ERROR decoder problem: {} layer={}", error.kind(), error.layer());
        }
        ErrorKind::SourceError | ErrorKind::Canceled => {
            eprintln!("DEBUG decode interrupted: {}", error.kind()); // not an attack signal
        }
        _ => eprintln!("WARN refused: {} layer={} limit={}", error.kind(), error.layer(), error.limit()),
    }
    // counter!("refusals", "kind" => error.kind().as_str()).increment(1); // your metrics
    error.kind().http_status()
}
# assert_eq!(refusal(&Error::new(ErrorKind::OutputLimit, "x")), 413);
```

### What each outcome means and what to do

| Kind (`as_str`) | Meaning | Server answers (`http_status`) | Client side | Log / metric |
| --- | --- | --- | --- | --- |
| `OutputLimit` (`output_limit`) | the data decodes to more than `max_output` | 413 | treat the response as failed, do not retry | warn, count; a spike is an attack or a limit that is too low |
| `RatioLimit` | expansion over `max_ratio` | 413 | failed, do not retry | warn, count; check if a legitimate data type needs a higher ratio |
| `LayerLimit` | more layers or elements than allowed | 413 | failed, do not retry | warn, count |
| `InputLimit` | more compressed bytes than `max_input` | 413 | failed, do not retry | warn, count |
| `UnsupportedEncoding` | a valid token the decoder cannot handle (`compress`, `dcz`, `aes128gcm`, ...) | 415 | failed; nothing was decoded | info; shows clients using something you do not offer |
| `MalformedEncoding` | the header breaks the strict grammar | 400 | failed | info, bounded text only |
| `Corrupt` | the stream is invalid, truncated or has trailing data | 400 | may retry once if the connection was cut; a repeat is a bad server | info |
| `MemoryLimit` | a brotli or zstd stream needs a larger window than the cap | 413 | failed, do not retry | warn; check the cap if legitimate traffic hits it |
| `SourceError` | your source (network, disk) failed; the original `io::Error` is `Error::source()` | 400 (or 5xx by your policy) | retry by your usual policy | the cause is in `source()` |
| `Canceled` | your `CancelToken` was canceled | 503, usually no response is needed | no retry by itself | debug |
| `Internal` | a codec or source broke its contract (a panic, no progress) | 500 | failed | **error and alert**: please report it (see `SECURITY.md`) |
| `InvalidLimits`, `InvalidOption` | bad configuration | 500 | - | returned by `Decoder::new` / `build`, never during traffic |

The status column is exactly what `ErrorKind::http_status()` returns, the same mapping as in the
other spillgate ports: 413 for output, ratio, layer and input limits, 415 for unsupported
encodings, 400 for malformed header, corrupt data and a failed read, 503 for
cancellation, 500 otherwise.

General rules:

1. **Any error means the whole body is unusable**, including the bytes you already received.
2. **Never retry a limit error.** The same input gives the same result and costs the same work.
3. **Match on `kind()`, do not parse messages.** Keep a wildcard arm: new kinds can appear in a
   minor version.
4. **Do not echo error details to the caller.** Return a fixed message and the status code. The
   library's own messages contain at most 32 bytes of attacker data, quoted and escaped
   (`quote_untrusted`), but your logs and responses are your decision; log the kind, layer, limit
   and a request ID, not the body.
5. **Treat repeated limit errors from one client as abuse**: rate-limit or block like other
   malformed input. One `RatioLimit` can be an accident; thousands from one address are not.
6. **Alert on `Internal` and `MemoryLimit`** rather than on the limit errors you expect.
7. **Do not `unwrap` or `expect` a decode result in a request path.** A refusal is the normal
   outcome for hostile input; a panic in a handler is a denial of service.

### Tuning after launch

Run for a few days with the limits at their intended values and count refusals per endpoint. If
legitimate traffic is refused, raise the specific limit for that endpoint by the smallest amount
that fixes it and write down why. Do not switch limits off to make an alert go away.

## 5. Test your integration

1. **Build a bomb and see it refused.** 20 MB of zeros compress to about 20 KB. `flate2` is fine
   in tests (`[dev-dependencies]`); it must not be in the request path:

   ```rust
   use std::io::Write;
   use flate2::{write::GzEncoder, Compression};
   use spillgate::{Decoder, ErrorKind, Limits};

   fn gzip_bomb(size: usize) -> Vec<u8> {
       let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
       encoder.write_all(&vec![0u8; size]).unwrap();
       encoder.finish().unwrap()
   }

   let decoder = Decoder::new(Limits::new(1 << 20)).unwrap();
   let error = decoder.decode_all(&gzip_bomb(20_000_000)[..], &["gzip"]).unwrap_err();
   assert_eq!(error.kind().http_status(), 413);
   assert!(matches!(error.kind(), ErrorKind::OutputLimit | ErrorKind::RatioLimit));
   ```

   Then send the same bomb to your endpoint in an integration test and assert on `413`. For
   larger or exotic cases use the generated inputs of the conformance corpus
   ([conformance/](../conformance), built by `crates/test-support`).
2. **Test every ingress.** Each endpoint and background consumer gets a bomb test, a test with
   `Content-Encoding: gzip, gzip, gzip, gzip, gzip, gzip, gzip`, one with an unknown encoding
   (`Content-Encoding: compress`, expect 415) and one with a truncated body (expect 400).
3. **Check memory.** Decode a bomb in a test binary with a counting `#[global_allocator]` and
   assert on the peak: this repository does exactly that in `tools/alloc-check` (a counting
   allocator needs `unsafe`, so it lives in its own workspace). For a whole service use
   `ulimit -v` / a container memory limit in the integration test and check that the process
   survives the bomb.
4. **Test the partial-data rule.** Make the downstream step fail midway (or truncate the input)
   and check that nothing from the failed body is committed.

## 6. Find and fix the places that decompress today

Search your code:

```text
grep -rnE "GzDecoder|ZlibDecoder|DeflateDecoder|MultiGzDecoder|brotli::|zstd::|decode_all|async_compression|read_to_end|with_capacity\(.*(len|size)|RequestDecompression|DecompressionLayer|\.bytes\(\)|\.text\(\)|\.json\(\)|\.gzip\(|no_gzip|auto_decompress" src/
```

And your dependency tree (`cargo tree -e features`): look for `flate2`, `miniz_oxide`, `brotli`,
`zstd`, `async-compression`, `reqwest/gzip`, `reqwest/brotli`, `reqwest/zstd`, `reqwest/deflate`,
`ureq/gzip`, `tower-http/decompression-*`, `actix-http/compress-*`. Then look at what decodes
without you asking:

- HTTP clients: `reqwest` (`bytes()`, `text()`, `json()`, `chunk()` after automatic decoding),
  `ureq`, `isahc`, `surf`, SDKs that wrap them (cloud SDKs, API clients, `octocrab`, `aws-sdk-*`
  response handling). Pass them a client configured as in section 3, or read the raw body
  yourself.
- Web servers and frameworks: `tower-http` decompression layers, actix-web payload decoding,
  reverse proxies that decompress for you, gRPC (`tonic` has `accept_compressed` /
  `send_compressed`; configure it deliberately), message-queue clients with automatic
  decompression.
- Object storage and file helpers: `object_store`, `arrow`/`parquet` readers, `csv` over a
  decoder, `tar` + `flate2` and `zip` (archives are out of scope for spillgate; bound them
  separately).

For each, replace the decoder with spillgate or make sure it never sees unbounded data.

## 7. Pitfalls

- **Decoding in two places.** If a proxy, middleware or client library decodes before spillgate,
  spillgate only bounds the plain data and the bomb has already been expanded. Make sure
  spillgate is the first decoder in the path.
- **Cargo features are additive.** Another crate in your tree can switch on `reqwest/gzip` for
  you. Set the client option (`no_gzip()` and friends) as well as the features.
- **Reading the body twice.** After an error the reader is spent. Do not fall back to "just read
  it plainly".
- **`Read::take` as a limit.** It truncates silently. Use `Limits`.
- **A huge `max_output` "to be safe".** It makes the guard useless. Size it from data.
- **`disable_ratio_limit()` as a first reaction.** See the tuning section.
- **Unbounded concurrency.** Each in-flight `decode_all` may hold up to `max_output` bytes; each
  streaming reader holds a few hundred KiB (more with `br` or `zstd`: the window). Size the
  blocking pool and the semaphore in front of it accordingly.
- **Blocking the async executor.** The reader is synchronous. Use `spawn_blocking` (or a
  dedicated thread pool) for anything beyond a few KiB.
- **Decoding in a detached thread.** A panic or a refusal there is lost unless you join the
  handle; use `spawn_blocking(..).await` and handle `JoinError`.
- **Treating `identity` as safe.** An unencoded body is bounded as well; that is deliberate.
- **`unwrap()` on decode results, and `Box<dyn Error>` that hides the kind.** Keep the
  `ErrorKind` until you have mapped it to a status.

## 8. Checklist before you ship

- [ ] One shared `Decoder`, created at start-up (a bad config fails there), limits chosen per data path from real sizes.
- [ ] Every ingress (HTTP client, web endpoint, queue consumer, file or object reader) goes through spillgate; no other decoder runs before it.
- [ ] HTTP libraries are told not to decode (`no_gzip()` and friends, features off, `RequestDecompressionLayer` removed), and `Accept-Encoding` is set explicitly (no `br`/`zstd` unless you registered them).
- [ ] The compressed size is bounded separately (server body limit, `max_input`).
- [ ] Decoding runs on a blocking thread in async code; the blocking pool and concurrency are capped.
- [ ] Streaming consumers discard or roll back partial data on any error.
- [ ] Limit errors map to 413, unsupported encodings to 415, malformed or corrupt data to 400 (`ErrorKind::http_status`).
- [ ] Metrics per kind; alerts on `Internal` and `MemoryLimit`; refusals visible per endpoint.
- [ ] No retries of limit errors; no echoing of attacker-supplied text; no `unwrap` on decode results.
- [ ] Bomb, deep-chain, unknown-encoding and truncation tests exist for every ingress and run in CI.
- [ ] You know who gets the report if `Internal` appears (see [SECURITY.md](../SECURITY.md)).
