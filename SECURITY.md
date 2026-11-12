# Security policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting: the repository's **Security** tab,
**Report a vulnerability**. Please do not open a public issue for a bypass.

A bypass is any input that makes the library deliver more than the configured limits, pass an
unsupported or malformed encoding through, panic or abort instead of returning an `Error`, loop
without bound, or use memory that grows with the output instead of staying bounded.

What to expect:

- acknowledgment within 3 business days
- coordinated disclosure, up to 90 days from the report
- credit in the advisory if you want it
- no bug bounty

Every fixed bypass becomes a permanent conformance vector in the reference repository
([spillgate](https://github.com/FelixMiddelhoff/spillgate)), so all language implementations get it.

## Supported versions

The latest release only.

## Scope

The limits, header parsing, the DEFLATE decoder, gzip and deflate framing, the reader contract,
the own zstd decoder (feature `zstd`) and the window and input handling around brotli (feature
`br`) are in scope. Feature `br` uses a vendored copy of the `brotli-decompressor` crate (5.0.0, with the changes
listed in `src/vendored/brotli_decompressor/VENDORED.md`): flaws that are also in upstream go
upstream, but report them to us too, and report anything the limiter should have contained. Bugs in the Rust standard library, the compiler or other crates are reported
upstream; tell us as well if the limiter should have contained them.

The crate forbids `unsafe` code. A memory-safety problem in it is a bug in a dependency or the
compiler, and equally a reportable bypass.
