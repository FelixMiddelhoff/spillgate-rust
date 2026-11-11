# Contributing

## Run the checks

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features                     # unit, conformance vectors, differential and memory tests, doc tests
cargo test --release --all-features --test conformance   # with SPILLGATE_NO_SKIPS=1: the same vectors, optimized
cargo test --test spectrace                   # every rule of the specification is named by a test or vector
cargo test --manifest-path tools/alloc-check/Cargo.toml  # retained memory with a counting allocator
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

`SPILLGATE_NO_SKIPS=1` makes a vector that needs a missing codec feature fail instead of being
skipped. Without features, only the vectors for identity, gzip and deflate run. Fuzz targets are in
`fuzz/` (`cargo +nightly fuzz run <target>`, needs `cargo install cargo-fuzz`).

## Rules

- The specification comes first. Behavior that the spec does not describe is not added here: change `spec/SPEC.md` in the reference repository, add vectors there, then sync.
- A test names the rules it protects with `// Covers: SG-R-...` or in its name (`fn sg_r_lay_03_...`); `tests/spectrace.rs` reads that. It is a checklist, not proof that the test asserts everything the rule says. Review the assertions too.
- Test first for every bug. Never weaken a test or a conformance vector to make code pass.
- `conformance/` and `spec/` are copies. Do not edit them here; update them from the reference repository and record the release in `conformance/SOURCE`.
- The crate has no dependencies except `brotli-decompressor` behind the `br` feature (pinned exactly). `flate2`, `zstd` and friends are dev-dependencies for differential tests only and must never be used in `src/`.
- No `unsafe` (the crate forbids it, tests included; the counting allocator lives in `tools/alloc-check`). No `unwrap`, `expect`, `panic!` or unchecked indexing on input-derived data in `src/`; arithmetic on sizes from the stream is checked or saturating.
- Public API changes update `docs/how-to.md`, README and CHANGELOG in the same change; the how-to snippets are compiled by `cargo test --all-features --doc` and `tests/howto_snippets.rs`.
- MSRV is 1.85 for the default features. Do not raise it without a changelog entry.
- Code is read by people: short functions, a doc comment that explains why, rule IDs where a rule applies.
