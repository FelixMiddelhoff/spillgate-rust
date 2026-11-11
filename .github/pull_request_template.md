## What and why

## Checklist
- [ ] Test written first; it failed before the change
- [ ] New or changed rule: spec/SPEC.md, a conformance vector and a test with the ID in its name or a `Covers:` comment
- [ ] No expected outcome in conformance/manifest.json weakened
- [ ] `cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check`
- [ ] Public API change: docs/how-to.md, README.md and CHANGELOG.md updated, snippets still compile
- [ ] No dependency added (the `br` feature keeps its exact pin)
