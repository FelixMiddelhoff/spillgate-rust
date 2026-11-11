# Releasing to crates.io

The workflow `.github/workflows/release.yml` publishes from a GitHub environment that needs your
approval. After the first release it uses crates.io **trusted publishing** (OpenID Connect): the
action `rust-lang/crates-io-auth-action` exchanges the workflow's identity for a short-lived
crates.io token that is revoked when the job ends, so no long-lived token exists anywhere.

Checked on 2026-11-11 against the crates.io announcement of trusted publishing, the RFC 3691 text
and the README of `rust-lang/crates-io-auth-action` (v1.0.6). Trusted publishing is configured in
the settings of an **existing** crate; crates.io has no "pending publisher" for a first release.
Re-check <https://crates.io/docs/trusted-publishing> before the first release; the web UI may have
changed.

## One-time setup (maintainer)

1. **GitHub environment.** Repository **Settings, Environments, New environment**, name
   `crates-io`. Add yourself under *Required reviewers*, so that every publish needs an explicit
   approval. Optionally restrict *Deployment branches and tags* to the pattern `v*`.
2. **crates.io account.** Verify your email address, turn on the protections your account offers,
   and keep your recovery options safe.
3. **First release.** The crate does not exist yet, so trusted publishing cannot be configured.
   For the first release only, create an **API token** on crates.io (*Account Settings, API Tokens*)
   with the scope *publish-new* limited to the crate name `spillgate`, the shortest expiry, and add
   it as a secret `CARGO_REGISTRY_TOKEN` of the environment `crates-io`. Do the first release soon
   after step 1: the name is reserved only by the first publish.
4. **Switch to trusted publishing.** After the first release, open the crate on crates.io, *Settings,
   Trusted Publishing, Add*, and enter: owner `FelixMiddelhoff`, repository `spillgate-rust`,
   workflow filename `release.yml`, environment `crates-io`. Then **delete the
   `CARGO_REGISTRY_TOKEN` secret and revoke the token.** Optionally enable the crate setting that
   requires trusted publishing for all publishes.

The workflow works in both phases: if the secret `CARGO_REGISTRY_TOKEN` exists it is used,
otherwise the OIDC token from `rust-lang/crates-io-auth-action`.

## Each release

1. Update `CHANGELOG.md` (move the Unreleased entries under the version and date) and set
   `version` in `Cargo.toml` (for example `0.1.0`; update `Cargo.lock` with `cargo update -w`).
   Commit to `main` and wait for a green CI.
2. Tag exactly that version and push the tag:
   ```
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
3. The `release` workflow checks that the tag equals the `Cargo.toml` version, runs the whole suite
   (all features, no skips) and the rule coverage check, packages the crate, installs the packaged
   crate into an empty project, and waits for your approval in the `crates-io` environment. After
   the approval it publishes with `cargo publish`.
4. Check from a clean directory: `cargo search spillgate`, then add the crate to a new project and
   build it. Check that <https://docs.rs/spillgate> built.
5. Create the GitHub release from the tag with the changelog text.

There is a single crate in the repository, so there is no publish order. (`crates/test-support` and
`tools/alloc-check` are `publish = false` helpers; the main crate lists only `src/**`, README,
LICENSE, CHANGELOG and `docs/**` in `include`.)

## Never

Never re-publish a version (crates.io refuses it). A wrong release is **yanked**
(`cargo yank --version 0.1.0 spillgate`, which blocks new dependents but keeps builds that already
locked it working) and fixed with the next patch version. Versions at or above 1.0 need separate,
explicit consent.
