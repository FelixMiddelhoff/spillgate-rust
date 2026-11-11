//! Runs the shared conformance corpus (`conformance/SCHEMA.md`) against this implementation.
//!
//! Vectors that need the optional codec `br` or `zstd` run only with the matching crate feature; without it they
//! are skipped and counted, unless `SPILLGATE_NO_SKIPS=1` (then they fail). Run it in release mode: the large
//! vectors decode tens of megabytes.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

#[path = "../crates/test-support/src/json_spec.rs"]
mod json_spec;
mod support;

use serde_json::Value;
use sha2::{Digest, Sha256};
use spillgate::{Decoder, DecoderBuilder, Error, Limits};
use spillgate_test_support::{generate, sha256_hex};
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Every vector must give the same result for these read sizes (SG-R-RDR-01). `-1` is "MaxOutput + 1, capped".
const ALTERNATIVE_PATTERNS: [&[i64]; 5] = [&[1], &[3], &[4096], &[-1], &[1, 7, 4096, 1]];

/// The cap of the `-1` read size.
const MAX_READ: u64 = 32 * 1024 * 1024;

/// A source that counts the bytes taken and the reads made, to prove what was taken (SG-R-INP-02, SG-R-HDR-09).
struct SpySource {
    data: Arc<Vec<u8>>,
    pos: usize,
    reads: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

impl Read for SpySource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        self.total.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// One limit value: a JSON number, or a decimal string for values above 2^53-1. Values the API cannot even express
/// (negative, fractional, unparsable) become `invalid`, a value the limit's range check refuses (0).
fn limit_value(value: &Value) -> u64 {
    match value {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn build_limits(vector: &Value) -> Limits {
    let raw = &vector["limits"];
    // An absent max_output is expressed as 0: both are invalid_limits (SG-R-LIM-01).
    let mut limits = Limits::new(raw.get("max_output").map_or(0, limit_value));
    if let Some(v) = raw.get("max_layers") {
        limits = limits.max_layers(u32::try_from(limit_value(v)).unwrap_or(u32::MAX));
    }
    if let Some(v) = raw.get("ratio_grace") {
        limits = limits.ratio_grace(limit_value(v));
    }
    if let Some(v) = raw.get("max_input") {
        limits = limits.max_input(limit_value(v));
    }
    match raw.get("max_ratio") {
        Some(Value::String(s)) if s == "none" => limits = limits.disable_ratio_limit(),
        Some(v) => limits = limits.max_ratio(limit_value(v)),
        None => {}
    }
    limits
}

fn needed_codecs(vector: &Value) -> Vec<String> {
    vector["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str()?.strip_prefix("needs-").map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn codec_available(name: &str) -> bool {
    (name == "br" && cfg!(feature = "br")) || (name == "zstd" && cfg!(feature = "zstd"))
}

/// The largest brotli window bits (10..24) whose window, 2^n - 16 bytes, fits `limit`.
#[cfg(feature = "br")]
fn window_bits_within(limit: u64) -> u32 {
    let mut bits = 10;
    while bits < 24 && (1u64 << (bits + 1)) - 16 <= limit {
        bits += 1;
    }
    bits
}

#[cfg_attr(not(any(feature = "br", feature = "zstd")), allow(unused_variables, unused_mut))]
fn add_codec(mut builder: DecoderBuilder, name: &str, memory_cap: u64) -> Result<DecoderBuilder, String> {
    match name {
        #[cfg(feature = "br")]
        "br" => {
            let mut options = spillgate::br::BrotliOptions::default();
            if memory_cap != 0 {
                options.max_window_bits = window_bits_within(memory_cap) as _;
            }
            let codec = spillgate::br::codec(options).map_err(|e| format!("br codec: {e}"))?;
            builder = builder.codec("br", codec);
            Ok(builder)
        }
        #[cfg(feature = "zstd")]
        "zstd" => {
            let mut options = spillgate::zstd::ZstdOptions::default();
            if memory_cap != 0 {
                options.max_window_bytes = memory_cap as _;
            }
            let codec = spillgate::zstd::codec(options).map_err(|e| format!("zstd codec: {e}"))?;
            builder = builder.codec("zstd", codec);
            Ok(builder)
        }
        other => Err(format!("codec {other} is not available")),
    }
}

fn outcome_of_io(error: &std::io::Error) -> String {
    match Error::from_io(error) {
        Some(e) => e.kind().as_str().to_string(),
        None => format!("other: {error}"),
    }
}

struct ReadResult {
    delivered: u64,
    digest: String,
    error: Option<std::io::Error>,
}

fn read_with_pattern(reader: &mut dyn Read, pattern: &[i64], max_output: u64) -> ReadResult {
    let sizes: Vec<usize> = pattern
        .iter()
        .map(|&s| {
            if s < 0 {
                (max_output.min(MAX_READ - 1) + 1) as usize
            } else {
                s as usize
            }
        })
        .collect();
    let mut buf = vec![0u8; sizes.iter().copied().max().unwrap_or(1)];
    let mut digest = Sha256::new();
    let mut delivered = 0u64;
    for i in 0usize.. {
        let size = sizes[i % sizes.len()];
        match reader.read(&mut buf[..size]) {
            Ok(0) => break,
            Ok(n) => {
                digest.update(&buf[..n]);
                delivered += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return ReadResult {
                    delivered,
                    digest: hex(digest),
                    error: Some(e),
                };
            }
        }
    }
    ReadResult {
        delivered,
        digest: hex(digest),
        error: None,
    }
}

fn hex(digest: Sha256) -> String {
    digest.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn skip_tiny(vector: &Value, pattern: &[i64]) -> bool {
    let e = &vector["expect"];
    let expected = ["length", "delivered_exactly", "delivered_at_most"]
        .iter()
        .find_map(|k| e.get(*k).map(limit_value))
        .unwrap_or(0);
    expected > 4 * 1024 * 1024 && pattern.iter().any(|&s| (0..64).contains(&s))
}

fn run_pattern(vector: &Value, stream: &Arc<Vec<u8>>, pattern: &[i64]) -> Result<(), String> {
    let id = vector["id"].as_str().unwrap_or("?");
    let label = format!("{id} read pattern {pattern:?}");
    let expect = &vector["expect"];
    let want_outcome = expect["outcome"].as_str().unwrap_or("?");
    let reads = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(0));
    let source = SpySource {
        data: stream.clone(),
        pos: 0,
        reads: reads.clone(),
        total: total.clone(),
    };

    let encodings: Vec<&str> = vector["encodings"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let strict_zlib = vector["options"]["strict_zlib"].as_bool() == Some(true);
    let memory_cap = vector["options"].get("memory_cap").map_or(0, limit_value);
    let max_output = vector["limits"].get("max_output").map_or(0, limit_value);

    let built = (|| -> Result<_, Result<Error, String>> {
        let mut builder = Decoder::builder(build_limits(vector)).strict_zlib(strict_zlib);
        for name in needed_codecs(vector) {
            builder = add_codec(builder, &name, memory_cap).map_err(Err)?;
        }
        let decoder = builder.build().map_err(Ok)?;
        decoder.reader(source, &encodings).map_err(Ok)
    })();

    let expect_construct = expect["phase"].as_str() == Some("construct");
    let mut reader = match built {
        Err(Err(message)) => return Err(format!("{label}: {message}")),
        Err(Ok(error)) => {
            if !expect_construct {
                return Err(format!("{label}: unexpected construction error {error}"));
            }
            let got = error.kind().as_str();
            if got != want_outcome {
                return Err(format!(
                    "{label}: construction error {got}, want {want_outcome}: {error}"
                ));
            }
            if reads.load(Ordering::Relaxed) != 0 {
                return Err(format!("{label}: the source was read before the construction error"));
            }
            return Ok(());
        }
        Ok(reader) => {
            if expect_construct {
                return Err(format!("{label}: expected {want_outcome} at construction"));
            }
            reader
        }
    };

    let result = read_with_pattern(&mut reader, pattern, max_output);
    let outcome = match &result.error {
        None => "ok".to_string(),
        Some(e) => outcome_of_io(e),
    };
    let checked = check_outcome(vector, &label, &result, &outcome, max_output);
    // Sticky (SG-R-LAY-05): further reads return the same outcome and no data.
    let mut sticky = Ok(());
    if checked.is_ok() {
        for _ in 0..3 {
            let mut one = [0u8; 16];
            let again = match reader.read(&mut one) {
                Ok(0) => "ok".to_string(),
                Ok(n) => format!("{n} more bytes"),
                Err(e) => outcome_of_io(&e),
            };
            if again != outcome {
                sticky = Err(format!("{label}: not sticky: {outcome} then {again}"));
                break;
            }
        }
    }
    reader.close();
    checked?;
    sticky?;
    if let Some(cap) = vector["limits"].get("max_input").map(limit_value) {
        let taken = total.load(Ordering::Relaxed);
        if taken > cap.saturating_add(1) {
            return Err(format!("{label}: took {taken} bytes from the source (SG-R-INP-02)"));
        }
    }
    Ok(())
}

fn check_outcome(vector: &Value, label: &str, r: &ReadResult, outcome: &str, max_output: u64) -> Result<(), String> {
    let expect = &vector["expect"];
    let want = expect["outcome"].as_str().unwrap_or("?");
    if r.delivered > max_output {
        return Err(format!("{label}: delivered {} > max_output {max_output}", r.delivered));
    }
    if outcome != want {
        let detail = r.error.as_ref().map(ToString::to_string).unwrap_or_default();
        return Err(format!(
            "{label}: outcome {outcome}, want {want} (delivered {}; {detail})",
            r.delivered
        ));
    }
    if want == "ok" {
        let length = expect["length"].as_u64().unwrap_or(u64::MAX);
        if r.delivered != length {
            return Err(format!("{label}: delivered {}, want {length}", r.delivered));
        }
        if expect["sha256"].as_str() != Some(r.digest.as_str()) {
            return Err(format!("{label}: wrong data"));
        }
        return Ok(());
    }
    if expect["phase"].as_str() != Some("read") {
        return Err(format!("{label}: a read error but a construction error was expected"));
    }
    if let Some(exact) = expect.get("delivered_exactly").map(limit_value) {
        if r.delivered != exact {
            return Err(format!("{label}: delivered {}, want exactly {exact}", r.delivered));
        }
    }
    if let Some(most) = expect.get("delivered_at_most").map(limit_value) {
        if r.delivered > most {
            return Err(format!("{label}: delivered {}, want at most {most}", r.delivered));
        }
    }
    if let Some(layer) = expect.get("layer").map(limit_value) {
        if let Some(e) = r.error.as_ref().and_then(Error::from_io) {
            if e.layer() as u64 != layer {
                return Err(format!("{label}: error in layer {}, want {layer}", e.layer()));
            }
        }
    }
    Ok(())
}

fn build_input(vector: &Value) -> Result<Vec<u8>, String> {
    let id = vector["id"].as_str().unwrap_or("?");
    let input = &vector["input"];
    let stream = match input.get("generator") {
        Some(g) => {
            generate(&json_spec::parse(g).map_err(|e| format!("{id}: {e}"))?).map_err(|e| format!("{id}: {e}"))?
        }
        None => {
            let file = input["file"]
                .as_str()
                .ok_or_else(|| format!("{id}: input without file or generator"))?;
            std::fs::read(support::root().join("conformance").join(file)).map_err(|e| format!("{id}: {file}: {e}"))?
        }
    };
    if Some(sha256_hex(&stream).as_str()) != input["sha256"].as_str() {
        return Err(format!(
            "{id}: the input differs from the manifest (generator or file drift)"
        ));
    }
    Ok(stream)
}

fn run_vector(vector: &Value) -> Result<(), String> {
    let stream = Arc::new(build_input(vector)?);
    let first: Vec<i64> = vector
        .get("read_pattern")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_else(|| vec![4096]);
    let mut patterns: Vec<&[i64]> = vec![&first];
    patterns.extend(ALTERNATIVE_PATTERNS);
    for pattern in patterns {
        if !skip_tiny(vector, pattern) {
            run_pattern(vector, &stream, pattern)?;
        }
    }
    Ok(())
}

#[test]
fn conformance_corpus() {
    let no_skips = std::env::var("SPILLGATE_NO_SKIPS").is_ok_and(|v| !["", "0", "false", "no"].contains(&v.as_str()));
    let manifest = support::read_manifest();
    let (mut passed, mut skipped) = (0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    for vector in manifest["vectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().unwrap_or("?");
        if let Some(missing) = needed_codecs(vector).into_iter().find(|c| !codec_available(c)) {
            if no_skips {
                failures.push(format!(
                    "{id}: needs the optional codec {missing}, which is not enabled"
                ));
            } else {
                skipped += 1;
            }
            continue;
        }
        match catch_unwind(AssertUnwindSafe(|| run_vector(vector))) {
            Ok(Ok(())) => passed += 1,
            Ok(Err(message)) => failures.push(message),
            Err(_) => failures.push(format!("{id}: panicked")),
        }
    }
    println!(
        "conformance: {passed} passed, {skipped} skipped, {} failed",
        failures.len()
    );
    for failure in &failures {
        println!("FAIL {failure}");
    }
    assert!(
        failures.is_empty(),
        "{} vectors failed, first: {}",
        failures.len(),
        failures[0]
    );
}

#[test]
fn the_manifest_is_well_formed() {
    let spec = std::fs::read_to_string(support::root().join("spec").join("SPEC.md")).expect("spec");
    let rules = support::defined_rules(&spec);
    let manifest = support::read_manifest();
    assert_eq!(manifest["schema_version"], 1);
    let vectors = manifest["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 200);
    let mut seen = std::collections::BTreeSet::new();
    for vector in vectors {
        let id = vector["id"].as_str().expect("id");
        let ok = id
            .strip_prefix("SG-V-")
            .and_then(|r| r.split_once('-'))
            .is_some_and(|(family, n)| {
                !family.is_empty()
                    && family.bytes().all(|b| b.is_ascii_uppercase())
                    && n.len() == 4
                    && n.bytes().all(|b| b.is_ascii_digit())
            });
        assert!(ok, "bad vector id {id}");
        assert!(seen.insert(id.to_string()), "duplicate {id}");
        assert!(
            vector["description"].as_str().is_some_and(|d| !d.is_empty()),
            "{id}: no description"
        );
        let named = vector["rules"].as_array().expect("rules");
        assert!(!named.is_empty(), "{id}: no rules");
        for rule in named {
            let rule = rule.as_str().expect("rule");
            assert!(rules.contains(rule), "{id} names an undefined rule {rule}");
        }
        let sha = vector["input"]["sha256"].as_str().expect("sha256");
        assert!(
            sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{id}: bad sha256"
        );
    }
}
