//! Parses the `generator` object of a manifest vector into a `Spec`.
//!
//! This file is shared: the support crate's tests and the root crate's `tests/conformance.rs` both include it
//! (the latter with `#[path]`), so it only names the crate through `spillgate_test_support`.

use serde_json::Value;
use spillgate_test_support::Spec;

fn text(params: &Value, key: &str) -> Result<String, String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing string param {key}"))
}

fn number(params: &Value, key: &str) -> Result<u64, String> {
    match params.get(key) {
        None => Ok(0),
        Some(v) => v
            .as_u64()
            .ok_or_else(|| format!("param {key} is not an unsigned integer")),
    }
}

/// Parse `{"kind": ..., "params": {...}}`.
pub fn parse(generator: &Value) -> Result<Spec, String> {
    let kind = generator
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("generator without kind")?;
    let params = generator.get("params").ok_or("generator without params")?;
    let window = u32::try_from(number(params, "window")?).map_err(|_| "window out of range".to_string())?;
    match kind {
        "zeros" => Ok(Spec::Zeros {
            codec: text(params, "codec")?,
            matches: number(params, "matches")?,
            size: number(params, "size")?,
            window,
        }),
        "data" => Ok(Spec::Data {
            codec: text(params, "codec")?,
            seed: number(params, "seed")?,
            size: number(params, "size")?,
            window,
        }),
        "wrap" => Ok(Spec::Wrap {
            codec: text(params, "codec")?,
            times: number(params, "times")?,
            inner: Box::new(parse(params.get("inner").ok_or("wrap without inner")?)?),
            window,
        }),
        other => Err(format!("unknown generator kind {other}")),
    }
}
