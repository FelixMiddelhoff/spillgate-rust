//! Helpers shared by `conformance.rs` and `spectrace.rs`.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root (where `conformance/` and `spec/` live).
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn read_manifest() -> Value {
    let text = std::fs::read_to_string(root().join("conformance").join("manifest.json")).expect("manifest.json");
    serde_json::from_str(&text).expect("manifest.json is valid JSON")
}

/// Every rule ID (`SG-R-AAA-nn`, `SG-I-nn`) mentioned anywhere in `text`.
pub fn rule_ids_in(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    let mut at = 0;
    while let Some(offset) = text[at..].find("SG-") {
        let start = at + offset;
        at = start + 3;
        let rest = &bytes[start + 3..];
        let end = match rest.first() {
            Some(b'R') if rest.get(1) == Some(&b'-') => {
                let letters = rest[2..].iter().take_while(|b| b.is_ascii_uppercase()).count();
                let digits_at = 2 + letters;
                if letters > 0
                    && rest.get(digits_at) == Some(&b'-')
                    && rest.get(digits_at + 1).is_some_and(u8::is_ascii_digit)
                    && rest.get(digits_at + 2).is_some_and(u8::is_ascii_digit)
                {
                    Some(start + 3 + digits_at + 3)
                } else {
                    None
                }
            }
            Some(b'I')
                if rest.get(1) == Some(&b'-')
                    && rest.get(2).is_some_and(u8::is_ascii_digit)
                    && rest.get(3).is_some_and(u8::is_ascii_digit) =>
            {
                Some(start + 3 + 4)
            }
            _ => None,
        };
        if let Some(end) = end {
            found.insert(text[start..end].to_string());
        }
    }
    found
}

/// The rules and invariants the spec defines: IDs in bold at the start of a line or bullet.
pub fn defined_rules(spec: &str) -> BTreeSet<String> {
    let mut defined = BTreeSet::new();
    for line in spec.lines() {
        let line = line.strip_prefix("- ").unwrap_or(line);
        if let Some(rest) = line.strip_prefix("**") {
            if let Some(close) = rest.find("**") {
                defined.extend(rule_ids_in(&rest[..close]));
            }
        }
    }
    defined
}

/// All files below `dir` (recursively), skipping build output and hidden directories.
pub fn files_below(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "target" && !name.starts_with('.') {
                files_below(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}
