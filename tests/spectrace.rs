//! Every rule and invariant of `spec/SPEC.md` must be covered: named in the `rules` of a conformance vector, or
//! in a file under `src/`, `tests/` or `crates/` (a `// Covers: <id>` comment or a test name). It is a checklist,
//! not proof that a test asserts everything a rule says.
//!
//! Set `SPILLGATE_SPECTRACE_WARN=1` to print the uncovered rules without failing (for use before all parts of
//! the port are merged).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::collections::BTreeSet;

#[test]
fn every_rule_is_covered() {
    let root = support::root();
    let spec = std::fs::read_to_string(root.join("spec").join("SPEC.md")).expect("spec/SPEC.md");
    let defined = support::defined_rules(&spec);
    assert!(
        defined.len() > 50,
        "found only {} rules in the spec: the extraction is broken",
        defined.len()
    );

    let manifest = support::read_manifest();
    let mut covered = BTreeSet::new();
    let mut unknown_in_vectors = BTreeSet::new();
    for vector in manifest["vectors"].as_array().expect("vectors") {
        for rule in vector["rules"].as_array().expect("rules") {
            let rule = rule.as_str().expect("rule id").to_string();
            if !defined.contains(&rule) {
                unknown_in_vectors.insert(format!("{} names {rule}", vector["id"].as_str().unwrap_or("?")));
            }
            covered.insert(rule);
        }
    }

    let mut files = Vec::new();
    for dir in ["src", "tests", "crates"] {
        support::files_below(&root.join(dir), &mut files);
    }
    for file in files {
        if let Ok(text) = std::fs::read_to_string(&file) {
            covered.extend(support::rule_ids_in(&text));
        }
    }

    let missing: Vec<&String> = defined.iter().filter(|id| !covered.contains(*id)).collect();
    println!(
        "defined: {}, covered: {}, uncovered: {}",
        defined.len(),
        defined.len() - missing.len(),
        missing.len()
    );
    for id in &missing {
        println!("uncovered: {id}");
    }
    for entry in &unknown_in_vectors {
        println!("names a rule the spec does not define: {entry}");
    }
    assert!(
        unknown_in_vectors.is_empty(),
        "vectors name rules the spec does not define: {unknown_in_vectors:?}"
    );
    let warn_only = std::env::var("SPILLGATE_SPECTRACE_WARN").is_ok_and(|v| v == "1");
    if !warn_only {
        assert!(
            missing.is_empty(),
            "{} rules are not covered: {missing:?}",
            missing.len()
        );
    }
}
