//! Strict parsing of `Content-Encoding` field values (SPEC section 4).
//!
//! The evaluation order is normative because it decides the outcome class when several faults are
//! present: total length, then element grammar left to right, then element count, then support
//! (alias resolution), then layer count. This module does steps 1 to 3 ([`parse_content_encoding`])
//! and step 4 and 5 given a support predicate ([`resolve_layers`]).

use crate::error::{quote_untrusted, Error, ErrorKind};

/// SG-R-HDR-02: longest joined list, in bytes.
pub(crate) const MAX_HEADER_LENGTH: usize = 1024;
/// SG-R-HDR-06: most elements, counting `identity`.
pub(crate) const MAX_ELEMENTS: usize = 16;
/// SG-R-HDR-04: longest token.
pub(crate) const MAX_TOKEN_LENGTH: usize = 32;
/// The no-op coding.
pub(crate) const IDENTITY: &str = "identity";

/// A validated, lower-cased `Content-Encoding` token.
pub(crate) type Token = String;

/// SG-R-HDR-04 for an element: `[A-Za-z0-9][A-Za-z0-9._-]{0,31}`, ASCII only.
pub(crate) fn is_token(element: &[u8]) -> bool {
    match element.split_first() {
        Some((first, rest)) => {
            element.len() <= MAX_TOKEN_LENGTH
                && first.is_ascii_alphanumeric()
                && rest
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
        None => false,
    }
}

/// Steps 1 to 3 of the evaluation order: length, grammar, element count. Returns the non-empty
/// elements in the order listed, lower-cased (`identity` and `x-gzip` are still unresolved).
pub(crate) fn parse_content_encoding(values: &[&str]) -> Result<Vec<Token>, Error> {
    check_length(values)?;
    let elements = split(values)?;
    if elements.len() > MAX_ELEMENTS {
        return Err(Error::new(
            ErrorKind::LayerLimit,
            format!(
                "{} encodings listed, at most {MAX_ELEMENTS} are accepted",
                elements.len()
            ),
        )
        .with_limit(MAX_ELEMENTS as u64));
    }
    Ok(elements)
}

/// Steps 4 and 5: resolve the `x-gzip` alias, require support for every element, count the layers
/// against `max_layers`. Returns the layers in decoding order (layer 1 first, SG-R-HDR-12);
/// `identity` elements are dropped.
pub(crate) fn resolve_layers(
    elements: Vec<Token>,
    supported: impl Fn(&str) -> bool,
    max_layers: u32,
) -> Result<Vec<Token>, Error> {
    let mut layers = Vec::with_capacity(elements.len());
    for element in elements {
        let name = if element == "x-gzip" {
            "gzip".to_string()
        } else {
            element
        };
        if name == IDENTITY {
            continue;
        }
        if !supported(&name) {
            return Err(Error::new(
                ErrorKind::UnsupportedEncoding,
                format!("encoding {} is not supported", quote_untrusted(name.as_bytes())),
            ));
        }
        layers.push(name);
    }
    if layers.len() as u64 > u64::from(max_layers) {
        return Err(Error::new(
            ErrorKind::LayerLimit,
            format!("{} encoding layers, at most {max_layers} are accepted", layers.len()),
        )
        .with_limit(u64::from(max_layers)));
    }
    layers.reverse();
    Ok(layers)
}

/// SG-R-HDR-02: the joined list (values separated by one comma each) is at most 1024 bytes.
fn check_length(values: &[&str]) -> Result<(), Error> {
    let mut total = values.len().saturating_sub(1);
    for value in values {
        total = total.saturating_add(value.len());
    }
    if total > MAX_HEADER_LENGTH {
        return Err(Error::new(
            ErrorKind::MalformedEncoding,
            format!("Content-Encoding is {total} bytes long, at most {MAX_HEADER_LENGTH} are accepted"),
        )
        .with_limit(MAX_HEADER_LENGTH as u64));
    }
    Ok(())
}

/// SG-R-HDR-01, 03, 04, 05: join, split, trim, validate, lower-case. Joining with a comma and
/// splitting at commas is the same as splitting every value on its own.
fn split(values: &[&str]) -> Result<Vec<Token>, Error> {
    let mut elements = Vec::new();
    for value in values {
        for raw in value.as_bytes().split(|&b| b == b',') {
            let part = trim_space_and_tab(raw);
            if part.is_empty() {
                continue; // RFC 9110 section 5.6.1.2: empty list elements are ignored
            }
            if !is_token(part) {
                return Err(Error::new(
                    ErrorKind::MalformedEncoding,
                    format!("invalid encoding name {}", quote_untrusted(part)),
                ));
            }
            // Only ASCII passed the grammar, so the conversion cannot fail or fold anything.
            elements.push(String::from_utf8_lossy(part).to_ascii_lowercase());
        }
    }
    Ok(elements)
}

/// Only space and horizontal tab, never other whitespace.
fn trim_space_and_tab(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const ALL: [&str; 4] = ["gzip", "deflate", "br", "zstd"];

    fn full(values: &[&str], max_layers: u32) -> Result<Vec<Token>, Error> {
        resolve_layers(parse_content_encoding(values)?, |n| ALL.contains(&n), max_layers)
    }

    fn parse(values: &[&str]) -> Result<Vec<Token>, Error> {
        full(values, 5)
    }

    fn kind<T: std::fmt::Debug>(r: Result<T, Error>) -> ErrorKind {
        r.unwrap_err().kind()
    }

    fn names(values: &[&str]) -> Vec<String> {
        parse(values).unwrap()
    }

    // Covers: SG-R-HDR-12
    #[test]
    fn sg_r_hdr_12_decoding_order_is_the_reverse_of_the_list() {
        assert_eq!(names(&["gzip, deflate"]), ["deflate", "gzip"]);
        assert_eq!(names(&["gzip", "br"]), ["br", "gzip"]);
    }

    // Covers: SG-R-HDR-01 SG-R-HDR-03 SG-R-HDR-05 SG-R-HDR-14
    #[test]
    fn sg_r_hdr_14_equivalent_presentations_give_the_same_result() {
        let presentations: Vec<Vec<&str>> = vec![
            vec!["gzip,br"],
            vec!["GZIP, BR"],
            vec!["gzip", "br"],
            vec![" gzip ", "\tbr\t"],
            vec![",,gzip,,br,,"],
            vec!["", "gzip", " ", "br", ""],
            vec!["gzip,\t,br"],
            vec!["GzIp", "bR"],
        ];
        for p in presentations {
            assert_eq!(names(&p), ["br", "gzip"], "{p:?}");
        }
    }

    // Covers: SG-R-HDR-01 SG-R-HDR-03 SG-R-HDR-10
    #[test]
    fn sg_r_hdr_03_an_empty_header_is_the_empty_chain() {
        let empties: Vec<Vec<&str>> = vec![
            vec![""],
            vec![" "],
            vec![","],
            vec![", ,\t,"],
            vec![],
            vec!["", " "],
            vec!["identity, identity"],
        ];
        for e in empties {
            assert!(names(&e).is_empty(), "{e:?}");
        }
    }

    // Covers: SG-R-HDR-07
    #[test]
    fn sg_r_hdr_07_x_gzip_is_the_only_alias() {
        assert_eq!(names(&["x-gzip"]), ["gzip"]);
        assert_eq!(names(&["X-GZIP"]), ["gzip"]);
        for name in ["x-compress", "x-deflate", "x-br"] {
            assert_eq!(kind(parse(&[name])), ErrorKind::UnsupportedEncoding, "{name}");
        }
    }

    // Covers: SG-R-HDR-08 SG-R-HDR-09 SG-I-06
    #[test]
    fn sg_r_hdr_08_unknown_but_well_formed_tokens_are_unsupported() {
        for token in ["compress", "dcb", "dcz", "aes128gcm", "snappy", "deflate64", "bzip2"] {
            assert_eq!(
                kind(parse(&[&format!("gzip, {token}")])),
                ErrorKind::UnsupportedEncoding,
                "{token}"
            );
        }
    }

    // Covers: SG-R-HDR-04 SG-R-HDR-05
    #[test]
    fn sg_r_hdr_04_malformed_elements_are_refused() {
        let long = "g".repeat(33);
        let evil: Vec<&str> = vec![
            "gzip;q=1.0",
            "gzip;",
            "\"gzip\"",
            "gz ip",
            "gzip br",
            "gzip\n",
            "gzip\r\n",
            "\0gzip",
            "gzip\0",
            "g\u{e9}zip",
            "gzip\u{200b}",
            "-gzip",
            ".gzip",
            "_gzip",
            "gzip/br",
            "gzip:",
            &long,
            "gzip\u{b}",
            "gzip\u{c}",
            "gzip\u{85}",
            "gzip, br;x",
            "\u{fb01}",
            "\u{ff47}zip",
            "gzip\u{a0}",
            "\u{a0}gzip",
            "gzip\u{1b}[31m",
            "gzip\u{7f}",
        ];
        for token in evil {
            assert_eq!(kind(parse(&[token])), ErrorKind::MalformedEncoding, "{token:?}");
            assert_eq!(
                kind(parse(&["gzip", token])),
                ErrorKind::MalformedEncoding,
                "second value {token:?}"
            );
        }
    }

    // Covers: SG-R-HDR-04
    #[test]
    fn sg_r_hdr_04_token_length_and_alphabet_edges() {
        let any = |_: &str| true;
        let max = "a".repeat(32);
        assert_eq!(
            resolve_layers(parse_content_encoding(&[&max]).unwrap(), any, 5).unwrap(),
            [max]
        );
        assert_eq!(
            kind(parse_content_encoding(&[&"a".repeat(33)])),
            ErrorKind::MalformedEncoding
        );
        for token in ["a", "z", "A", "Z", "0", "9", "a.b_c-d", "9z", "A0._-"] {
            let got = resolve_layers(parse_content_encoding(&[token]).unwrap(), any, 5).unwrap();
            assert_eq!(got, [token.to_ascii_lowercase()]);
        }
        for first in "`{@[/:.-_ ".chars().filter(|c| *c != ' ') {
            assert_eq!(
                kind(parse_content_encoding(&[&format!("{first}x")])),
                ErrorKind::MalformedEncoding,
                "{first}"
            );
        }
        assert!(!is_token(b""));
    }

    // Covers: SG-R-HDR-03
    #[test]
    fn sg_r_hdr_03_only_space_and_tab_are_trimmed() {
        assert_eq!(names(&[" \t gzip \t "]), ["gzip"]);
        for ws in ["\r", "\n", "\u{b}", "\u{c}", "\u{a0}", "\u{2003}"] {
            assert_eq!(
                kind(parse(&[&format!("{ws}gzip")])),
                ErrorKind::MalformedEncoding,
                "{ws:?}"
            );
            assert_eq!(
                kind(parse(&[&format!("gzip{ws}")])),
                ErrorKind::MalformedEncoding,
                "{ws:?}"
            );
        }
    }

    // Covers: SG-R-HDR-02 SG-I-07
    #[test]
    fn sg_r_hdr_02_the_header_length_cap_counts_bytes() {
        let ok = format!("gzip{}", ",".repeat(1020));
        assert_eq!(ok.len(), 1024);
        assert_eq!(names(&[&ok]), ["gzip"]);
        assert_eq!(kind(parse(&[&format!("{ok},")])), ErrorKind::MalformedEncoding);
        // the joining commas count: 512 + 512 + 4 + 2 commas = 1030
        assert_eq!(
            kind(parse(&[&",".repeat(512), &",".repeat(512), "gzip"])),
            ErrorKind::MalformedEncoding
        );
        // exactly 1024 with two values: 1020 + 1 comma + ... = 1024
        let a = ",".repeat(1019);
        assert_eq!(names(&[&a, "gzip"]), ["gzip"]);
        assert_eq!(kind(parse(&[&a, "gzipp"])), ErrorKind::MalformedEncoding);
        // 600 two-byte characters are 1200 bytes
        assert_eq!(kind(parse(&[&"\u{e9}".repeat(600)])), ErrorKind::MalformedEncoding);
        let e = parse(&[&"x".repeat(1025)]).unwrap_err();
        assert_eq!(e.limit(), 1024);
        // many empty values: the separators count
        let empties = vec![""; 1026];
        assert_eq!(kind(parse(&empties)), ErrorKind::MalformedEncoding);
        let empties = vec![""; 1025];
        assert!(names(&empties).is_empty());
    }

    // Covers: SG-R-HDR-02 SG-R-HDR-04 SG-R-HDR-06 SG-R-HDR-08 SG-R-HDR-11
    #[test]
    fn evaluation_order_decides_the_outcome_class() {
        // length beats grammar
        let e = parse(&[&"x;".repeat(600)]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::MalformedEncoding);
        assert!(e.message().contains("long"), "{}", e.message());
        // grammar beats count
        let many = format!("{}, bad;", vec!["gzip"; 20].join(", "));
        assert_eq!(kind(parse(&[&many])), ErrorKind::MalformedEncoding);
        // grammar, left to right: first fault wins
        let e = parse(&["bad;one, bad;two"]).unwrap_err();
        assert!(e.message().contains("one"));
        // count beats support
        assert_eq!(kind(parse(&[&vec!["compress"; 17].join(", ")])), ErrorKind::LayerLimit);
        // support beats layers
        let mixed = format!("{}, compress", ["gzip"; 6].join(", "));
        assert_eq!(kind(parse(&[&mixed])), ErrorKind::UnsupportedEncoding);
        // grammar beats support
        assert_eq!(kind(parse(&["compress, bad;"])), ErrorKind::MalformedEncoding);
    }

    // Covers: SG-R-HDR-06 SG-R-HDR-10 SG-I-07
    #[test]
    fn sg_r_hdr_06_sixteen_elements_including_identity() {
        assert!(full(&[&vec!["identity"; 16].join(", ")], 1).unwrap().is_empty());
        assert_eq!(
            kind(full(&[&vec!["identity"; 17].join(", ")], 16)),
            ErrorKind::LayerLimit
        );
        let sixteen_gzip = vec!["gzip"; 16].join(", ");
        assert_eq!(full(&[&sixteen_gzip], 16).unwrap().len(), 16);
        assert_eq!(
            kind(full(&[&format!("{sixteen_gzip}, identity")], 16)),
            ErrorKind::LayerLimit
        );
        let e = full(&[&vec!["identity"; 17].join(", ")], 16).unwrap_err();
        assert_eq!(e.limit(), 16);
        // empty elements are not counted
        assert_eq!(
            parse_content_encoding(&[&format!(",{}", vec!["gzip"; 16].join(",,"))])
                .unwrap()
                .len(),
            16
        );
    }

    // Covers: SG-R-HDR-10 SG-R-HDR-11
    #[test]
    fn sg_r_hdr_11_the_layer_count_ignores_identity() {
        assert_eq!(full(&["identity, gzip, identity, gzip"], 2).unwrap(), ["gzip", "gzip"]);
        let e = full(&["gzip, gzip, gzip"], 2).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::LayerLimit);
        assert_eq!(e.limit(), 2);
        assert!(full(&["gzip, gzip"], 1).is_err());
        assert!(full(&["gzip"], 1).is_ok());
        assert!(full(&["identity"], 1).is_ok());
    }

    // Covers: SG-R-HDR-13
    #[test]
    fn sg_r_hdr_13_error_messages_quote_and_bound_attacker_data() {
        for evil in [
            "evil\nSEVERITY=ALERT;",
            &"x".repeat(900),
            "\u{1b}]0;title\u{7}",
            "a\r\nb\0\u{1b}[31m",
        ] {
            let e = parse(&[evil]).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::MalformedEncoding);
            let shown = e.to_string();
            assert!(!shown.chars().any(|c| c.is_control()), "{shown:?}");
            assert!(shown.matches('x').count() <= 32);
            assert!(shown.len() < 300);
        }
        // unsupported names are quoted too
        let e = parse(&["gzip, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnsupportedEncoding);
        assert!(e.message().contains('"'));
    }

    // Covers: SG-R-HDR-05
    #[test]
    fn sg_r_hdr_05_comparison_is_ascii_case_insensitive_without_folding() {
        assert_eq!(names(&["GZip, DEFLATE"]), ["deflate", "gzip"]);
        // the Kelvin sign and the long s are not ASCII and are malformed
        assert_eq!(kind(parse(&["\u{212a}"])), ErrorKind::MalformedEncoding);
        assert_eq!(kind(parse(&["\u{17f}"])), ErrorKind::MalformedEncoding);
    }
}
