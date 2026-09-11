//! Differential test: this port against the C library it was ported from.
//!
//! `libinjectionrs/src/tests/differential_tests.rs` runs only the Rust side,
//! as its own comments note, and asserts that the test count is above zero, so
//! it cannot fail. This one links the C library through the FFI harness and
//! compares verdicts and fingerprints over libinjection's own corpus, so a
//! behavioural regression fails `cargo test`.
//!
//! Known divergences are declared in `known_divergences.rs` at the repository
//! root, shared with the fuzz targets, as classes each naming the construct
//! that causes it and why. Anything outside those classes fails. That keeps the suite green
//! today while making a new divergence impossible to introduce quietly, and a
//! class that gets fixed has to be removed rather than left to excuse future
//! regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Known divergences live in one place, shared with the fuzz targets.
include!("../../known_divergences.rs");

fn c_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("libinjection-c")
}

/// The C library's own attack vectors and false-positive set, plus every
/// single-line test input. This is the strongest ground truth available.
fn corpus() -> Vec<String> {
    let root = c_root();
    if !root.join("src").join("libinjection_sqli.c").exists() {
        panic!("libinjection-c is missing. Run: git submodule update --init --recursive");
    }

    let mut lines: Vec<String> = Vec::new();

    for entry in read_txt(&root.join("data")) {
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        for line in text.lines() {
            if !line.is_empty() && !line.starts_with('#') {
                lines.push(line.to_string());
            }
        }
    }

    for entry in read_txt(&root.join("tests")) {
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        let all: Vec<&str> = text.split('\n').collect();
        for (i, line) in all.iter().enumerate() {
            if line.trim() != "--INPUT--" {
                continue;
            }
            let body: Vec<&str> = all[i + 1..]
                .iter()
                .take_while(|l| !l.starts_with("--"))
                .copied()
                .collect();
            if body.len() == 1 && !body[0].trim().is_empty() {
                lines.push(body[0].to_string());
            }
        }
    }

    let mut seen = BTreeSet::new();
    lines.retain(|l| !l.is_empty() && seen.insert(l.clone()));
    lines
}

fn read_txt(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "txt"))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Call the C library. The harness takes an explicit length, so the input may
/// contain NUL bytes.
fn c_sqli(input: &[u8]) -> (bool, String) {
    unsafe {
        let result = harness_detect_sqli(input.as_ptr() as *const c_char, input.len(), 0);
        let fp = result
            .fingerprint
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8 as char)
            .collect();
        (result.is_sqli != 0, fp)
    }
}

fn c_xss(input: &[u8]) -> bool {
    unsafe { harness_detect_xss(input.as_ptr() as *const c_char, input.len(), 0).is_xss != 0 }
}

/// The most SQLi fingerprint divergences from the C library the corpus is
/// allowed to produce. Lower it when a defect is fixed; never raise it.
///
/// 0 of 162,963 inputs: the Rust tokenizer produces the same fingerprint as the
/// C library for every input in the corpus. Word merging by table presence and
/// a case-insensitive `INTO` whitelist check closed the last of them.
const FINGERPRINT_DIVERGENCE_CEILING: usize = 0;

#[test]
fn sqli_verdicts_match_the_c_library_over_the_full_corpus() {
    let corpus = corpus();
    assert!(
        corpus.len() > 100_000,
        "corpus looks truncated: {} inputs",
        corpus.len()
    );

    let mut unexpected = Vec::new();
    let mut class_hits: BTreeSet<&str> = BTreeSet::new();
    let mut accepted = 0usize;

    for input in &corpus {
        let bytes = input.as_bytes();
        let rust = libinjectionrs::detect_sqli(bytes);
        let (c_is, c_fp) = c_sqli(bytes);

        if rust.is_injection() == c_is {
            continue;
        }
        if let Some(class) = known_class(input, KNOWN_SQLI_DIVERGENCES) {
            class_hits.insert(class.marker);
            accepted += 1;
            continue;
        }
        let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
        if unexpected.len() < 25 {
            unexpected.push(format!(
                "  {:?}\n    rust: injection={} fingerprint={:?}\n    c:    injection={} fingerprint={:?}",
                truncate(input),
                rust.is_injection(),
                rust_fp,
                c_is,
                c_fp
            ));
        }
    }

    println!("accepted divergences: {accepted} across {} known classes", class_hits.len());

    // A class that no longer diverges should be removed, not left to rot: a
    // stale entry silently excuses the next regression on the same construct.
    let stale: Vec<&str> = KNOWN_SQLI_DIVERGENCES
        .iter()
        .filter(|c| !class_hits.contains(c.marker))
        .map(|c| c.marker)
        .collect();

    assert!(
        unexpected.is_empty(),
        "{} SQLi inputs diverge from the C library outside the known classes:\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
    assert!(
        stale.is_empty(),
        "these classes no longer diverge; remove them from KNOWN_SQLI_DIVERGENCES: {stale:?}"
    );
}

/// Fingerprints are the tokenizer's output, so a divergence here is the
/// clearest signal that the two implementations parse differently even when
/// they happen to agree on the verdict. The corpus is now fully in agreement,
/// so the ceiling is zero.
#[test]
fn sqli_fingerprint_divergences_do_not_grow() {
    let corpus = corpus();
    let mut diverged = 0usize;
    let mut examples = Vec::new();

    for input in &corpus {
        let bytes = input.as_bytes();
        let rust = libinjectionrs::detect_sqli(bytes);
        let (_, c_fp) = c_sqli(bytes);
        let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
        if rust_fp != c_fp {
            diverged += 1;
            if examples.len() < 10 {
                examples.push(format!("  {:?}  rust={rust_fp:?} c={c_fp:?}", truncate(input)));
            }
        }
    }

    println!("fingerprint divergences: {diverged} of {} inputs", corpus.len());
    for e in &examples {
        println!("{e}");
    }
    // The `<=` form is deliberate: it stays correct if the ceiling ever has to
    // rise again. With the ceiling at 0 the comparison is `usize <= 0`, which
    // clippy flags as absurd, so it is allowed here rather than special-cased.
    #[allow(clippy::absurd_extreme_comparisons)]
    let within_ceiling = diverged <= FINGERPRINT_DIVERGENCE_CEILING;
    assert!(
        within_ceiling,
        "fingerprint divergences rose to {diverged}, above the {FINGERPRINT_DIVERGENCE_CEILING} \
         recorded when this test was written. Lower the ceiling when fixing, never raise it.\n{}",
        examples.join("\n")
    );
}

#[test]
fn xss_verdicts_match_the_c_library_over_the_full_corpus() {
    let corpus = corpus();
    let mut unexpected = Vec::new();
    let mut class_hits: BTreeSet<&str> = BTreeSet::new();
    let mut accepted = 0usize;

    for input in &corpus {
        let bytes = input.as_bytes();
        let rust = libinjectionrs::detect_xss(bytes).is_injection();
        let c = c_xss(bytes);
        if rust == c {
            continue;
        }
        if let Some(class) = known_class(input, KNOWN_XSS_DIVERGENCES) {
            class_hits.insert(class.marker);
            accepted += 1;
            continue;
        }
        if unexpected.len() < 25 {
            unexpected.push(format!("  {:?}  rust={rust} c={c}", truncate(input)));
        }
    }

    println!("accepted divergences: {accepted} across {} known classes", class_hits.len());

    let stale: Vec<&str> = KNOWN_XSS_DIVERGENCES
        .iter()
        .filter(|c| !class_hits.contains(c.marker))
        .map(|c| c.marker)
        .collect();

    assert!(
        unexpected.is_empty(),
        "{} XSS inputs diverge from the C library outside the known classes:\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
    assert!(
        stale.is_empty(),
        "these classes no longer diverge; remove them from KNOWN_XSS_DIVERGENCES: {stale:?}"
    );
}

/// Neither entry point may panic. A panic on attacker-controlled input is a
/// denial of service for anything using this as a WAF backend, and the crate
/// keeps direct slice indexing, so this is worth asserting rather than
/// assuming.
#[test]
fn neither_detector_panics_on_adversarial_input() {
    let mut rng: u64 = 0x243F6A8885A308D3;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let alphabet: Vec<u8> = b"\0\x01\x09\x0a\x0b\x0c\x0d '\"`\\/*-+=<>()[]{};:,.!?#%&|^~$@0123456789abcdefxXuU"
        .iter()
        .copied()
        .chain([0x7f, 0x80, 0xc0, 0xfe, 0xff])
        .collect();

    // Every one- and two-byte input, including NUL and invalid UTF-8.
    for a in 0u16..=255 {
        let _ = libinjectionrs::detect_sqli(&[a as u8]);
        let _ = libinjectionrs::detect_xss(&[a as u8]);
        for b in 0u16..=255 {
            let pair = [a as u8, b as u8];
            let _ = libinjectionrs::detect_sqli(&pair);
            let _ = libinjectionrs::detect_xss(&pair);
        }
    }

    for _ in 0..20_000 {
        let len = (next() % 64) as usize;
        let buf: Vec<u8> = (0..len)
            .map(|_| alphabet[(next() as usize) % alphabet.len()])
            .collect();
        let _ = libinjectionrs::detect_sqli(&buf);
        let _ = libinjectionrs::detect_xss(&buf);
    }

    // Pathological repetition, well past any internal buffer size.
    for pattern in [&b"'"[..], b"/*", b"--", b"0x", b"<", b"\0", b"("] {
        for reps in [500usize, 5_000, 50_000] {
            let buf: Vec<u8> = pattern.iter().cycle().take(reps).copied().collect();
            let _ = libinjectionrs::detect_sqli(&buf);
            let _ = libinjectionrs::detect_xss(&buf);
        }
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(120).collect()
}

/// Guards the NUL-in-`$`-token case, because the text corpus contains no NUL
/// bytes and only the fuzzer reaches it otherwise. C's `strlenspn` counts an
/// embedded NUL as a member of any accept set (its `strchr` finds the accept
/// string's terminator), so `'$\0T` scans `$\0` as a number; the port now does
/// the same.
#[test]
fn nul_in_dollar_token_matches_the_c_library() {
    for input in [&b"'$T"[..], b"'$\0T", b"T'$\0T#"] {
        let (c_is, c_fp) = c_sqli(input);
        let rust = libinjectionrs::detect_sqli(input);
        let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
        assert_eq!(
            (rust.is_injection(), rust_fp.as_str()),
            (c_is, c_fp.as_str()),
            "{input:?} diverges from the C library"
        );
    }
    // The specific behaviour: the NUL turns `$` into a number token.
    assert_eq!(c_sqli(b"'$\0T").1, "s1n");
    assert!(c_sqli(b"T'$\0T#").0, "C flags this injection, and so must the port");
}

/// Guards the `sp_password` force-true when the input is not valid UTF-8. C's
/// `my_memmem` searches the raw bytes, so it finds `sp_password` even amid high
/// bytes; the port searches bytes too rather than lossily decoding to a string.
/// The text corpus reaches this only in ASCII, so the fuzzer found this case.
#[test]
fn sp_password_in_non_utf8_input_matches_the_c_library() {
    // A comment-terminated fingerprint with `sp_password` embedded among high
    // bytes. C flags it via the raw-byte memmem; the port must agree.
    let input: &[u8] = &[
        0x2d, 0xfe, 0x23, 0x28, 0x41, 0x29, 0x2d, 0x28, 0x73, 0x70, 0x5f, 0x70, 0x61, 0x73,
        0x73, 0x77, 0x6f, 0x72, 0x64, 0x8a, 0x8a, 0x8a, 0x8a, 0x5b, 0x8a, 0x8a, 0x3d, 0x8a,
        0x8a, 0x8a, 0x8a, 0x8a, 0x8a, 0x2d, 0xff, 0xff, 0xff, 0x09, 0xff,
    ];
    let (c_is, c_fp) = c_sqli(input);
    let rust = libinjectionrs::detect_sqli(input);
    let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
    assert_eq!(
        (rust.is_injection(), rust_fp.as_str()),
        (c_is, c_fp.as_str()),
        "sp_password in non-UTF-8 input diverges from the C library"
    );
    assert!(c_is, "C flags this injection, and so must the port");
}

/// Guards the collate + bareword rule for a non-UTF-8 bareword. C's `strchr`
/// searches the raw token value for `_`, retyping the bareword as an SQL type;
/// the port searches the value bytes too rather than lossily decoding it. The
/// text corpus reaches this only in ASCII.
#[test]
fn collate_underscore_in_non_utf8_bareword_matches_the_c_library() {
    // `collate` then a bareword with `_` next to a high byte: C's strchr finds
    // the `_` and marks it TYPE_SQLTYPE (fingerprint `t`); the port must agree.
    let input: &[u8] = b"collate \xff_z";
    let (c_is, c_fp) = c_sqli(input);
    let rust = libinjectionrs::detect_sqli(input);
    let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
    assert_eq!(
        (rust.is_injection(), rust_fp.as_str()),
        (c_is, c_fp.as_str()),
        "collate + non-UTF-8 bareword diverges from the C library"
    );
    assert_eq!(c_fp, "At", "C types the bareword as an SQL type (fingerprint char `t`)");
}

/// Guards the number scans that use `strlenspn`: the `0x`/`0b` prefixes and the
/// `B'..'`/`X'..'` string forms. C's `strlenspn` counts an embedded NUL as a
/// digit, so a NUL inside the literal is consumed rather than ending it. The
/// text corpus has no NUL bytes, so only the fuzzer reaches this.
#[test]
fn nul_in_number_literal_matches_the_c_library() {
    let inputs: [&[u8]; 5] = [
        b"0x1\x002",
        b"0b1\x001",
        b"B'0\x001'",
        b"X'a\x00b'",
        b"1 union select 0x4\x005 from x",
    ];
    for input in inputs {
        let (c_is, c_fp) = c_sqli(input);
        let rust = libinjectionrs::detect_sqli(input);
        let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
        assert_eq!(
            (rust.is_injection(), rust_fp.as_str()),
            (c_is, c_fp.as_str()),
            "{input:?} diverges from the C library"
        );
    }
    // The NUL inside the hex literal is consumed, so this stays a UNION injection.
    assert!(c_sqli(b"1 union select 0x4\x005 from x").0, "C flags this injection, and so must the port");
}

/// Guards the HTML5 tokenizer's treatment of a NUL as whitespace. C's
/// `h5_is_white` is `strchr(" \t\n\v\f\r", ch)`, which matches the string's NUL
/// terminator, so a NUL ends an attribute name or unquoted value as whitespace
/// would. The text corpus has no NUL bytes, so only the fuzzer reaches this.
#[test]
fn nul_as_whitespace_in_html5_matches_the_c_library() {
    // A NUL inside an attribute name: C ends the name there, so the trailing
    // `</`+backtick never becomes a comment. The port must not flag it either.
    let input: &[u8] = &[60, 0, 47, 50, 0, 255, 62, 60, 47, 96];
    assert_eq!(
        libinjectionrs::detect_xss(input).is_injection(),
        c_xss(input),
        "NUL-as-whitespace in HTML5 diverges from the C library"
    );
    assert!(!c_xss(input), "C treats this as safe, and so must the port");
}

/// Guards the variable token value: C stores the name without the leading `@`
/// (the `@` count lives in a separate field), so the function fold that matches
/// a name like `PASSWORD` sees `pasSword`, not `@pasSword`. The corpus has no
/// `@`-variable named like a function followed by `(`, so the fuzzer found it.
#[test]
fn at_variable_named_like_a_function_matches_the_c_library() {
    // `@pasSword(` : C types the variable as a function (fingerprint `f`), so
    // this folds to `f(f(1`, a blacklisted pattern. The port must agree.
    let input: &[u8] = b"@pasSword(pasSword(2";
    let (c_is, c_fp) = c_sqli(input);
    let rust = libinjectionrs::detect_sqli(input);
    let rust_fp = rust.fingerprint.as_ref().map(|f| f.to_string()).unwrap_or_default();
    assert_eq!(
        (rust.is_injection(), rust_fp.as_str()),
        (c_is, c_fp.as_str()),
        "@-variable named like a function diverges from the C library"
    );
    assert_eq!(c_fp, "f(f(1", "C folds the variable to a function");
    assert!(c_is, "C flags this injection, and so must the port");
}
