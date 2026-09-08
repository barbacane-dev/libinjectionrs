//! Differential test: this port against the C library it was ported from.
//!
//! `libinjectionrs/src/tests/differential_tests.rs` runs only the Rust side,
//! as its own comments note, and asserts that the test count is above zero, so
//! it cannot fail. This one links the C library through the FFI harness and
//! compares verdicts and fingerprints over libinjection's own corpus, so a
//! behavioural regression fails `cargo test`.
//!
//! Known divergences are declared in [`KNOWN_SQLI_DIVERGENCES`] and
//! [`KNOWN_XSS_DIVERGENCES`] as classes, each naming the construct that causes
//! it and why. Anything outside those classes fails. That keeps the suite green
//! today while making a new divergence impossible to introduce quietly, and a
//! class that gets fixed has to be removed rather than left to excuse future
//! regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// A class of input that is known to diverge, and why.
///
/// Keyed by the construct that causes it rather than by individual inputs. A
/// list of literal strings would need every long payload transcribed exactly,
/// and it would not say what the defect is. Naming the class means fixing the
/// defect retires the whole entry at once.
struct KnownDivergence {
    /// Substring, matched case-insensitively, that identifies the class.
    marker: &'static str,
    /// Why these diverge.
    reason: &'static str,
}

/// SQLi divergences: SQL keywords of three or more words are not folded into a
/// single keyword token.
///
/// Two-word keywords fold correctly on their own (`into outfile` fingerprints
/// `k` in both implementations), and every intermediate prefix is present in
/// both keyword tables (`LOCK IN`, `LOCK IN SHARE`, `LOCK IN SHARE MODE`), so
/// the defect is in chaining the merge rather than in the data. Fingerprints
/// show it directly:
///
/// | input | C | Rust |
/// |---|---|---|
/// | `LOCK IN SHARE MODE` | `k` | `nnnn` |
/// | `x IN BOOLEAN MODE` | `nk` | `nnn` |
/// | `1 into outfile 'asd'` | `1ks` | `sns` |
///
/// Every verdict divergence in this class is a false negative, so each is a
/// missed detection. `INTO OUTFILE` is a file-write primitive.
const KNOWN_SQLI_DIVERGENCES: &[KnownDivergence] = &[
    KnownDivergence {
        marker: "into outfile",
        reason: "multi-word keyword INTO OUTFILE is not folded when followed by a string",
    },
    KnownDivergence {
        marker: "lock in share mode",
        reason: "four-word keyword LOCK IN SHARE MODE is not folded",
    },
    KnownDivergence {
        marker: "in boolean mode",
        reason: "three-word keyword IN BOOLEAN MODE is not folded",
    },
];

/// XSS divergences: whitespace or a control byte between an attribute name and
/// its `=`, as in `<img src=x onerror%09="alert(1)">`.
///
/// The C library treats the separator as part of the attribute and flags the
/// input; this port does not. Every one is a false negative, and this is a
/// standard attribute-separator evasion.
const KNOWN_XSS_DIVERGENCES: &[KnownDivergence] = &[KnownDivergence {
    marker: "onerror%",
    reason: "a separator between attribute name and '=' is not recognised",
}];

/// Which known class an input belongs to, if any.
fn known_class<'a>(input: &str, classes: &'a [KnownDivergence]) -> Option<&'a KnownDivergence> {
    let lower = input.to_ascii_lowercase();
    classes.iter().find(|c| lower.contains(c.marker))
}

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

/// Fingerprint divergences known today. Every one traces to the same
/// multi-word keyword folding defect described on [`KNOWN_SQLI_DIVERGENCES`],
/// and most do not change the verdict, so they are tracked as a ceiling rather
/// than enumerated. Lower it when the defect is fixed; never raise it.
///
/// 1,631 of 162,963 inputs, about 1%. That the verdict survives most of them
/// is luck rather than correctness, so this number is the better measure of
/// how far the two implementations have drifted.
const FINGERPRINT_DIVERGENCE_CEILING: usize = 1631;

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
/// they happen to agree on the verdict. Tracked as a ceiling because the count
/// is large and has one known cause.
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
    assert!(
        diverged <= FINGERPRINT_DIVERGENCE_CEILING,
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
