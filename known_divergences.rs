// Divergences from the C library that are known and understood.
//
// Included by both `comparison-bin/tests/differential.rs` and the fuzz
// targets, so there is one source of truth. Each class names the construct
// that causes it, not individual inputs: fixing the defect retires the whole
// entry, and a fuzzer generating a fresh instance of a known class does not
// fail the build while a genuinely new divergence still does.
//
// Every class below is a false negative, so each is a missed detection.
// Remove a class when it is fixed; the differential test fails if a listed
// class stops diverging, so a stale entry cannot linger and excuse a future
// regression.

/// A class of input known to diverge, and why.
pub struct KnownDivergence {
    /// Substring, matched case-insensitively, that identifies the class.
    pub marker: &'static str,
    /// Why these diverge.
    pub reason: &'static str,
}

/// SQL keywords of three or more words are not folded into a single keyword
/// token.
///
/// Two-word keywords fold correctly on their own (`into outfile` fingerprints
/// `k` in both), and every intermediate prefix is present in both keyword
/// tables (`LOCK IN`, `LOCK IN SHARE`, `LOCK IN SHARE MODE`), so the defect is
/// in chaining the merge rather than in the data.
///
/// | input | C | Rust |
/// |---|---|---|
/// | `LOCK IN SHARE MODE` | `k` | `nnnn` |
/// | `x IN BOOLEAN MODE` | `nk` | `nnn` |
/// | `1 into outfile 'asd'` | `1ks` | `sns` |
pub const KNOWN_SQLI_DIVERGENCES: &[KnownDivergence] = &[
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

/// Whitespace or a control byte between an attribute name and its `=`, as in
/// `<img src=x onerror%09="alert(1)">`. The C library treats the separator as
/// part of the attribute and flags the input; this port does not. A standard
/// attribute-separator evasion.
pub const KNOWN_XSS_DIVERGENCES: &[KnownDivergence] = &[KnownDivergence {
    marker: "onerror%",
    reason: "a separator between attribute name and '=' is not recognised",
}];

/// Which known class a text input belongs to, if any.
pub fn known_class<'a>(
    input: &str,
    classes: &'a [KnownDivergence],
) -> Option<&'a KnownDivergence> {
    let lower = input.to_ascii_lowercase();
    classes.iter().find(|c| lower.contains(c.marker))
}

/// A NUL byte inside a `$`-prefixed token changes tokenization in the C
/// library but not here: `'$\0T` fingerprints `s1n` in C and `snn` here, so
/// `T'$\0T#` is an injection to C and clean to this port. Without the NUL the
/// two agree (`'$T` gives `snn` both sides).
///
/// Kept deliberately narrow. Excusing every NUL-containing input would
/// recreate the blind spot that hid this class in the first place: the fuzz
/// targets used to skip anything with a NUL because they converted through
/// `CString`, and the C harness takes an explicit length, so they never
/// needed to.
pub fn is_known_nul_divergence(input: &[u8]) -> bool {
    input.contains(&0) && input.contains(&b'$')
}

/// Whether a raw byte input falls in any known class. Used by the fuzz
/// targets, which generate bytes rather than text.
pub fn is_known_divergence(input: &[u8], classes: &[KnownDivergence]) -> bool {
    if is_known_nul_divergence(input) {
        return true;
    }
    match std::str::from_utf8(input) {
        Ok(text) => known_class(text, classes).is_some(),
        // A non-UTF-8 input cannot match a textual marker, but the NUL class
        // above already covers the byte-level case.
        Err(_) => {
            let lower: Vec<u8> = input.to_ascii_lowercase();
            classes.iter().any(|c| {
                lower
                    .windows(c.marker.len().max(1))
                    .any(|w| w == c.marker.as_bytes())
            })
        }
    }
}
