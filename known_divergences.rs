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

/// No SQLi divergences from the C library remain over the corpus: word merging
/// folds multi-word keywords by table presence, and the three-token whitelist
/// compares `INTO` case-insensitively as C does. New classes the fuzzer finds
/// are added here.
pub const KNOWN_SQLI_DIVERGENCES: &[KnownDivergence] = &[];

/// No XSS divergences from the C library remain over the corpus: the event
/// handler check compares only the blacklisted event name's length, as C does,
/// so `onerror%09` matches on `error`. New classes the fuzzer finds are added
/// here.
pub const KNOWN_XSS_DIVERGENCES: &[KnownDivergence] = &[];

/// Which known class a text input belongs to, if any.
pub fn known_class<'a>(
    input: &str,
    classes: &'a [KnownDivergence],
) -> Option<&'a KnownDivergence> {
    let lower = input.to_ascii_lowercase();
    classes.iter().find(|c| lower.contains(c.marker))
}

/// Whether a raw byte input falls in any known class. Used by the fuzz
/// targets, which generate bytes rather than text.
pub fn is_known_divergence(input: &[u8], classes: &[KnownDivergence]) -> bool {
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
