# Changelog

All notable changes to this fork are recorded here. It adds differential
verification against the C library `libinjectionrs` was ported from, and closes
the divergences that testing surfaces.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.3] - 2026-11-04

### Fixed
- The crate builds without the `std` feature. The SQLi tokenizer called
  `std::str::from_utf8`, and `Vec`, `String` and `format!` were used without
  importing them from `alloc`, so a `no_std` build failed
  ([saarw/libinjectionrs#2](https://github.com/saarw/libinjectionrs/issues/2)).
  Detection is unchanged.

### Added
- A CI job builds the crate for a bare-metal target (`thumbv7em-none-eabihf`)
  without `std`, with and without `smallvec`.

## [0.1.2] - 2026-11-03

### Fixed
- `htmlencode_startswith` compares each pattern byte against the low byte of
  the decoded entity, as C's `*a != (char)cb` does, so `d&#833ta:` (0x341, low
  byte `A`) starts with `DATA`. A URL attribute value spelling a blacklisted
  scheme with out-of-range numeric entities is flagged, as in C.

### Changed
- The C reference is libinjection 4.0.1. The `libinjection-c` submodule had
  been pinned at 85e252a (February 2025) since the port began. The port follows
  the detection changes since then:
  - A number like `1.e` or `10.E` with no exponent digits produces no token,
    as MySQL ignores it, so `1' or 1.e(1)` folds and is flagged as in C.
  - `LIKE (` is read as a function only when it does not follow an operand
    (number, string, bareword, variable or `)`).
  - The HTML5 tokenizer reads bytes unsigned when skipping whitespace, so a
    0xFF byte is no longer taken as end of input and attributes after it are
    checked.
  - The XSS event-handler list follows upstream's 432 entries (145 added, 11
    removed).
  - `html_decode_char_at` and the event-handler comparison mirror 4.0.1's
    length guards. Verdicts are unchanged.

  4.0.0 fixed the `htmlencode_startswith` over-read noted under 0.1.1; the
  harness keeps the zero padding. Over the corpus, now 163,275 inputs, SQLi and
  XSS divergences from the C library remain at 0.

### Added
- Dependabot watches the `libinjection-c` submodule, so upstream changes open
  a pull request that the differential job runs against.

## [0.1.1] - 2026-09-12

### Fixed
- Word merging now folds multi-word keywords by table presence, matching the C
  library's `ch != CHAR_NULL` check, so `LOCK IN SHARE MODE` and `IN BOOLEAN
  MODE` fold as they do in C.
- The three-token whitelist compares `INTO` case-insensitively, matching C's
  `cstrcasecmp`. It had used a case-sensitive `starts_with(b"INTO")`, so a
  lowercase `1 into outfile 'asd'` was wrongly whitelisted as safe while C
  flags it.
- Together these bring **SQLi fingerprint divergences from the C library to 0**
  over the 162,963-input corpus (from 1,631, about 1%), retiring every known
  SQLi divergence class with no new divergence.
- The XSS event-handler check compares only the blacklisted event name's
  length, as C's `cstrcasecmp_with_null(black->name, s_without_on,
  strlen(black->name))` does, so an attribute-separator evasion like
  `onerror%09=` matches on the `error` prefix. This brings **XSS verdict
  divergences to 0** over the corpus.
- `$`-token scanning now counts an embedded NUL as a member of any accept set,
  as C's `strlenspn` does (its `strchr(accept, '\0')` finds the accept string's
  terminator), so `'$\0T` scans `$\0` as a number and `T'$\0T#` is flagged.
  This retires the last known divergence class: **no known divergence from the
  C library remains** on SQLi or XSS.
- Further char-semantics classes the differential fuzzer surfaced, each fixed
  following C: a variable name and the binary/hex/decimal number scans stop at
  or consume a NUL as C's `strchr`-based helpers do; `sp_password` and the
  collate `_` check search the raw token bytes rather than a lossily decoded
  string; NUL counts as whitespace in the HTML5 tokenizer (`h5_is_white`), as
  it does in C's `strchr(" \t\n\v\f\r", ch)`; and a variable token stores its
  name without the leading `@`, so the function fold matches a name like
  `@pasSword`. The SQLi detector then found no divergence over a two-hour
  differential-fuzzing campaign.

### Added
- `lookup_word_type`, a presence-aware keyword lookup returning `None` only
  when a word is absent, alongside the generator in `build.rs` so a regenerated
  table keeps the behaviour.
- A line-coverage gate in CI (`cargo-llvm-cov`), enforcing a floor on the
  library.

### Changed
- The differential fingerprint ceiling is lowered from 1,631 to 0: SQLi
  fingerprints now match the C library exactly across the corpus.
- The FFI harness zero-pads the C input. libinjection reads a few bytes past
  the end of the buffer on some adversarial inputs (an ASan-confirmed
  out-of-bounds read in `htmlencode_startswith`, reached from
  `libinjection_is_xss`), which makes its verdict depend on whatever sits past
  the input. Padding makes those reads land on defined zero bytes, so the
  differential compares against a deterministic C answer; the memory-safe port
  never reads past the input.

## Baseline

The starting point of this fork: a working AI port whose verdicts already match
the C library across the corpus, with a differential test, CI, and a
known-divergence list added when that harness was contributed upstream
([saarw/libinjectionrs#1](https://github.com/saarw/libinjectionrs/pull/1)).
