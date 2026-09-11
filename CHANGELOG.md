# Changelog

All notable changes to this fork are recorded here. The fork exists to make
`libinjectionrs` a differential-verified backend for `@detectSQLi` /
`@detectXSS` in [parapet](https://github.com/barbacane-dev/parapet); see the
audit in that repository for the acceptance bar.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Word merging now folds multi-word keywords by table presence, matching the C
  library's `ch != CHAR_NULL` check, so `LOCK IN SHARE MODE` and `IN BOOLEAN
  MODE` fold as they do in C. Over the 162,963-input corpus this dropped
  fingerprint divergences from 1,631 (~1%) to 3, and retired two known
  divergence classes with no new divergence.

### Added
- `lookup_word_type`, a presence-aware keyword lookup returning `None` only
  when a word is absent, alongside the generator in `build.rs` so a regenerated
  table keeps the behaviour.
- A line-coverage gate in CI (`cargo-llvm-cov`), enforcing a floor on the
  library.

### Changed
- The differential fingerprint ceiling is lowered from 1,631 to 3, holding the
  gain against regression.

## Baseline

The starting point of this fork: a working AI port whose verdicts already match
the C library across the corpus, with a differential test, CI, and a
known-divergence list added during the parapet audit
([saarw/libinjectionrs#1](https://github.com/saarw/libinjectionrs/pull/1)).
