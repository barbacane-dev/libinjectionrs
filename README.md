# libinjectionrs

A memory-safe Rust port of [libinjection](https://github.com/libinjection/libinjection), the SQL injection and XSS detection library. The original translation from C was AI-generated (a "vibe port": an AI plan from GPT-5, executed with Claude Code, with little of the code manually reviewed line by line). This fork exists to make that port trustworthy by measurement rather than by reading: it is differential-tested against the C library it was ported from, and this README describes what that testing currently shows.

It backs the `@detectSQLi` and `@detectXSS` operators in [parapet](https://github.com/barbacane-dev/parapet).

## Features

- SQL injection detection with fingerprinting
- XSS detection with context awareness
- No `unsafe`, and lints that deny the common panic sources (see [Linting](#linting))
- Minimal heap allocations using `SmallVec`

## Agreement with the C library

Correctness here means one thing: the same answer as the C library. That is measured, not asserted, by `comparison-bin/tests/differential.rs`, which links the C sources through the FFI harness and compares this port against them over libinjection's own corpus of ~163,000 inputs, on both verdicts and fingerprints.

**No known divergence from the C library remains.** SQLi fingerprints and XSS verdicts match exactly across the whole corpus (0 of 162,963 each), and the NUL-in-`$`-token edge, which the text corpus cannot reach, is matched too and held by a dedicated test. Any divergence outside this state fails the build.

The fixes that got here, each following the C control flow rather than a particular input:

- multi-word keyword folding by table presence (`LOCK IN SHARE MODE`)
- a case-insensitive `INTO` check in the three-token whitelist (`into outfile`)
- a length-limited XSS event-handler check (`onerror%09=`)
- a `strlenspn` that counts an embedded NUL as a set member, as C's `strchr` does

This is not the same as "provably identical". Beyond the corpus and these characterised edges, [differential fuzzing](#fuzzing) still finds new divergences, including false positives, within seconds. Treat this port as a close match with a measured gap of zero on the corpus, not as a drop-in replacement whose every answer is guaranteed.

## Testing and CI

CI runs on every push and pull request:

- **Lints and unit tests** across the workspace.
- **Library coverage** (`cargo-llvm-cov`) with an enforced floor.
- **Differential against the C library** — the job that matters, described above. A divergence fails it.
- **Differential fuzzing** (two minutes per detector). It **reports rather than gates**: it still surfaces new divergence classes faster than they are fixed, so gating on it would mean either a red build forever or an exception list that excuses everything. The corpus differential is the gate; this job keeps new classes visible.

A separate test asserts that neither detector panics on adversarial input: every one- and two-byte value including NUL, random metacharacter strings, and 50,000-byte pathological repeats.

## Usage

```rust
use libinjectionrs::{detect_sqli, detect_xss};

let input = b"1' OR '1'='1";
if detect_sqli(input).is_injection() {
    // handle SQL injection
}

if detect_xss(b"<script>alert('xss')</script>").is_injection() {
    // handle XSS
}
```

## Development

Fetch the C library submodule first; the differential test and the FFI harness need it:

```bash
git submodule update --init --recursive
cargo test                                                   # unit tests
cargo test -p libinjection-comparison --test differential    # against the C library
```

`comparison-bin` and `libinjection-debug` compare and trace this port against C; reach for them before writing new probes.

### Linting

Third-party warnings are allowed, but the workspace denies `unsafe`, `unwrap`, `expect`, `panic`, `unreachable`, `todo`, and `unimplemented` in the library:

```bash
cargo clippy --workspace --all-targets -- -A warnings
```

## Fuzzing

The fuzz targets under `fuzz/` compare each detector against C on generated input. `scripts/seed_fuzz_corpus.sh` seeds their corpora from libinjection's own `test-sqli-*.txt` and `test-html5-*.txt` cases, de-duplicated by hash:

```bash
./scripts/seed_fuzz_corpus.sh sqli   # SQLi corpus
./scripts/seed_fuzz_corpus.sh xss    # XSS corpus
./scripts/seed_fuzz_corpus.sh all    # both
```

## Project structure

```text
libinjectionrs/       Main Rust library source
comparison-bin/       Differential test and CLI comparison against C
libinjection-debug/   Token-level tracing tools for comparing implementations
ffi-harness/          C FFI harness the differential test links against
fuzz/                 Differential fuzz targets and corpora
benches/              Benchmarks
libinjection-c/       Git submodule: the original C library
docs/                 Architecture and porting notes
scripts/              Corpus generation
```

## License

Licensed under the BSD 3-Clause License ([LICENSE](LICENSE) or <https://opensource.org/licenses/BSD-3-Clause>). This is a Rust port of [libinjection](https://github.com/libinjection/libinjection), also BSD 3-Clause.
