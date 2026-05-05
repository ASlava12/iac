# cargo-fuzz harness

Coverage-guided fuzzing for the parts of the codebase that touch
attacker-influenced input: provider spec parsers and the manifest
document loader.

This directory is **not** part of the workspace — running
`cargo build --workspace` doesn't pull in `libfuzzer-sys` (which
needs nightly + nasm). For day-to-day regression coverage of the
same parsers, see [`crates/iac-providers/tests/fuzz_parsers.rs`](../crates/iac-providers/tests/fuzz_parsers.rs)
which uses `proptest` and runs under stable `cargo test`.

## Setup

```sh
rustup install nightly
cargo install cargo-fuzz
```

## Run a target

```sh
cd fuzz
cargo +nightly fuzz run fuzz_provider_specs
cargo +nightly fuzz run fuzz_manifest_documents
```

Targets run until Ctrl-C. Crashes land under `fuzz/artifacts/` as
small reproducers — paste the first ~256 bytes into a normal test
case so future regressions get caught at `cargo test` time too.

## Triage

A crash here is a **sev-2 bug** for the manifest loader (operator-
controlled input from git) and a **sev-3 bug** for individual
provider specs (one bad manifest fails one resource, not the
whole control plane). File a ticket with:

* The crashing input (`fuzz/artifacts/<target>/crash-*`).
* The shrunk repro from `cargo +nightly fuzz tmin <target>`.
* A fix that makes the parser return `Result::Err(String)` rather
  than panicking.
