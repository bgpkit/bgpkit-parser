# Fuzz Testing

Fuzz testing targets for the BGPKIT Parser using `cargo-fuzz`.

## Setup

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

## Run Fuzzers

```bash
# Basic MRT record fuzzing (60s)
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_mrt_record -- -max_total_time=60

# BGP message fuzzing (60s)
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_bgp_message -- -max_total_time=60

# Full parser fuzzing (60s)
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_parser -- -max_total_time=60

# Run all fuzzers (5 minutes each)
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_mrt_record -- -max_total_time=300
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_bgp_message -- -max_total_time=300
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_parser -- -max_total_time=300
```

## Analyze Crashes

Crashes are saved in `tests/fuzz/artifacts/<target>/`.

```bash
# Reproduce a crash
cargo +nightly fuzz run --fuzz-dir tests/fuzz fuzz_mrt_record artifacts/fuzz_mrt_record/crash-<hash>
```

## Expected Behavior

The parser should **never panic**. All invalid inputs must return `Result::Err`.
