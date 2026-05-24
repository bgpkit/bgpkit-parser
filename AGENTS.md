# bgpkit-parser — Agent Instructions

## Project Overview

`bgpkit-parser` is a Rust library for parsing MRT/BGP/BMP data. It provides both a library API and a CLI (`bgpkit-parser` binary).

Key features defined in `Cargo.toml`:
- `default` — `parser` + `rustls`
- `parser` — core parsing (bytes, chrono, regex, zerocopy)
- `cli` — command-line interface (clap, env_logger, serde, serde_json)
- `rislive` — RIS Live WebSocket support (serde, serde_json, hex)
- `serde` — serialization support
- `native-tls` / `rustls` — TLS backend selection
- `xz` / `lz` — optional compression algorithms

## Build & Test Commands

### Building
Always build with `--all-features` and include examples:
```
cargo build --all-features --examples
```

### Testing
Always run tests with `--all-features`:
```
cargo test --all-features
```

### Linting
Always run clippy with `--all-features`:
```
cargo clippy --all-features
```

The pre-push hook uses the stricter form below; run it before pushing if you want to match the exact CI check:
```
cargo clippy --all-targets --all-features -- -D warnings
```

### Formatting
`cargo fmt` does not accept `--all-features` (formatting is feature-independent):
```
cargo fmt
```
To check formatting without modifying files:
```
cargo fmt -- --check
```

### Documentation
`README.md` is **auto-generated** from `src/lib.rs` doc comments via [`cargo-readme`](https://github.com/livioribeiro/cargo-readme).

- Edit documentation in **`src/lib.rs`** (inside the top-level `//!` doc comment block), not in `README.md` directly.
- After editing `src/lib.rs`, regenerate `README.md`:
  ```
  cargo readme > README.md
  ```
- The pre-push hook runs a `cargo readme` diff check; if `README.md` is out of sync with `src/lib.rs`, the push will be rejected.
- If you do not have `cargo-readme` installed:
  ```
  cargo install cargo-readme
  ```

## Pre-push Checks

The repository has a `.git/hooks/pre-push` script that runs automatically on every push. It performs three checks in order:

1. **Formatting**: `cargo fmt --check`
2. **README sync**: `cargo readme > TMP_README.md && diff -b TMP_README.md README.md`
3. **Clippy**: `cargo clippy --all-targets --all-features -- -D warnings`

If any check fails, the push is aborted. Fix the issue, commit, and push again.

## Notes

- The `bgpkit-parser` binary requires the `cli` feature (`required-features = ["cli"]`).
- Examples under `examples/` may require specific features (see `[[example]]` entries in `Cargo.toml`).
- Benchmarks use Criterion (`[[bench]]` entries).

## Changelog Conventions

When documenting changes in `CHANGELOG.md`:

- **Contributor attribution**: For features or significant fixes contributed by external contributors, append `(thanks @<github-handle> for the contribution)` in plain text at the end of the bullet point. This ensures the attribution flows into the automated GitHub release notes.
  - Example: `* **Route-level parser**: Added ... (thanks @ties for the contribution)`
  - Do not use markdown links like `[@ties](https://github.com/ties)` — the automated release tool copies CHANGELOG verbatim, and plain text is preferred for consistency.

## Finding Missing Implementations

When looking for incomplete or missing BGP attribute implementations, check `src/parser/bgp/attributes/README.md`. This file contains:

1. **Unit Test Coverage** table — lists fully implemented attributes with RFC references
2. **Known Limitations** table — lists attributes that are:
   - Type defined in `AttrType` enum but have no parser (e.g., PMSI_TUNNEL, BGPSEC_PATH)
   - Model structs exist but parser/encoder not yet implemented (e.g., AIGP, ATTR_SET)

Use this file to identify which attributes need implementation work and their corresponding RFCs.
