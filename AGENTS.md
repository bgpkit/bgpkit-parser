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

### Formatting
`cargo fmt` does not accept `--all-features` (formatting is feature-independent):
```
cargo fmt
```
To check formatting without modifying files:
```
cargo fmt -- --check
```

## Notes

- The `bgpkit-parser` binary requires the `cli` feature (`required-features = ["cli"]`).
- Examples under `examples/` may require specific features (see `[[example]]` entries in `Cargo.toml`).
- Benchmarks use Criterion (`[[bench]]` entries).

## Finding Missing Implementations

When looking for incomplete or missing BGP attribute implementations, check `src/parser/bgp/attributes/README.md`. This file contains:

1. **Unit Test Coverage** table — lists fully implemented attributes with RFC references
2. **Known Limitations** table — lists attributes that are:
   - Type defined in `AttrType` enum but have no parser (e.g., PMSI_TUNNEL, BGPSEC_PATH)
   - Model structs exist but parser/encoder not yet implemented (e.g., AIGP, ATTR_SET)

Use this file to identify which attributes need implementation work and their corresponding RFCs.
