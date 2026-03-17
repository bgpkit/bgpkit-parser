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
