# Local-files-only example

This standalone project parses an MRT file from the local filesystem without
including remote HTTP/TLS support.

Its `Cargo.toml` uses:

```toml
bgpkit-parser = { path = "../..", default-features = false, features = ["local"] }
```

The `local` feature enables the parser and local compressed-file I/O. Replace
`path` with a published crate version when copying this configuration into
another project.

## Run

Place an MRT file named `updates.bz2` in this directory, then run:

```bash
cd examples/local_only
cargo run --release
```

Or pass a local filename explicitly:

```bash
cargo run --release -- path/to/updates.mrt.gz
```
