# Changelog

All notable changes to this project will be documented in this file.

## v0.10.0-beta.2 - 2024-01-29

### Highlights

- switch to `rustls` as default TLS backend and remove unnecessary build dependencies and feature flags
  - updated `oneio` to v0.16.0
  - remove `openssl` and `vendored-openssl` dependency and feature flag for building CLI binary
  - remove `ureq` dev-dependency

### Release process changes

- added `cargo binstall` support
- added SHA256 checksum to corresponding release binary files

## v0.10.0-beta.1 - 2024-01-03

* add TableDumpV2 support: https://github.com/bgpkit/bgpkit-parser/pull/146
* increase code test coverage to 92%: https://github.com/bgpkit/bgpkit-parser/pull/147
