# Changelog

All notable changes to this project will be documented in this file.

## v0.10.0-beta.3 - 2024-02-08

### Highlights

`Bytes::split_to` will panic if not enough bytes available. 
We added multiple safety checks to make sure enough bytes are available before calling `.split_to()` function.
If not enough bytes available, it will send out a `TruncatedMsg` error.
The current iterator will catch the error and skip the remainder of the message.

### Breaking changes

- remove `IoNotEnoughBytes`, and use `TruncatedMsg` when not enough bytes available to read

### Other changes

- bump `bytes` crate version to `1.5.0`

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
