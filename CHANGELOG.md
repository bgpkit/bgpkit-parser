# Changelog

All notable changes to this project will be documented in this file.

## v0.10.7 - 2024-03-30

### Highlights

* improve end-of-RIB marker detection ([#161](https://github.com/bgpkit/bgpkit-parser/pull/161))

## v0.10.6 - 2024-03-30

### Bug fix

* fixed an code panic issue where malformed RIB dump entry with non-existing peer ID causes a panic
    * also removed a number of unwraps in the code to handle errors more gracefully
    * see issue [#157](https://github.com/bgpkit/bgpkit-parser/issues/158) for details

## v0.10.5 - 2024-03-26

### Highlights

* by default handles only `gzip` and `bzip2` files
    * to support `xz` and `lz` files, use the optional feature `xz` and `lz`

## v0.10.4 - 2024-03-20

### Hot fix

* update `oneio` to `v0.16.4`
    * add `http2` and `charset` feature flag to `reqwest`

## v0.10.3 - 2024-03-20

### Highlights

* fixed an panic issue when sometimes merging AS path segments of 4-byte ASN path and 2-byte ASN path
    * see issue [#156](https://github.com/bgpkit/bgpkit-parser/issues/156) for details
* update `oneio` to `v0.16.3`
    * gzip decompression depends on `flate2`'s `rust-backend` feature instead of `zlib-ng` which requires `cmake` to
      build

## v0.10.2 - 2024-03-06

### Highlights

* added new `ip_version` filter type with values of `ipv4` or `ipv6`
    * library users can use this filter to filter BGP messages by IP version
    * CLI users can specify `-4` or `-6` to filter BGP messages by IP version
* add new dependency security checkups using `cargo audit`
    * all new releases will need to pass `cargo audit` checks before being published
    * weekly `cargo audit` checks added to the CI pipeline

## v0.10.1 - 2024-02-23

### Highlights

* updating `oneio` to `v0.16.2`
    * switching to `flate2` with `zlib-ng` for handling `gzip` files, which is significantly faster than the default
      pure-Rust implementation

## v0.10.0 - 2024-02-12

Version 0.10.0 is a major release with a lot of changes and improvements.

### Highlights

#### MRT Encoding

`bgpkit-parser` now supports encoding MRT messages. The following MRT message types are supported:

- TableDumpV1
- TableDumpV2
- BGP4MP
  It also supports encoding BMP messages into MRT files.

Example of writing BgpElems into a file RIB dump file:

```rust
let mut encoder = bgpkit_parser::encoder::MrtRibEncoder::new();
for elem in parser {
encoder.process_elem( & elem);
}
let mut writer = oneio::get_writer("filtered.rib.gz").unwrap();
writer.write_all(encoder.export_bytes().as_ref()).unwrap();
drop(writer);
```

Another example of writing `BgpElem` to BGP updates bytes:

```rust
let mut encoder = bgpkit_parser::encoder::MrtUpdatesEncoder::new();
let mut elem = BgpElem::default ();
elem.peer_ip = IpAddr::V4("10.0.0.1".parse().unwrap());
elem.peer_asn = Asn::from(65000);
elem.prefix.prefix = "10.250.0.0/24".parse().unwrap();
encoder.process_elem( & elem);
elem.prefix.prefix = "10.251.0.0/24".parse().unwrap();
encoder.process_elem( & elem);
let bytes = encoder.export_bytes();

let mut cursor = Cursor::new(bytes.clone());
while cursor.has_remaining() {
let parsed = parse_mrt_record( & mut cursor).unwrap();
dbg ! ( & parsed);
}
```

See `encoder` module for more details.

#### Better developer experiences

- added several utility functions to `BgpElem`
    - `.is_announcement()`: check if the BGP element is an announcement
    - `.get_as_path_opt()`: get the AS path if it exists and no AS set or confederated segments
    - `.get_origin_asn_opt()`: get the origin ASN if it exists
- full `serde` serialization support
- add `BgpElem` to PSV (pipe-separated values) conversion
- improved time-related filters parsing
    - `ts_start` `start_ts` `ts_end` `end_ts` are all supported
- many quality of life improvements by [@jmeggitt](https://github.com/jmeggitt)
    - https://github.com/bgpkit/bgpkit-parser/pull/122
    - https://github.com/bgpkit/bgpkit-parser/pull/123

#### Improved testing coverage

- `bgpkit-parser` code test coverage is now at 92%.
    - codecov.io coverage report is available at https://app.codecov.io/gh/bgpkit/bgpkit-parser

#### TLS backend choice

- by default, `bgpkit-parser` now uses `rustls` as the default TLS backend
    - `openssl` is still supported, but it is no longer the default
    - `openssl` support can be enabled by using the `native-tls` feature flag and set default features to `false`

### Added RFCs support

- [`RFC 4724: Graceful Restart Mechanism for BGP`][rfc4724]
- [`RFC 8671 Support for Adj-RIB-Out in the BGP Monitoring Protocol (BMP)`][rfc8671]
- [`RFC 9069: Support for Local RIB in the BGP Monitoring Protocol (BMP)`][rfc9069]
- the supported RFCs list is documented at https://github.com/bgpkit/bgpkit-parser?tab=readme-ov-file#rfcs-support

[rfc4724]: https://www.rfc-editor.org/rfc/rfc4724

[rfc8671]: https://www.rfc-editor.org/rfc/rfc8671

[rfc9069]: https://www.rfc-editor.org/rfc/rfc9069

### Fixes

- fixed a bug where when multiple `AsSequences` are present, only the first one is parsed
    - issue: https://github.com/bgpkit/bgpkit-parser/issues/140
- fixed a bug where the parser panics when messages are truncated
    - https://github.com/bgpkit/bgpkit-parser/issues/149

### Other changes

- Move pybgpkit to its own repository at https://github.com/bgpkit/pybgpkit
- CLI build feature changed from `build-binary` to `cli`
- add more ways to install compiled `bgpkit-parser` CLI
    - homebrew on macOS: `brew install bgpkit/tap/bgpkit-parser`
    - other platforms: `cargo binstall bgpkit-parser`

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
