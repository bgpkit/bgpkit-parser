# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Breaking changes

* change `path_id` from `u32` to `Option<u32>` for proper null handling
    * `NetworkPrefix::path_id` field now properly represents absence with `None` instead of using `0`
    * `NetworkPrefix::new()` and `NetworkPrefix::encode()` signatures updated accordingly
    * `RibEntry` now stores `path_id` for TABLE_DUMP_V2 messages with AddPath support
    * fixes issue [#217](https://github.com/bgpkit/bgpkit-parser/issues/217)

### Code improvements

* added RFC 8950 support for IPv4 NLRI with IPv6 next-hops
    * extended `Safi` enum with `MplsVpn` (128) and `MulticastVpn` (129) for VPN address families
    * added `RouteDistinguisher` type for VPN next-hop parsing
    * extended `NextHopAddress` enum with `VpnIpv6` and `VpnIpv6LinkLocal` variants
    * updated `parse_mp_next_hop` to handle 24-byte and 48-byte VPN next-hops
    * enables parsing of VPN-IPv4 routes with VPN-IPv6 next-hops per RFC 8950 Section 4
* added RFC 9069 validation warnings for BMP Local RIB peer types
    * validates Local RIB peer header requirements including zero-filled peer address and 4-byte ASN encoding
    * validates Local RIB peer up notifications for fabricated OPEN messages and VrTableName TLV presence
    * validates Local RIB route monitoring messages for proper ASN encoding
    * validation warnings logged when BMP messages do not conform to RFC 9069 specifications

### Bug fixes

* fixed TABLE_DUMP_V2 parsing to properly store path_id when AddPath is enabled
    * previously path_id was read but discarded, now properly stored in `RibEntry`

## v0.11.1 - 2025-06-06

### Bug fixes

* Fixed an issue where IPv6 NLRI next-hop addresses were not properly passed to `BgpElem` objects.
    * The fix ensures that the `next_hop` value is extracted from either `NEXT_HOP` or `MP_REACHABLE_NLRI` BGP
      attribute, and is correctly set in the `BgpElem` object.
    * Fixes issue [#211](https://github.com/bgpkit/bgpkit-parser/issues/211)
    * Thanks [m-appel](https://github.com/m-appel) for reporting this issue!

### Maintenance

* Apply `cargo clippy` lints to the codebase
* Add more tests to improve code coverage

## v0.11.0 - 2025-02-26

### Breaking changes

* removing string format prefix like `lg:` or `ecv6` for large and extended communities
    * users who work with community value strings will have a unified experience for all community values
    * users can still use SDK to match and check different types of community values

### Highlights

* storing AS path filter regex object for reuse
    * this will improve filter performance
* allow filter messages by community values
    * by converting community values to string and do string comparison
* add `local` flag to allow local-only processing
    * this removes dependencies like `reqwest`
* support converting singleton AsSet to Vec<u32>
    * when calling `to_u32_vec_opt` on AS path object, singleton AsSet will be treated as single ASN

### Bug fixes

* fixed a bug where RIS-live withdrawal messages were not properly parsed

### Documentation

* add new RIS-Live async example

### Maintenance

* update dependencies
* add `.env` to gitignore
* remote unnecessary life-time annotations

## v0.10.11 - 2024-10-27

### Highlights

* Improved RIS Live message types and handling
* clean up dependencies
    * `models` feature is removed, and all dependencies are now required dependencies for the crate
    * `models` module no-longer requires dependencies introduced by parser, like `bytes` for encoding
* decouple `oneio` from `parser` feature
    * `oneio` is no-longer a required dependency for the parser
    * users can now use `parser` feature without `oneio` (with `--no-default-features` specified)
        * to create a new parser, one needs to user `BgpkitParser::from_reader` function instead of `BgpkitParser::new`
    * downstream libraries that only utilize parser code (such as RIS Live parsing) no-longer have to depend on oneio
* improve RouteViews Kafka example by allowing wildcard topic subscription

### Bug fixes

* fixed an issue where when merging `AS_PATH` and `AS4_PATH` segments, the parser incorrectly uses `AS_PATH` segment
  content
    * this issue may manifest as `AS_TRANS` (`AS23456`) appearing in the AS path while the correct 32-bit ASN has been
      sent in `AS4_PATH`

## v0.10.11-beta.1 - 2024-10-16

### Highlights

* Improved RIS Live message types and handling
* clean up dependencies
    * `models` feature is removed, and all dependencies are now required dependencies for the crate
    * `models` module no-longer requires dependencies introduced by parser, like `bytes` for encoding
* decouple `oneio` from `parser` feature
    * `oneio` is no-longer a required dependency for the parser
    * users can now use `parser` feature without `oneio` (with `--no-default-features` specified)
        * to create a new parser, one needs to user `BgpkitParser::from_reader` function instead of `BgpkitParser::new`
    * downstream libraries that only utilize parser code (such as RIS Live parsing) no-longer have to depend on oneio

## v0.10.10 - 2024-08-05

### Highlights

* update `oneio` to v0.17.0
    * now users can set env var `ONEIO_ACCEPT_INVALID_CERTS=true` to disable certificate validation, useful in some
      environment where users do not manage certificates

## v0.10.9 - 2024-04-12

### BMP messages SDK improvements

* expose all pub structs and enums for BMP messages
    * this allows users to access struct definitions and operate on them directly
* added `Copy` to `BmpMsgType`, `BmpPeerType` and `BmpPerPeerHeader`, `PerPeerFlags`, `BmpPeerType`
* implemented `Default`, `PartialEq`, `Eq` and `Hash` for `BmpPerPeerHeader`
    * this allows users and compare and hash `BmpPerPeerHeader` structs
    * also implemented `.strip_timestamp()` to remove the timestamp from the `BmpPerPeerHeader` struct for cases where
      the timestamp is not needed
* rename `MessageBody` to `BmpMessageBody`
* derive `Clone`, `PartialEq` to `BmpMessage` and `MessageBody`
* added serialization/deserialization support for `BmpMessage` and `BmpMessageBody`

## v0.10.8 - 2024-04-05

### Highlights

* improve support for more BMP data types and better error
  handling ([#163](https://github.com/bgpkit/bgpkit-parser/pull/163))
    * added explicit enum `PeerDownReason`, `TerminationReason`, `PeerUpTlvType` instead of saving them as integers
    * added support for AFI-SAFI gauge for `StatisticsReport` message
        * this fixes issue [#162](https://github.com/bgpkit/bgpkit-parser/pull/162)
    * added `UnknownTlvType` and `UnknownTlvValue` errors for parsing BMP TLV records
    * added `Clone` and `PartialEq` derives to most of the BMP message structs

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
