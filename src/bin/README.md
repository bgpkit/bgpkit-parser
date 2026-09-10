# bgpkit-parser CLI

`bgpkit-parser` is a simple CLI tool for parsing MRT/BGP/BMP files, built from this crate with
`--features cli`. The crate README documents the library API and CLI examples in full; this file
records the current option set.

## Usage

```text
MRT/BGP/BMP data processing library

Usage: bgpkit-parser [OPTIONS] <FILE>

Arguments:
  <FILE>  File path to a MRT file, local or remote

Options:
  -c, --cache-dir <CACHE_DIR>    Set the cache directory for caching remote files
  -F, --format <FORMAT>          Output format: default, json, json-pretty, psv, text [default: default]
  -L, --level <LEVEL>            Output level: elems (per-prefix) or records (MRT records) [default: elems]
      --json                     Output as JSON objects (shorthand for --format json)
      --pretty                   Pretty-print JSON output (shorthand for --format json-pretty)
      --psv                      Output as full PSV entries with header (shorthand for --format psv)
      --hex                      Include each record's raw bytes as hex (record-level output only)
      --color <COLOR>            Colorize --format text output: auto, always, never [default: auto]
  -e, --elems-count              Count BGP elems
  -r, --records-count            Count MRT records
      --recover                  Recover after damaged MRT framing and report skipped byte ranges on stderr
  -o, --origin-asn <ORIGIN_ASN>  Filter by origin AS Number
  -f, --filter <FILTERS>         Generic filter expression (key=value or key!=value)
  -p, --prefix <PREFIX>          Filter by network prefix
  -s, --include-super            Include super-prefix when filtering
  -S, --include-sub              Include sub-prefix when filtering
  -4, --ipv4-only                Filter by IPv4 only
  -6, --ipv6-only                Filter by IPv6 only
  -j, --peer-ip <PEER_IP>        Filter by peer IP address
  -J, --peer-asn <PEER_ASN>      Filter by peer ASN
  -m, --elem-type <ELEM_TYPE>    Filter by elem type: announce (a) or withdraw (w)
  -t, --start-ts <START_TS>      Filter by start unix timestamp inclusive
  -T, --end-ts <END_TS>          Filter by end unix timestamp inclusive
  -a, --as-path <AS_PATH>        Filter by AS path regex string
  -C, --community <COMMUNITY>    Filter by community string
  -h, --help                     Print help
  -V, --version                  Print version
```

Run `bgpkit-parser --help` for the complete option descriptions, and see the crate README for
worked examples (local and remote files, counting, filtering).
