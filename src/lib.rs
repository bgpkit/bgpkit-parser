/*!
BGPKIT Parser aims to provide the most ergonomic MRT/BGP/BMP message parsing Rust API.

BGPKIT Parser has the following features:
- **performant**: comparable to C-based implementations like `bgpdump` or `bgpreader`.
- **actively maintained**: we consistently introduce feature updates and bug fixes, and support most of the relevant BGP RFCs.
- **ergonomic API**: a three-line for loop can already get you started.
- **battery-included**: ready to handle remote or local, bzip2 or gz data files out of the box

# Examples

For complete examples, check out the [examples folder](https://github.com/bgpkit/bgpkit-parser/tree/main/examples).

## Parsing single MRT file

Let's say we want to print out all the BGP announcements/withdrawal from a single MRT file, either located remotely or locally.
Here is an example that does so.

```no_run
use bgpkit_parser::BgpkitParser;
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap();
for elem in parser {
    println!("{}", elem)
}
```

Yes, it is this simple!

You can even do some more interesting iterator operations that are event shorter.
For example, counting the number of announcements/withdrawals in that file:
```no_run
use bgpkit_parser::BgpkitParser;
let url = "http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2";
let count = BgpkitParser::new(url).unwrap().into_iter().count();
println!("total: {}", count);
```

and it prints out
```text
total: 255849
```

## Parsing multiple MRT files with BGPKIT Broker

[BGPKIT Broker][broker-repo] library provides search API for all RouteViews and RIPE RIS MRT data files. Using the
broker's Rust API ([`bgpkit-broker`][broker-crates-io]), we can easily compile a list of MRT files that we are interested
in for any time period and any data type (`update` or `rib`). This allows users to gather information without needing to
know about the locations of specific data files.

[broker-repo]: https://github.com/bgpkit/bgpkit-broker
[broker-crates-io]: https://crates.io/crates/bgpkit-broker

The example below shows a relatively more interesting example that does the following:
- find all BGP archive data created on time 1634693400
- filter to only BGP updates files
- find all announcements originated from AS13335
- print out the total count of the announcements

```no_run
use bgpkit_parser::{BgpkitParser, BgpElem};

let broker = bgpkit_broker::BgpkitBroker::new()
    .ts_start("1634693400")
    .ts_end("1634693400")
    .page(1);

for item in broker.into_iter().take(2) {
    log::info!("downloading updates file: {}", &item.url);
    let parser = BgpkitParser::new(item.url.as_str()).unwrap();

    log::info!("parsing updates file");
    // iterating through the parser. the iterator returns `BgpElem` one at a time.
    let elems = parser
        .into_elem_iter()
        .filter_map(|elem| {
            if let Some(origins) = &elem.origin_asns {
                if origins.contains(&13335.into()) {
                    Some(elem)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect::<Vec<BgpElem>>();
    log::info!("{} elems matches", elems.len());
}
```

## Filtering BGP Messages

BGPKIT Parser also has a built-in [Filter] mechanism. When creating a new [`BgpkitParser`] instance,
once can also call `add_filter` function to customize the parser to only show matching messages
when iterating through [BgpElem]s.

For all types of filters, check out the [Filter] enum documentation.

```no_run
use bgpkit_parser::BgpkitParser;

/// This example shows how to parse an MRT file and filter by prefix.
env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

log::info!("downloading updates file");

// create a parser that takes the buffered reader
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter("prefix", "211.98.251.0/24").unwrap();

log::info!("parsing updates file");
// iterating through the parser. the iterator returns `BgpElem` one at a time.
for elem in parser {
    log::info!("{}", &elem);
}
log::info!("done");
```


## Parsing Real-time Data Streams

BGPKIT Parser also provides parsing functionalities for real-time data streams, including [RIS-Live][ris-live-url]
and [BMP][bmp-rfc]/[OpenBMP][openbmp-url] messages. See the examples below and the documentation for more.

### Parsing Messages From RIS-Live

Here is an example of handling RIS-Live message streams. After connecting to the websocket server,
we need to subscribe to a specific data stream. In this example, we subscribe to the data stream
from on collector (`rrc21`). We can then loop and read messages from the websocket.

```no_run
# #[cfg(feature = "rislive")]
use bgpkit_parser::parse_ris_live_message;
use serde_json::json;
use tungstenite::{connect, Message};

const RIS_LIVE_URL: &str = "ws://ris-live.ripe.net/v1/ws/?client=rust-bgpkit-parser";

/// This is an example of subscribing to RIS-Live's streaming data from one host (`rrc21`).
///
/// For more RIS-Live details, check out their documentation at https://ris-live.ripe.net/manual/
fn main() {
    // connect to RIPE RIS Live websocket server
    let (mut socket, _response) =
        connect(RIS_LIVE_URL)
            .expect("Can't connect to RIS Live websocket server");

    // subscribe to messages from one collector
    let msg = json!({"type": "ris_subscribe", "data": {"host": "rrc21"}}).to_string();
    socket.send(Message::Text(msg.into())).unwrap();

    loop {
        let msg = socket.read().expect("Error reading message").to_string();
#       #[cfg(feature = "rislive")]
        if let Ok(elems) = parse_ris_live_message(msg.as_str()) {
            for elem in elems {
                println!("{}", elem);
            }
        }
    }
}
```

### Parsing OpenBMP Messages From RouteViews Kafka Stream

[RouteViews](http://www.routeviews.org/routeviews/) provides a real-time Kafka stream of the OpenBMP
data received from their collectors. Below is a partial example of how we handle the raw bytes
received from the Kafka stream. For full examples, check out the [examples folder on GitHub](https://github.com/bgpkit/bgpkit-parser/tree/main/examples).

```ignore
let bytes = m.value;
let mut reader = Cursor::new(Vec::from(bytes));
let header = parse_openbmp_header(&mut reader).unwrap();
let bmp_msg = parse_bmp_msg(&mut reader);
match bmp_msg {
    Ok(msg) => {
        let timestamp = header.timestamp;
        let per_peer_header = msg.per_peer_header.unwrap();
        match msg.message_body {
            MessageBody::RouteMonitoring(m) => {
                for elem in Elementor::bgp_to_elems(
                    m.bgp_message,
                    timestamp,
                    &per_peer_header.peer_ip,
                    &per_peer_header.peer_asn
                )
                {
                    info!("{}", elem);
                }
            }
            _ => {}
        }
    }
    Err(_e) => {
        let hex = hex::encode(bytes);
        error!("{}", hex);
        break
    }
}
```

[ris-live-url]: https://ris-live.ripe.net
[bmp-rfc]: https://datatracker.ietf.org/doc/html/rfc7854
[openbmp-url]: https://www.openbmp.org/

### Archive filtered MRT records to a new MRT file on disk

The example will download one MRT file from RouteViews, filter out all the BGP messages that
are not originated from AS3356, and write the filtered MRT records to disk. Then it re-parses the
filtered MRT file and prints out the number of BGP messages.

```no_run
use bgpkit_parser::Elementor;
use itertools::Itertools;
use std::io::Write;

let mut updates_encoder = bgpkit_parser::encoder::MrtUpdatesEncoder::new();

bgpkit_parser::BgpkitParser::new(
    "http://archive.routeviews.org/bgpdata/2023.10/UPDATES/updates.20231029.2015.bz2",
).unwrap()
    .add_filter("origin_asn", "3356").unwrap()
    .into_iter()
    .for_each(|elem| {
        updates_encoder.process_elem(&elem);
    });

let mut mrt_writer = oneio::get_writer("as3356_mrt.gz").unwrap();
mrt_writer.write_all(updates_encoder.export_bytes().as_ref()).unwrap();
drop(mrt_writer);
```

# Command Line Tool

`bgpkit-parser` is bundled with a utility commandline tool `bgpkit-parser-cli`.

## Installation

### Install compiled binaries

You can install the compiled `bgpkit-parser` CLI binaries with the following methods:
- **Homebrew** (macOS): `brew install bgpkit/tap/bgpkit-parser`
- [**Cargo binstall**](https://github.com/cargo-bins/cargo-binstall): `cargo binstall bgpkit-parser`

### From source

You can install the tool by running
```bash
cargo install bgpkit-parser --features cli
```
or checkout this repository and run
```bash
cargo install --path . --features cli
```

## Usage

Run `bgpkit-parser --help` to see the full list of options.

```text
MRT/BGP/BMP data processing library

Usage: bgpkit-parser [OPTIONS] <FILE>

Arguments:
  <FILE>  File path to a MRT file, local or remote

Options:
  -c, --cache-dir <CACHE_DIR>    Set the cache directory for caching remote files. Default behavior does not enable caching
      --json                     Output as JSON objects
      --psv                      Output as full PSV entries with header
      --pretty                   Pretty-print JSON output
  -e, --elems-count              Count BGP elems
  -r, --records-count            Count MRT records
  -o, --origin-asn <ORIGIN_ASN>  Filter by origin AS Number
  -p, --prefix <PREFIX>          Filter by network prefix
  -4, --ipv4-only                Filter by IPv4 only
  -6, --ipv6-only                Filter by IPv6 only
  -s, --include-super            Include super-prefix when filtering
  -S, --include-sub              Include sub-prefix when filtering
  -j, --peer-ip <PEER_IP>        Filter by peer IP address
  -J, --peer-asn <PEER_ASN>      Filter by peer ASN
  -m, --elem-type <ELEM_TYPE>    Filter by elem type: announce (a) or withdraw (w)
  -t, --start-ts <START_TS>      Filter by start unix timestamp inclusive
  -T, --end-ts <END_TS>          Filter by end unix timestamp inclusive
  -a, --as-path <AS_PATH>        Filter by AS path regex string
  -h, --help                     Print help
  -V, --version                  Print version

```

# Data Representation

There are two key data structures to understand for the parsing results: [MrtRecord] and [BgpElem].

## `MrtRecord`: unmodified MRT information representation

The [MrtRecord] is the data structure that holds the unmodified, complete information parsed from the MRT data file.

```ignore
pub struct MrtRecord {
    pub common_header: CommonHeader,
    pub message: MrtMessage,
}

pub enum MrtMessage {
    TableDumpMessage(TableDumpMessage),
    TableDumpV2Message(TableDumpV2Message),
    Bgp4Mp(Bgp4Mp),
}
```

`MrtRecord` record representation is concise, storage efficient, but often less convenient to use. For example, when
trying to find out specific BGP announcements for certain IP prefix, we often needs to go through nested layers of
internal data structure (NLRI, announced, prefix, or even looking up peer index table for Table Dump V2 format), which
could be irrelevant to what users really want to do.

## [BgpElem]: per-prefix BGP information, MRT-format-agnostic

To facilitate simpler data analysis of BGP data, we defined a new data structure called [BgpElem] in this crate. Each
[BgpElem] contains a piece of self-containing BGP information about one single IP prefix.
For example, when a bundled announcement of three prefixes P1, P2, P3 that shares the same AS path is processed, we break
the single record into three different [BgpElem] objects, each presenting a prefix.

```ignore
pub struct BgpElem {
    pub timestamp: f64,
    pub elem_type: ElemType,
    pub peer_ip: IpAddr,
    pub peer_asn: Asn,
    pub prefix: NetworkPrefix,
    pub next_hop: Option<IpAddr>,
    pub as_path: Option<AsPath>,
    pub origin_asns: Option<Vec<Asn>>,
    pub origin: Option<Origin>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub communities: Option<Vec<Community>>,
    pub atomic: Option<AtomicAggregate>,
    pub aggr_asn: Option<Asn>,
    pub aggr_ip: Option<IpAddr>,
}
```

The main benefit of using [BgpElem] is that the analysis can be executed on a per-prefix basis, generic to what the
backend MRT data format (bgp4mp, tabledumpv1, tabledumpv2, etc.). The obvious drawback is that we will have to duplicate
information to save at each elem, that consuming more memory.

# RFCs Support

We support most of the RFCs and plan to continue adding support for more recent RFCs in the future.
Here is a list of relevant RFCs that we support or plan to add support.

If you would like to see any specific RFC's support, please submit an issue on GitHub.

## BGP

- [X] [RFC 2042](https://datatracker.ietf.org/doc/html/rfc2042): Registering New BGP Attribute Types
- [X] [RFC 2858](https://datatracker.ietf.org/doc/html/rfc2858): Multiprotocol Extensions for BGP-4
- [X] [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918): Route Refresh Capability for BGP-4
- [X] [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392): Capabilities Advertisement with BGP-4
- [X] [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271): A Border Gateway Protocol 4 (BGP-4)
- [X] [RFC 4724](https://datatracker.ietf.org/doc/html/rfc4724): Graceful Restart Mechanism for BGP
- [X] [RFC 4456](https://datatracker.ietf.org/doc/html/rfc4456): BGP Route Reflection: An Alternative to Full Mesh Internal BGP (IBGP)
- [X] [RFC 5065](https://datatracker.ietf.org/doc/html/rfc5065): Autonomous System Confederations for BGP
- [X] [RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793): BGP Support for Four-Octet Autonomous System (AS) Number Space
- [X] [RFC 7606](https://datatracker.ietf.org/doc/html/rfc7606): Revised Error Handling for BGP UPDATE Messages
- [X] [RFC 7911](https://datatracker.ietf.org/doc/html/rfc7911): Advertisement of Multiple Paths in BGP (ADD-PATH)
- [X] [RFC 8950](https://datatracker.ietf.org/doc/html/rfc8950): Advertising IPv4 Network Layer Reachability Information (NLRI) with an IPv6 Next Hop
- [X] [RFC 9072](https://datatracker.ietf.org/doc/html/rfc9072): Extended Optional Parameters Length for BGP OPEN Message Updates
- [X] [RFC 9234](https://datatracker.ietf.org/doc/html/rfc9234):  Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages

## Tunnel Encapsulation

- [X] [RFC 5640](https://datatracker.ietf.org/doc/html/rfc5640): Load-Balancing for Mesh Softwires
- [X] [RFC 8365](https://datatracker.ietf.org/doc/html/rfc8365): A Network Virtualization Overlay Solution Using Ethernet VPN (EVPN)
- [X] [RFC 9012](https://datatracker.ietf.org/doc/html/rfc9012): The BGP Tunnel Encapsulation Attribute

## MRT

- [X] [RFC 6396](https://datatracker.ietf.org/doc/html/rfc6396): Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format
- [X] [RFC 6397](https://datatracker.ietf.org/doc/html/rfc6397): Multi-Threaded Routing Toolkit (MRT) Border Gateway Protocol (BGP) Routing Information Export Format with Geo-Location Extensions
- [X] [RFC 8050](https://datatracker.ietf.org/doc/html/rfc8050): Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format with BGP Additional Path Extensions

## BMP

- [X] [RFC 7854](https://datatracker.ietf.org/doc/html/rfc7854): BGP Monitoring Protocol (BMP)
- [X] [RFC 8671](https://datatracker.ietf.org/doc/html/rfc8671): Support for Adj-RIB-Out in the BGP Monitoring Protocol (BMP)
- [X] [RFC 9069](https://datatracker.ietf.org/doc/html/rfc9069): Support for Local RIB in the BGP Monitoring Protocol (BMP)

## Communities

We support normal communities, extended communities, and large communities.

- [X] [RFC 1977](https://datatracker.ietf.org/doc/html/rfc1977): BGP Communities Attribute
- [X] [RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360): BGP Extended Communities Attribute
- [X] [RFC 5668](https://datatracker.ietf.org/doc/html/rfc5668): 4-Octet AS Specific BGP Extended Community
- [X] [RFC 5701](https://datatracker.ietf.org/doc/html/rfc5701): IPv6 Address Specific BGP Extended Community Attribute
- [X] [RFC 7153](https://datatracker.ietf.org/doc/html/rfc7153): IANA Registries for BGP Extended Communities Updates 4360, 5701
- [X] [RFC 8097](https://datatracker.ietf.org/doc/html/rfc8097): BGP Prefix Origin Validation State Extended Community
- [X] [RFC 8092](https://datatracker.ietf.org/doc/html/rfc8092): BGP Large Communities

## FlowSpec

- [X] [RFC 8955](https://datatracker.ietf.org/doc/html/rfc8955) Dissemination of Flow Specification Rules
- [X] [RFC 8956](https://datatracker.ietf.org/doc/html/rfc8956) Dissemination of Flow Specification Rules for IPv6
- [X] [RFC 9117](https://datatracker.ietf.org/doc/html/rfc9117) Revised Validation Procedure for BGP Flow Specifications Updates 8955

## Link-State
- [X] [RFC 7752](https://datatracker.ietf.org/doc/html/rfc7752): North-Bound Distribution of Link-State and Traffic Engineering (TE) Information Using BGP
- [X] [RFC 8571](https://datatracker.ietf.org/doc/html/rfc8571): BGP - Link State (BGP-LS) Advertisement of IGP Traffic Engineering Performance Metric Extensions
- [X] [RFC 9085](https://datatracker.ietf.org/doc/html/rfc9085): Border Gateway Protocol - Link State (BGP-LS) Extensions for Segment Routing
- [X] [RFC 9294](https://datatracker.ietf.org/doc/html/rfc9294): BGP-LS Advertisement of Application-Specific Link Attributes

# Built with ❤️ by BGPKIT Team

<a href="https://bgpkit.com"><img src="https://bgpkit.com/Original%20Logo%20Cropped.png" alt="https://bgpkit.com/favicon.ico" width="200"/></a>
*/

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/bgpkit/assets/main/logos/icon-transparent.png",
    html_favicon_url = "https://raw.githubusercontent.com/bgpkit/assets/main/logos/favicon.ico"
)]

#[cfg(feature = "parser")]
pub mod encoder;
pub mod error;
pub mod models;
#[cfg(feature = "parser")]
pub mod parser;

pub use models::BgpElem;
pub use models::MrtRecord;
#[cfg(feature = "parser")]
pub use parser::*;
