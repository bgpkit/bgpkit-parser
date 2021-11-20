/*!
BGPKIT Parser aims to provides the most ergonomic MRT/BGP message parsing Rust API.

Features:
- **performant**: comparable to C-based implementations like `bgpdump` or `bgpreader`.
- **actively maintained**: we consistently introduce feature updates and bug fixes, and support most of the relevant BGP RFCs.
- **ergonomic API**: a three-line for loop can already get you started.
- **battery-included**: ready to handle remote or local, bzip2 or gz data files out of the box

## Examples

### Parsing single MRT file

Let's say we want to print out all the BGP announcements/withdrawal from a single MRT file, either located remotely or locally.
Here is an example that does so.

```rust
use bgpkit_parser::BgpkitParser;
fn main() {
    let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap();
    for elem in parser {
        println!("{}", elem)
    }
}
```

Yes, it is this simple!

You can even do some more interesting iterator operations that are event shorter.
For example, counting the number of announcements/withdrawals in that file:
```rust
use bgpkit_parser::BgpkitParser;
fn main() {
    let url = "http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2";
    let count = BgpkitParser::new(url).unwrap().into_iter().count();
    println!("total: {}", count);
}
```

and it prints out
```text
total: 255849
```

### Parsing multiple MRT files with BGPKIT Broker

[BGPKIT Broker][broker-repo] library provides search API for all RouteViews and RIPE RIS MRT data files. Using the
broker's Rust API ([`bgpkit-broker`][broker-crates-io]), we can easily compile a list of MRT files that we are interested
in for any time period and any data type (`update` or `rib`). This allows users to gather information without needing to
know about locations of specific data files.

[broker-repo]: https://github.com/bgpkit/bgpkit-broker
[broker-crates-io]: https://crates.io/crates/bgpkit-broker

The example below shows a relatively more interesting example that does the following:
- find all BGP archive data created on time 1634693400
- filter to only BGP updates files
- find all announcements originated from AS13335
- print out the total count of the announcements

```no_run
use bgpkit_parser::{BgpkitParser, BgpElem};
fn main(){
    // set broker query parameters
    let broker = bgpkit_broker::BgpkitBroker::new_with_params(
       "https://api.broker.bgpkit.com/v1",
       bgpkit_broker::QueryParams{
           start_ts: Some(1634693400),
           end_ts: Some(1634693400),
           page: 1,
           ..Default::default()
    });

    // loop through data files found by broker
    for item in broker {

        // create a parser that takes an URL and automatically determine
        // the file location and file type, and handles data download and
        // decompression streaming intelligently
        let parser = BgpkitParser::new(item.url.as_str()).unwrap();

        // iterating through the parser. the iterator returns `BgpElem` one at a time.
        let elems = parser.into_elem_iter().map(|elem|{
            if let Some(origins) = &elem.origin_asns {
                if origins.contains(&13335) {
                    Some(elem)
                } else {
                    None
                }
            } else {
                None
            }
        }).filter_map(|x|x).collect::<Vec<BgpElem>>();
        log::info!("{} elems matches", elems.len());
    }
}
```

### Parsing Real-time Data Streams

BGPKIT Parser also provides parsing functionalities for real-time data streams, including [RIS-Live][ris-live-url]
and [BMP][bmp-rfc]/[OpenBMP][openbmp-url] messages. See the examples below and the documentation for more.

#### Parsing Messages From RIS-Live

Here is an example of handling RIS-Live message streams. After connecting to the websocket server,
we need to subscribe to a specific data stream. In this example, we subscribe to the data stream
from on collector (`rrc21`). We can then loop and read messages from the websocket.

```no_run
use bgpkit_parser::parse_ris_live_message;
use serde_json::json;
use tungstenite::{connect, Message};
use url::Url;

const RIS_LIVE_URL: &str = "ws://ris-live.ripe.net/v1/ws/?client=rust-bgpkit-parser";

/// This is an example of subscribing to RIS-Live's streaming data from one host (`rrc21`).
///
/// For more RIS-Live details, check out their documentation at https://ris-live.ripe.net/manual/
fn main() {
    // connect to RIPE RIS Live websocket server
    let (mut socket, _response) =
        connect(Url::parse(RIS_LIVE_URL).unwrap())
            .expect("Can't connect to RIS Live websocket server");

    // subscribe to messages from one collector
    let msg = json!({"type": "ris_subscribe", "data": {"host": "rrc21"}}).to_string();
    socket.write_message(Message::Text(msg)).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message").to_string();
        if let Ok(elems) = parse_ris_live_message(msg.as_str()) {
            for elem in elems {
                println!("{}", elem);
            }
        }
    }
}
```

#### Parsing OpenBMP Messages From RouteViews Kafka Stream

[RouteViews](http://www.routeviews.org/routeviews/) provides a real-time Kafka stream of the OpenBMP
data received from their collectors. Below is an partial example of how we handle the raw bytes
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

## Data Representation

There are two key data structure to understand for the parsing results: [MrtRecord][bgp_models::mrt::MrtRecord] and [BgpElem].

### `MrtRecord`: unmodified MRT information representation

The MrtRecord is the data structrue that holds the unmodified, complete information parsed
from the MRT data file. The code definition of the `MrtRecord` is defined in the crate `bgp-models` ([documentation][mrt-record-doc]).

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

MrtRecord record representation is concise, storage efficient, but often less convenient to use. For example, when
trying to find out specific BGP announcements for certain IP prefix, we often needs to go through nested layers of
internal data structure (NLRI, announced, prefix, or even looking up peer index table for Table Dump V2 format), which
could be irrelevant to what users really want to do.

### [BgpElem]: per-prefix BGP information, MRT-format-agnostic

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

[mrt-record-doc]: https://docs.rs/bgp-models/0.3.4/bgp_models/mrt/struct.MrtRecord.html
*/
extern crate byteorder;
extern crate chrono;
extern crate ipnetwork;
extern crate num_traits;

#[macro_use]
extern crate enum_primitive_derive;

pub mod error;
pub mod parser;

mod io;

pub use parser::BgpkitParser;
pub use parser::BgpElem;
pub use parser::ParserError;
pub use parser::Elementor;
pub use parser::iters::{ElemIterator, RecordIterator};
pub use parser::bmp::parse_openbmp_msg;
pub use parser::bmp::parse_bmp_msg;
pub use parser::bmp::parse_openbmp_header;
pub use parser::rislive::parse_ris_live_message;
