# BGPKIT Parser

BGPKIT Parser provides MRT/BGP message parsing functionalities written in Rust.

## Features

BGPKIT Parser has the following features:
- performance comparable to C-based implementations like `bgpdump` or `bgpreader`.
- supporting most of the relevant BGP RFCs.
- simple API serves as building block for more complex workflows.

## Key Data Structures

There are two key data structure to understand the parsing results:`MrtRecord` and `BgpElem`.

### `MrtRecord`: unmodified MRT information representation

The `MrtRecord` is the data strcutrue that holds the unmodified, complete information parsed
from the MRT data file. The code definition of the `MrtRecord` is defined in the crate `bgp-models` ([documentation][mrt-record-doc]).

```rust
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

### `BgpElem`: per-prefix BGP information, MRT-format-agnostic

To facilitate simpler data analysis of BGP data, we defined a new data structure called `BgpElem` in this crate. Each 
`BgpElem` contains a piece of self-containing BGP information about one single IP prefix.
For example, when a bundled announcement of three prefixes P1, P2, P3 that shares the same AS path is processed, we break
the single record into three different `BgpElem` objects, each presenting a prefix. 

```rust
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

The main benefit of using `BgpElem` is that the analysis can be executed on a per-prefix basis, generic to what the 
backend MRT data format (bgp4mp, tabledumpv1, tabledumpv2, etc.). The obvious drawback is that we will have to duplicate
information to save at each elem, that consuming more memory. 

[mrt-record-doc]: https://docs.rs/bgp-models/0.3.4/bgp_models/mrt/struct.MrtRecord.html

## Examples

For complete examples, check out the [examples folder](examples)

### Parsing single MRT file

If having a file location already known, a user can directly read the data into memory and parse the bytes to creat
a parser object. The BGPKIT Parser provides convenient iterator over either `BgpElem` (the default iterator, or `.into_iter()`),
or `MrtRecord` (use `.into_record_iter()`). The example below iterates through all the elements in a single MRT updates file,
and logging all the announcements that were originated from a specific ASN.

```rust
// read updates data into bytes
let data_bytes = reqwest::blocking::get("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2")
    .unwrap().bytes().unwrap().to_vec();
// create a buffered reader that wraps around a bzip2 decoder
let reader = BufReader::new(BzDecoder::new(&*data_bytes));
// create a parser that takes the buffered reader
let parser = BgpkitParser::new(reader);

// iterating through the parser. the iterator returns `BgpElem` one at a time.
for elem in parser {
    // each BGP announcement contains one AS path, which depending on the path segment's type
    // there could be multiple origin ASNs (e.g. AS-Set as the origin)
    if let Some(origins) = &elem.origin_asns {
        if origins.contains(&13335) {
            log::info!("{}", &elem);
        }
    }
}
```

### Parsing multiple MRT files with BGPKIT Broker

[BGPKIT Broker][broker-repo] library provides search API for all RouteViews and RIPE RIS MRT data files. Using the 
broker's Rust API ([`bgpkit-broker`][broker-crates-io]), we can easily compile a list of MRT files that we are interested
in for any time period and any data type (`update` or `rib`). This allows users to gather information without needing to
know about locations of specific data files. 

[broker-repo]: https://github.com/bgpkit/bgpkit-broker
[broker-crates-io]: https://crates.io/crates/bgpkit-broker

```rust
let mut params = bgpkit_broker::QueryParams::new();
params = params.start_ts(1634693400);
params = params.end_ts(1634693400);
params = params.data_type("update");
let mut broker = bgpkit_broker::BgpkitBroker::new("https://api.broker.bgpkit.com/v1");
broker.set_params(&params);

for item in broker {
    log::info!("downloading updates file: {}", &item.url);
    // read updates data into bytes
    let data_bytes = reqwest::blocking::get(item.url)
    .unwrap().bytes().unwrap().to_vec();
    // create a buffered reader that wraps around a bzip2 decoder
    let reader = BufReader::new(BzDecoder::new(&*data_bytes));
    // create a parser that takes the buffered reader
    let parser = BgpkitParser::new(reader);

    log::info!("parsing updates file");
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
```

## Contribution

Issues and pull requests are welcome!

## Built with ❤️ by BGPKIT Team

BGPKIT is a small-team start-up that focus on building the best tooling for BGP data in Rust. We have 10 years of
experience working with BGP data and believe that our work can enable more companies to start keeping tracks of BGP data
on their own turf. Learn more about what services we provide at https://bgpkit.com.

<a href="https://bgpkit.com"><img src="https://bgpkit.com/Original%20Logo%20Cropped.png" alt="https://bgpkit.com/favicon.ico" width="200"/></a>
