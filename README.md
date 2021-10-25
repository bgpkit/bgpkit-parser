# BGPKIT Parser

BGPKIT Parser aims to provides the most ergonomic MRT/BGP message parsing Rust API.

BGPKIT Parser has the following features:
- **performant**: comparable to C-based implementations like `bgpdump` or `bgpreader`.
- **actively maintained**: we consistently introduce feature updates and bug fixes, and support most of the relevant BGP RFCs.
- **ergonomic API**: a three-line for loop can already get you started.
- **battery-included**: ready to handle remote or local, bzip2 or gz data files out of the box

## Examples

For complete examples, check out the [examples folder](examples).

### Parsing single MRT file

Let's say we want to print out all the BGP announcements/withdrawal from a single MRT file, either located remotely or locally.
Here is an example that does so.

```rust
use bgpkit_parser::BgpkitParser;
fn main() {
    let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2");
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
    let count = BgpkitParser::new(url).into_iter().count();
    println!("total: {}", count);
}
```

and it prints out
```
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

```rust
fn main(){
    // set broker query parameters
    let mut params = bgpkit_broker::QueryParams::new();
    params = params.start_ts(1634693400);
    params = params.end_ts(1634693400);
    params = params.data_type("update");
    let mut broker = bgpkit_broker::BgpkitBroker::new("https://api.broker.bgpkit.com/v1");
    broker.set_params(&params);

    // loop through data files found by broker
    for item in broker {
        
        // create a parser that takes an URL and automatically determine
        // the file location and file type, and handles data download and
        // decompression streaming intelligently
        let parser = BgpkitParser::new(item.url.as_str());

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

## Data Representation

There are two key data structure to understand for the parsing results:`MrtRecord` and `BgpElem`.

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


## Contribution

Issues and pull requests are welcome!

## Built with ❤️ by BGPKIT Team

BGPKIT is a small-team start-up that focus on building the best tooling for BGP data in Rust. We have 10 years of
experience working with BGP data and believe that our work can enable more companies to start keeping tracks of BGP data
on their own turf. Learn more about what services we provide at https://bgpkit.com.

<a href="https://bgpkit.com"><img src="https://bgpkit.com/Original%20Logo%20Cropped.png" alt="https://bgpkit.com/favicon.ico" width="200"/></a>
