/*!
## Message Filters

The filters package defines a number of available filters that users can utilize, and implements
the filtering mechanism for [BgpElem].

The available filters are (`filter_type` (`FilterType`) -- definition):
- `origin_asn` (`OriginAsn(u32)`) -- origin AS number
- `prefix` (`Prefix(IpNetwork)`) -- network prefix
- `peer_ip` (`PeerIp(IpAddr)`) -- peer's IP address
- `peer_asn` (`PeerAsn(u32)`) -- peer's IP address
- `type` (`Type(ElemType)`) -- message type (`withdraw` or `announce`)
- `ts_start` (`TsStart(f64)`) and `ts_end` (`TsEnd(f64)`) -- start and end unix timestamp
- `as_path` (`AsPath(Regex)`) -- regular expression for AS path string

[Filter::new] function takes a str for filter type and str for filter value and returns a Result
of a [Filter] or a parsing error.

[BgpkitParser] also implements the function `add_filter("filter_type", "filter_value")` that takes the parser's ownership itself
and returns a new parser with specified filter added.

### Example

```no_run
use bgpkit_parser::BgpkitParser;

/// This example shows how to parse a MRT file and filter by prefix.
fn main() {
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
}
```

### Note

Currently, only [BgpElem] implements the filtering capability. Support for [MrtRecord] will come in
later releases.

*/
use std::net::IpAddr;
use std::str::FromStr;
use bgp_models::prelude::*;
use ipnetwork::IpNetwork;
use regex::Regex;
use crate::ParserErrorKind;
use crate::ParserErrorKind::FilterError;

/// Filter enum: definition o types of filters
///
/// The available filters are (`filter_type` (`FilterType`) -- definition):
/// - `origin_asn` (`OriginAsn(u32)`) -- origin AS number
/// - `prefix` (`Prefix(IpNetwork)`) -- network prefix
/// - `peer_ip` (`PeerIp(IpAddr)`) -- peer's IP address
/// - `peer_asn` (`PeerAsn(u32)`) -- peer's IP address
/// - `type` (`Type(ElemType)`) -- message type (`withdraw` or `announce`)
/// - `ts_start` (`TsStart(f64)`) and `ts_end` (`TsEnd(f64)`) -- start and end unix timestamp
/// - `as_path` (`AsPath(Regex)`) -- regular expression for AS path string
pub enum Filter {
    OriginAsn(u32),
    Prefix(IpNetwork),
    PeerIp(IpAddr),
    PeerAsn(u32),
    Type(ElemType),
    TsStart(f64),
    TsEnd(f64),
    AsPath(Regex),
}

impl Filter {
    pub fn new(filter_type: &str, filter_value: &str) -> Result<Filter, ParserErrorKind> {
        match filter_type {
            "origin_asn" => {
                match u32::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::OriginAsn(v))},
                    Err(_) => {
                        Err(FilterError(format!("cannot parse origin asn from {}", filter_value)))
                    }
                }
            }
            "prefix" => {
                match IpNetwork::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::Prefix(v))}
                    Err(_) => {
                        Err(FilterError(format!("cannot parse prefix from {}", filter_value)))
                    }
                }
            }
            "peer_ip" => {
                match IpAddr::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::PeerIp(v))}
                    Err(_) => {
                        Err(FilterError(format!("cannot parse peer IP from {}", filter_value)))
                    }
                }
            }
            "peer_asn" => {
                match u32::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::PeerAsn(v))},
                    Err(_) => {
                        Err(FilterError(format!("cannot parse peer asn from {}", filter_value)))
                    }
                }
            }
            "type" => {
                match filter_value {
                    "w"|"withdraw"|"withdrawal" => {
                        Ok(Filter::Type(ElemType::WITHDRAW))
                    }
                    "a"|"announce"|"announcement" => {
                        Ok(Filter::Type(ElemType::ANNOUNCE))
                    }
                    _ => {
                        Err(FilterError(format!("cannot parse elem type from {}", filter_value)))
                    }
                }
            }
            "start_ts" => {
                match f64::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::TsStart(v))},
                    Err(_) => {
                        Err(FilterError(format!("cannot parse f64 value from {}", filter_value)))
                    }
                }
            }
            "end_ts" => {
                match f64::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::TsEnd(v))},
                    Err(_) => {
                        Err(FilterError(format!("cannot parse f64 value from {}", filter_value)))
                    }
                }
            }
            "as_path" => {
                match Regex::from_str(filter_value) {
                    Ok(v) => {
                        Ok(Filter::AsPath(v))
                    }
                    Err(_) => {
                        Err(FilterError(format!("cannot parse AS path regex from {}", filter_value)))
                    }
                }
            }
            _ => {
                Err(FilterError(format!("unknown filter type: {}", filter_type)))
            }
        }
    }
}

pub trait Filterable {
    fn match_filter(&self, filter: &Filter) -> bool;
    fn match_filters(&self, filters: &Vec<Filter>) -> bool;
}

impl Filterable for BgpElem {
    fn match_filter(&self, filter: &Filter) -> bool {
        match filter {
            Filter::OriginAsn(v) => {
                if let Some(origins) = &self.origin_asns {
                    origins.contains(v)
                } else {
                    false
                }
            }
            Filter::Prefix(v) => {
                self.prefix.to_string() == v.to_string()
            }
            Filter::PeerIp(v) => {
                self.peer_ip == *v
            }
            Filter::PeerAsn(v) => {
                self.peer_asn == *v
            }
            Filter::Type(v) => {
                self.elem_type == *v
            }
            Filter::TsStart(v) => {
                self.timestamp >= *v
            }
            Filter::TsEnd(v) => {
                self.timestamp <= *v
            }
            Filter::AsPath(v) => {
                if let Some(path) = &self.as_path {
                    v.is_match(path.to_string().as_str())
                } else {
                    false
                }
            }
        }
    }

    fn match_filters(&self, filters: &Vec<Filter>) -> bool {
        filters.iter().all(|f| {
            self.match_filter(f)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use crate::BgpkitParser;
    use super::*;

    #[test]
    fn test_filter() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url).unwrap();
        let elems = parser.into_elem_iter().collect::<Vec<BgpElem>>();

        let mut filters = vec![];
        filters.push(Filter::PeerIp(IpAddr::from_str("185.1.8.65").unwrap()));
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 3393);

        let mut filters = vec![];
        filters.push(Filter::PeerIp(IpAddr::from_str("185.1.8.65").unwrap()));
        filters.push(Filter::Prefix(IpNetwork::from_str("190.115.192.0/22").unwrap()));
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 5);

        let mut filters = vec![];
        let regex = Regex::new(r" ?174 1916 52888$").unwrap();
        filters.push(Filter::AsPath(regex));
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 12);

        let mut filters = vec![];
        filters.push(Filter::TsStart(1637437798 as f64));
        filters.push(Filter::TsEnd(1637437798 as f64));
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 13);

        let mut filters = vec![];
        filters.push(Filter::Type(ElemType::WITHDRAW));
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 379);

        let mut filters = vec![];
        filters.push(Filter::Type(ElemType::WITHDRAW));
        filters.push(Filter::Prefix(IpNetwork::from_str("2804:100::/32").unwrap()));
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_filter_iter() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url).unwrap()
            .add_filter("peer_ip", "185.1.8.50").unwrap()
            .add_filter("type", "w").unwrap();
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 39);
    }
}
