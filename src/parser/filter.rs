/*!
## Message Filters

The filters package defines a number of available filters that users can utilize, and implements
the filtering mechanism for [BgpElem].

The available filters are:
- `origin_asn` -- origin AS number
- `prefix` -- network prefix and match type
- `peer_ip` -- peer's IP address
- `peer_ips` -- peers' IP addresses
- `peer_asn` -- peer's IP address
- `type` -- message type (`withdraw` or `announce`)
- `ts_start` -- start and end unix timestamp
- `as_path` -- regular expression for AS path string

[Filter::new] function takes a `str` for filter type and `str` for filter value and returns a Result
of a [Filter] or a parsing error.

[BgpkitParser](crate::BgpkitParser) implements the function `add_filter("filter_type", "filter_value")` that takes the parser's ownership itself
and returns a new parser with specified filter added. See the example below.

### Example

```no_run
use bgpkit_parser::BgpkitParser;
use bgpkit_parser::filter::Filter;
use bgpkit_parser::models::ElemType::ANNOUNCE;

/// This example shows how to parse a MRT file and filter by prefix.
env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

log::info!("downloading updates file");
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter(Filter::prefix("211.98.251.0/24").unwrap())
    .add_filter(Filter::Type(ANNOUNCE));

// iterating through the parser. the iterator returns `BgpElem` one at a time.
log::info!("parsing updates file");
for elem in parser {
    log::info!("{}", elem.unwrap());
}
log::info!("done");
```

Note, by default, the prefix filtering is for the exact prefix. You can include super-prefixes or
sub-prefixes when fitlering by using `"prefix_super"`, `"prefix_sub"`, or  `"prefix_super_sub"` as
the filter type string.

### Note

Currently, only [BgpElem] implements the filtering capability. Support for [MrtRecord] will come in
later releases.

*/
use crate::models::*;
use chrono::DateTime;
use ipnet::IpNet;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

/// Filter enum: definition o types of filters
///
/// The available filters are (`filter_type` (`FilterType`) -- definition):
/// - `origin_asn` (`OriginAsn(u32)`) -- origin AS number
/// - `prefix(_super, _sub, _super_sub)` (`Prefix(IpNet, PrefixMatchType)`) -- network prefix and match type
/// - `peer_ip` (`PeerIp(IpAddr)`) -- peer's IP address
/// - `peer_ips` (`Vec<PeerIp(IpAddr)>`) -- peers' IP addresses
/// - `peer_asn` (`PeerAsn(u32)`) -- peer's IP address
/// - `type` (`Type(ElemType)`) -- message type (`withdraw` or `announce`)
/// - `ts_start` (`TsStart(f64)`) and `ts_end` (`TsEnd(f64)`) -- start and end unix timestamp
/// - `as_path` (`AsPath(Regex)`) -- regular expression for AS path string
pub enum Filter {
    OriginAsn(u32),
    Prefix(IpNet, PrefixMatchType),
    PeerIp(IpAddr),
    PeerIps(Vec<IpAddr>),
    PeerAsn(u32),
    Type(ElemType),
    TsStart(f64),
    TsEnd(f64),
    AsPath(Regex),
}

pub enum PrefixMatchType {
    Exact,
    IncludeSuper,
    IncludeSub,
    IncludeSuperSub,
}

fn parse_time_str(time_str: &str) -> chrono::ParseResult<f64> {
    if let Ok(unix_timestamp) = time_str.parse::<f64>() {
        return Ok(unix_timestamp);
    }

    DateTime::parse_from_rfc3339(time_str).map(|x| x.naive_utc().timestamp() as f64)
}

/// Constructors provided for some backwards compatability with the removed `Filter::new`.
impl Filter {
    pub fn ts_start(time_str: &str) -> chrono::ParseResult<Self> {
        parse_time_str(time_str).map(Filter::TsStart)
    }

    pub fn ts_end(time_str: &str) -> chrono::ParseResult<Self> {
        parse_time_str(time_str).map(Filter::TsEnd)
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn as_path(regex: &str) -> Result<Self, regex::Error> {
        Regex::new(regex).map(Filter::AsPath)
    }

    pub fn prefix(prefix: &str) -> Result<Self, ipnet::AddrParseError> {
        IpNet::from_str(prefix).map(|prefix| Filter::Prefix(prefix, PrefixMatchType::Exact))
    }
}

pub trait Filterable {
    fn match_filter(&self, filter: &Filter) -> bool;
    fn match_filters(&self, filters: &[Filter]) -> bool;
}

fn prefix_match(match_prefix: &IpNet, input_prefix: &IpNet, t: &PrefixMatchType) -> bool {
    if input_prefix == match_prefix {
        return true;
    }

    match t {
        PrefixMatchType::Exact => false,
        PrefixMatchType::IncludeSuper => input_prefix.contains(match_prefix),
        PrefixMatchType::IncludeSub => match_prefix.contains(input_prefix),
        PrefixMatchType::IncludeSuperSub => {
            input_prefix.contains(match_prefix) || match_prefix.contains(input_prefix)
        }
    }
}

impl Filterable for BgpElem {
    fn match_filter(&self, filter: &Filter) -> bool {
        match filter {
            Filter::OriginAsn(v) => {
                let asn: Asn = (*v).into();
                if let Some(origins) = &self.origin_asns {
                    origins.contains(&asn)
                } else {
                    false
                }
            }
            Filter::Prefix(v, t) => prefix_match(v, &self.prefix.prefix, t),
            Filter::PeerIp(v) => self.peer_ip == *v,
            Filter::PeerIps(v) => v.contains(&self.peer_ip),
            Filter::PeerAsn(v) => self.peer_asn.eq(v),
            Filter::Type(v) => self.elem_type.eq(v),
            Filter::TsStart(v) => self.timestamp >= *v,
            Filter::TsEnd(v) => self.timestamp <= *v,
            Filter::AsPath(v) => {
                if let Some(path) = &self.as_path {
                    v.is_match(path.to_string().as_str())
                } else {
                    false
                }
            }
        }
    }

    fn match_filters(&self, filters: &[Filter]) -> bool {
        filters.iter().all(|f| self.match_filter(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BgpkitParser;
    use anyhow::Result;
    use chrono::NaiveDateTime;
    use itertools::Itertools;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_filter() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url).unwrap();
        let elems: Vec<BgpElem> = parser.into_elem_iter().try_collect().unwrap();

        let filters = vec![Filter::PeerIp(IpAddr::from_str("185.1.8.65").unwrap())];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 3393);

        let filters = vec![
            Filter::PeerIp(IpAddr::from_str("185.1.8.65").unwrap()),
            Filter::Prefix(
                IpNet::from_str("190.115.192.0/22").unwrap(),
                PrefixMatchType::Exact,
            ),
        ];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 5);

        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/24").unwrap(),
            PrefixMatchType::IncludeSuper,
        )];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 18);

        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/22").unwrap(),
            PrefixMatchType::IncludeSub,
        )];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 42);

        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/23").unwrap(),
            PrefixMatchType::IncludeSuperSub,
        )];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 24);

        let filters = vec![Filter::AsPath(Regex::new(r" ?174 1916 52888$").unwrap())];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 12);

        let filters = vec![
            Filter::TsStart(1637437798_f64),
            Filter::TsEnd(1637437798_f64),
        ];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 13);

        let filters = vec![Filter::Type(ElemType::WITHDRAW)];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 379);

        let filters = vec![
            Filter::Type(ElemType::WITHDRAW),
            Filter::Prefix(
                IpNet::from_str("2804:100::/32").unwrap(),
                PrefixMatchType::Exact,
            ),
        ];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 1);

        // test filtering by multiple peers
        /*
        1167 185.1.8.3
        1563 185.1.8.50
        3393 185.1.8.65
          51 185.1.8.89
         834 2001:7f8:73:0:3:fa4:0:1
          94 2001:7f8:73::c2a8:0:1
        1058 2001:7f8:73::edfc:0:2
         */
        let filters = vec![Filter::PeerIps(vec![
            IpAddr::from_str("185.1.8.65").unwrap(),
            IpAddr::from_str("2001:7f8:73:0:3:fa4:0:1").unwrap(),
        ])];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 3393 + 834);
    }

    #[test]
    fn test_parsing_time_str() {
        let ts = NaiveDateTime::from_str("2021-11-20T19:49:58")
            .unwrap()
            .timestamp() as f64;
        assert_eq!(parse_time_str("1637437798").ok(), Some(ts));
        assert_eq!(parse_time_str("2021-11-20T19:49:58Z").ok(), Some(ts));
        assert_eq!(parse_time_str("2021-11-20T19:49:58+00:00").ok(), Some(ts));

        assert_eq!(parse_time_str("2021-11-20T19:49:58").ok(), None);
        assert_eq!(parse_time_str("2021-11-20T19:49:58ZDXV").ok(), None);
        assert_eq!(parse_time_str("2021-11-20 19:49:58").ok(), None);
        assert_eq!(parse_time_str("2021-11-20").ok(), None);
    }

    #[test]
    fn test_filter_iter() -> Result<()> {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url)?
            .add_filter(Filter::PeerIp(Ipv4Addr::new(185, 1, 8, 50).into()))
            .add_filter(Filter::Type(ElemType::WITHDRAW));
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 39);

        let parser = BgpkitParser::new(url)?
            .add_filter(Filter::ts_start("1637437798")?)
            .add_filter(Filter::ts_end("2021-11-20T19:49:58Z")?);
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 13);
        Ok(())
    }

    #[test]
    fn test_filter_iter_multi_peers() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url)
            .unwrap()
            .add_filter(Filter::PeerIps(vec![
                Ipv4Addr::new(185, 1, 8, 65).into(),
                Ipv6Addr::from([0x2001, 0x7f8, 0x73, 0x0, 0x3, 0xfa4, 0x0, 0x1]).into(),
            ]));
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 3393 + 834);
    }

    #[test]
    fn test_prefix_match() {
        // network
        let p1 = IpNet::from_str("10.1.1.0/24").unwrap();
        let p1_exact = IpNet::from_str("10.1.1.0/24").unwrap();
        let p1_super = IpNet::from_str("10.1.0.0/16").unwrap();
        let p1_sub = IpNet::from_str("10.1.1.0/25").unwrap();

        let p2 = IpNet::from_str("2001:0DB8:0000:000b::/64").unwrap();

        // exact
        assert!(prefix_match(&p1, &p1_exact, &PrefixMatchType::Exact));
        assert!(!prefix_match(&p1, &p1_sub, &PrefixMatchType::Exact));
        assert!(!prefix_match(&p1, &p1_super, &PrefixMatchType::Exact));
        assert!(!prefix_match(&p1, &p2, &PrefixMatchType::Exact));

        // include super
        assert!(prefix_match(&p1, &p1_exact, &PrefixMatchType::IncludeSuper));
        assert!(!prefix_match(&p1, &p1_sub, &PrefixMatchType::IncludeSuper));
        assert!(prefix_match(&p1, &p1_super, &PrefixMatchType::IncludeSuper));
        assert!(!prefix_match(&p1, &p2, &PrefixMatchType::IncludeSuper));

        // include sub
        assert!(prefix_match(&p1, &p1_exact, &PrefixMatchType::IncludeSub));
        assert!(prefix_match(&p1, &p1_sub, &PrefixMatchType::IncludeSub));
        assert!(!prefix_match(&p1, &p1_super, &PrefixMatchType::IncludeSub));
        assert!(!prefix_match(&p1, &p2, &PrefixMatchType::IncludeSub));

        // include both
        assert!(prefix_match(
            &p1,
            &p1_exact,
            &PrefixMatchType::IncludeSuperSub
        ));
        assert!(prefix_match(
            &p1,
            &p1_sub,
            &PrefixMatchType::IncludeSuperSub
        ));
        assert!(prefix_match(
            &p1,
            &p1_super,
            &PrefixMatchType::IncludeSuperSub
        ));
        assert!(!prefix_match(&p1, &p2, &PrefixMatchType::IncludeSuperSub));
    }
}
