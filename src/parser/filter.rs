/*!
## Message Filters

The filter module defines a number of available filters that users can use, and implements
the filtering mechanism for [BgpElem].

The available filters are:
- `origin_asn` -- origin AS number
- `origin_asns` -- multiple origin AS numbers (OR logic)
- `prefix` -- network prefix and match type
- `prefixes` -- multiple network prefixes (OR logic)
- `peer_ip` -- peer's IP address
- `peer_ips` -- peers' IP addresses (OR logic)
- `peer_asn` -- peer's AS number
- `peer_asns` -- multiple peer AS numbers (OR logic)
- `type` -- message type (`withdraw` or `announce`)
- `ts_start` -- start and end unix timestamp
- `as_path` -- regular expression for AS path string
- `ip_version` -- IP version (`ipv4` or `ipv6`)

### Negative Filters

Most filters support negation by prefixing the filter value with `!`. For example:
- `origin_asn=!13335` -- matches elements where origin AS is NOT 13335
- `prefix=!10.0.0.0/8` -- matches elements where prefix is NOT 10.0.0.0/8
- `peer_ip=!192.168.1.1` -- matches elements where peer IP is NOT 192.168.1.1

For multi-value filters, you can negate all values:
- `origin_asns=!13335,!15169` -- matches elements where origin AS is NOT 13335 AND NOT 15169
- Mixing positive and negative values in the same filter is not allowed

**Note**: Timestamp filters (`ts_start`, `ts_end`) do not support negation as the behavior would be unintuitive.

[Filter::new] function takes a `str` as the filter type and `str` as the filter value and returns a
Result of a [Filter] or a parsing error.

[BgpkitParser](crate::BgpkitParser) implements the function `add_filter("filter_type", "filter_value")` that takes the parser's ownership itself
and returns a new parser with specified filter added. See the example below.

### Example

```no_run
use bgpkit_parser::BgpkitParser;

/// This example shows how to parse a MRT file and filter by prefix.
env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

log::info!("downloading updates file");
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter("prefix", "211.98.251.0/24").unwrap()
    .add_filter("type", "a").unwrap();

// iterating through the parser. the iterator returns `BgpElem` one at a time.
log::info!("parsing updates file");
for elem in parser {
    log::info!("{}", &elem);
}
log::info!("done");
```

### Example with Negative Filter

```no_run
use bgpkit_parser::BgpkitParser;

// Filter out all elements from AS 13335 (Cloudflare)
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter("origin_asn", "!13335").unwrap();

for elem in parser {
    println!("{}", elem);
}
```

### Example with Multiple Filters (OR Logic)

```no_run
use bgpkit_parser::BgpkitParser;

// Filter elements from multiple origin ASNs (matches ANY of the specified ASNs)
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter("origin_asns", "13335,15169,8075").unwrap();

for elem in parser {
    println!("{}", elem);
}

// Filter elements NOT from these ASNs (matches if NOT ANY of the specified ASNs)
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter("origin_asns", "!13335,!15169,!8075").unwrap();

for elem in parser {
    println!("{}", elem);
}

// Filter elements matching multiple prefixes (matches ANY of the specified prefixes)
let parser = BgpkitParser::new("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2").unwrap()
    .add_filter("prefixes", "1.1.1.0/24,8.8.8.0/24").unwrap();

for elem in parser {
    println!("{}", elem);
}
```

Note, by default, the prefix filtering is for the exact prefix. You can include super-prefixes or
sub-prefixes when filtering by using `"prefix_super"`, `"prefix_sub"`, or  `"prefix_super_sub"` as
the filter type string. For multiple prefixes, use `"prefixes_super"`, `"prefixes_sub"`, or `"prefixes_super_sub"`.

### Note

[BgpElem] and [BgpRouteElem] implement the filtering capability. Route-level filtering only has
access to route identity, peer metadata, timestamp, and AS path, so `community` filters do not match
[BgpRouteElem] values. Support for [MrtRecord] will come in later releases.

*/
use crate::models::*;
use crate::parser::ComparableRegex;
use crate::ParserError;
use crate::ParserError::FilterError;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

/// Filter enum: definition of types of filters
///
/// The available filters are (`filter_type` (`FilterType`) -- definition):
/// - `origin_asn` (`OriginAsn(u32)`) -- origin AS number
/// - `origin_asns` (`OriginAsns(Vec<u32>)`) -- multiple origin AS numbers (OR logic)
/// - `prefix(_super, _sub, _super_sub)` (`Prefix(IpNet, PrefixMatchType)`) -- network prefix and match type
/// - `prefixes(_super, _sub, _super_sub)` (`Prefixes(Vec<IpNet>, PrefixMatchType)`) -- multiple network prefixes (OR logic)
/// - `peer_ip` (`PeerIp(IpAddr)`) -- peer's IP address
/// - `peer_ips` (`PeerIps(Vec<IpAddr>)`) -- peers' IP addresses (OR logic)
/// - `peer_asn` (`PeerAsn(u32)`) -- peer's AS number
/// - `peer_asns` (`PeerAsns(Vec<u32>)`) -- multiple peer AS numbers (OR logic)
/// - `type` (`Type(ElemType)`) -- message type (`withdraw` or `announce`)
/// - `ts_start` (`TsStart(f64)`) and `ts_end` (`TsEnd(f64)`) -- start and end unix timestamp
/// - `as_path` (`ComparableRegex`) -- regular expression for AS path string
/// - `community` (`ComparableRegex`) -- regular expression for community string
/// - `ip_version` (`IpVersion`) -- IP version (`ipv4` or `ipv6`)
///
/// **Negative filters**: Most filters support negation by prefixing the filter value with `!`.
/// For example, `origin_asn=!13335` matches elements where origin AS is NOT 13335.
/// This creates a `Negated(Box<Filter>)` variant that inverts the match result.
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    OriginAsn(u32),
    OriginAsns(Vec<u32>),
    Prefix(IpNet, PrefixMatchType),
    Prefixes(Vec<IpNet>, PrefixMatchType),
    PeerIp(IpAddr),
    PeerIps(Vec<IpAddr>),
    PeerAsn(u32),
    PeerAsns(Vec<u32>),
    Type(ElemType),
    IpVersion(IpVersion),
    TsStart(f64),
    TsEnd(f64),
    AsPath(ComparableRegex),
    Community(ComparableRegex),
    /// Negated filter - matches when the inner filter does NOT match
    Negated(Box<Filter>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixMatchType {
    Exact,
    IncludeSuper,
    IncludeSub,
    IncludeSuperSub,
}

fn parse_time_str(time_str: &str) -> Option<chrono::NaiveDateTime> {
    if let Ok(t) = time_str.parse::<f64>() {
        return chrono::DateTime::from_timestamp(t as i64, 0).map(|t| t.naive_utc());
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(time_str) {
        return Some(t.naive_utc());
    }
    None
}

fn parse_asn_list(filter_value: &str) -> Result<(Vec<u32>, bool), ParserError> {
    let mut asns = vec![];
    let mut all_negated: Option<bool> = None;

    for asn_str in filter_value.replace(' ', "").split(',') {
        // Skip empty strings (from consecutive or trailing commas)
        if asn_str.is_empty() {
            continue;
        }

        let (is_negated, actual_value) = if let Some(stripped) = asn_str.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, asn_str)
        };

        // Check for mixed positive/negative values
        match all_negated {
            None => all_negated = Some(is_negated),
            Some(prev) if prev != is_negated => {
                return Err(FilterError(
                    "cannot mix positive and negative values in the same filter".to_string(),
                ));
            }
            _ => {}
        }

        match u32::from_str(actual_value) {
            Ok(v) => asns.push(v),
            Err(_) => return Err(FilterError(format!("cannot parse ASN from {actual_value}"))),
        }
    }
    // Validate that at least one ASN was provided
    if asns.is_empty() {
        return Err(FilterError(
            "ASN list filter requires at least one ASN".to_string(),
        ));
    }
    Ok((asns, all_negated.unwrap_or(false)))
}

fn parse_prefix_list(filter_value: &str) -> Result<(Vec<IpNet>, bool), ParserError> {
    let mut prefixes = vec![];
    let mut all_negated: Option<bool> = None;

    for prefix_str in filter_value.replace(' ', "").split(',') {
        // Skip empty strings (from consecutive or trailing commas)
        if prefix_str.is_empty() {
            continue;
        }

        let (is_negated, actual_value) = if let Some(stripped) = prefix_str.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, prefix_str)
        };

        // Check for mixed positive/negative values
        match all_negated {
            None => all_negated = Some(is_negated),
            Some(prev) if prev != is_negated => {
                return Err(FilterError(
                    "cannot mix positive and negative values in the same filter".to_string(),
                ));
            }
            _ => {}
        }

        match IpNet::from_str(actual_value) {
            Ok(v) => prefixes.push(v),
            Err(_) => {
                return Err(FilterError(format!(
                    "cannot parse prefix from {actual_value}"
                )))
            }
        }
    }
    // Validate that at least one prefix was provided
    if prefixes.is_empty() {
        return Err(FilterError(
            "prefix list filter requires at least one prefix".to_string(),
        ));
    }
    Ok((prefixes, all_negated.unwrap_or(false)))
}

fn parse_ip_list(filter_value: &str) -> Result<(Vec<IpAddr>, bool), ParserError> {
    let mut ips = vec![];
    let mut all_negated: Option<bool> = None;

    for ip_str in filter_value.replace(' ', "").split(',') {
        // Skip empty strings (from consecutive or trailing commas)
        if ip_str.is_empty() {
            continue;
        }

        let (is_negated, actual_value) = if let Some(stripped) = ip_str.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, ip_str)
        };

        // Check for mixed positive/negative values
        match all_negated {
            None => all_negated = Some(is_negated),
            Some(prev) if prev != is_negated => {
                return Err(FilterError(
                    "cannot mix positive and negative values in the same filter".to_string(),
                ));
            }
            _ => {}
        }

        match IpAddr::from_str(actual_value) {
            Ok(v) => ips.push(v),
            Err(_) => {
                return Err(FilterError(format!(
                    "cannot parse IP address from {actual_value}"
                )))
            }
        }
    }
    // Validate that at least one IP was provided
    if ips.is_empty() {
        return Err(FilterError(
            "IP list filter requires at least one IP address".to_string(),
        ));
    }
    Ok((ips, all_negated.unwrap_or(false)))
}

impl Filter {
    pub fn new(filter_type: &str, filter_value: &str) -> Result<Filter, ParserError> {
        // Multi-value filters handle their own negation detection internally
        // (each value can be prefixed with !, and all must be consistent)
        let multi_value_filters = [
            "origin_asns",
            "prefixes",
            "prefixes_super",
            "prefixes_sub",
            "prefixes_super_sub",
            "peer_ips",
            "peer_asns",
        ];

        if multi_value_filters.contains(&filter_type) {
            // Pass directly to new_base - it handles negation internally
            return Self::new_base(filter_type, filter_value);
        }

        // For single-value filters, check for negation in filter_value (e.g., origin_asn=!13335)
        let (negated, actual_value) = if let Some(stripped) = filter_value.strip_prefix('!') {
            // Reject double negation (e.g., "!!13335")
            if stripped.starts_with('!') {
                return Err(FilterError(format!(
                    "invalid filter value '{}': double negation is not allowed",
                    filter_value
                )));
            }
            (true, stripped)
        } else {
            (false, filter_value)
        };

        // Reject negation for timestamp filters (unintuitive behavior)
        if negated
            && (filter_type == "ts_start"
                || filter_type == "start_ts"
                || filter_type == "ts_end"
                || filter_type == "end_ts")
        {
            return Err(FilterError(format!(
                "timestamp filter '{}' does not support negation",
                filter_type
            )));
        }

        let base_filter = Self::new_base(filter_type, actual_value)?;

        if negated {
            Ok(Filter::Negated(Box::new(base_filter)))
        } else {
            Ok(base_filter)
        }
    }

    fn new_base(filter_type: &str, filter_value: &str) -> Result<Filter, ParserError> {
        match filter_type {
            "origin_asn" => match u32::from_str(filter_value) {
                Ok(v) => Ok(Filter::OriginAsn(v)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse origin asn from {filter_value}"
                ))),
            },
            "origin_asns" => {
                let (asns, negated) = parse_asn_list(filter_value)?;
                let filter = Filter::OriginAsns(asns);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "prefix" => match IpNet::from_str(filter_value) {
                Ok(v) => Ok(Filter::Prefix(v, PrefixMatchType::Exact)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse prefix from {filter_value}"
                ))),
            },
            "prefix_super" => match IpNet::from_str(filter_value) {
                Ok(v) => Ok(Filter::Prefix(v, PrefixMatchType::IncludeSuper)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse prefix from {filter_value}"
                ))),
            },
            "prefix_sub" => match IpNet::from_str(filter_value) {
                Ok(v) => Ok(Filter::Prefix(v, PrefixMatchType::IncludeSub)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse prefix from {filter_value}"
                ))),
            },
            "prefix_super_sub" => match IpNet::from_str(filter_value) {
                Ok(v) => Ok(Filter::Prefix(v, PrefixMatchType::IncludeSuperSub)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse prefix from {filter_value}"
                ))),
            },
            "prefixes" => {
                let (prefixes, negated) = parse_prefix_list(filter_value)?;
                let filter = Filter::Prefixes(prefixes, PrefixMatchType::Exact);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "prefixes_super" => {
                let (prefixes, negated) = parse_prefix_list(filter_value)?;
                let filter = Filter::Prefixes(prefixes, PrefixMatchType::IncludeSuper);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "prefixes_sub" => {
                let (prefixes, negated) = parse_prefix_list(filter_value)?;
                let filter = Filter::Prefixes(prefixes, PrefixMatchType::IncludeSub);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "prefixes_super_sub" => {
                let (prefixes, negated) = parse_prefix_list(filter_value)?;
                let filter = Filter::Prefixes(prefixes, PrefixMatchType::IncludeSuperSub);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "peer_ip" => match IpAddr::from_str(filter_value) {
                Ok(v) => Ok(Filter::PeerIp(v)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse peer IP from {filter_value}"
                ))),
            },
            "peer_ips" => {
                let (ips, negated) = parse_ip_list(filter_value)?;
                let filter = Filter::PeerIps(ips);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "peer_asn" => match u32::from_str(filter_value) {
                Ok(v) => Ok(Filter::PeerAsn(v)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse peer asn from {filter_value}"
                ))),
            },
            "peer_asns" => {
                let (asns, negated) = parse_asn_list(filter_value)?;
                let filter = Filter::PeerAsns(asns);
                if negated {
                    Ok(Filter::Negated(Box::new(filter)))
                } else {
                    Ok(filter)
                }
            }
            "type" => match filter_value {
                "w" | "withdraw" | "withdrawal" => Ok(Filter::Type(ElemType::WITHDRAW)),
                "a" | "announce" | "announcement" => Ok(Filter::Type(ElemType::ANNOUNCE)),
                _ => Err(FilterError(format!(
                    "cannot parse elem type from {filter_value}"
                ))),
            },
            "ts_start" | "start_ts" => match parse_time_str(filter_value) {
                Some(t) => Ok(Filter::TsStart(t.and_utc().timestamp() as f64)),
                None => Err(FilterError(format!(
                    "cannot parse TsStart filter from {filter_value}"
                ))),
            },
            "ts_end" | "end_ts" => match parse_time_str(filter_value) {
                Some(t) => Ok(Filter::TsEnd(t.and_utc().timestamp() as f64)),
                None => Err(FilterError(format!(
                    "cannot parse TsEnd filter from {filter_value}"
                ))),
            },
            "as_path" => match ComparableRegex::new(filter_value) {
                Ok(v) => Ok(Filter::AsPath(v)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse AS path regex from {filter_value}"
                ))),
            },
            "community" => match ComparableRegex::new(filter_value) {
                Ok(v) => Ok(Filter::Community(v)),
                Err(_) => Err(FilterError(format!(
                    "cannot parse Community regex from {filter_value}"
                ))),
            },
            "ip_version" | "ip" => match filter_value {
                "4" | "v4" | "ipv4" => Ok(Filter::IpVersion(IpVersion::Ipv4)),
                "6" | "v6" | "ipv6" => Ok(Filter::IpVersion(IpVersion::Ipv6)),
                _ => Err(FilterError(format!(
                    "cannot parse IP version from {filter_value}"
                ))),
            },
            _ => Err(FilterError(format!("unknown filter type: {filter_type}"))),
        }
    }
}

pub trait Filterable {
    fn match_filter(&self, filter: &Filter) -> bool;
    fn match_filters(&self, filters: &[Filter]) -> bool {
        filters.iter().all(|f| self.match_filter(f))
    }
}

trait RouteFilterView {
    fn timestamp(&self) -> f64;
    fn elem_type(&self) -> ElemType;
    fn peer_ip(&self) -> IpAddr;
    fn peer_asn(&self) -> Asn;
    fn prefix(&self) -> &NetworkPrefix;
    fn as_path(&self) -> Option<&AsPath>;
    fn matches_origin_asn(&self, asn: Asn) -> bool;

    fn matches_community(&self, _regex: &ComparableRegex) -> bool {
        false
    }

    fn supports_community_filter(&self) -> bool {
        false
    }
}

const fn same_family(prefix_1: &IpNet, prefix_2: &IpNet) -> bool {
    matches!(
        (prefix_1, prefix_2),
        (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_))
    )
}

fn prefix_match(match_prefix: &IpNet, input_prefix: &IpNet, t: &PrefixMatchType) -> bool {
    let exact = input_prefix.eq(match_prefix);
    match t {
        PrefixMatchType::Exact => exact,
        PrefixMatchType::IncludeSuper => {
            if exact {
                exact
            } else if !same_family(match_prefix, input_prefix) {
                // version not match
                false
            } else {
                // input_prefix is super prefix of match_prefix
                match_prefix.addr() >= input_prefix.addr()
                    && match_prefix.broadcast() <= input_prefix.broadcast()
            }
        }
        PrefixMatchType::IncludeSub => {
            if exact {
                exact
            } else if !same_family(match_prefix, input_prefix) {
                // version not match
                false
            } else {
                // input_prefix is sub prefix of match_prefix
                match_prefix.addr() <= input_prefix.addr()
                    && match_prefix.broadcast() >= input_prefix.broadcast()
            }
        }
        PrefixMatchType::IncludeSuperSub => {
            if exact {
                exact
            } else if !same_family(match_prefix, input_prefix) {
                // version not match
                false
            } else {
                // input_prefix is super prefix of match_prefix
                (match_prefix.addr() >= input_prefix.addr()
                    && match_prefix.broadcast() <= input_prefix.broadcast())
                    || (match_prefix.addr() <= input_prefix.addr()
                        && match_prefix.broadcast() >= input_prefix.broadcast())
            }
        }
    }
}

fn match_route_view_filter<T: RouteFilterView>(view: &T, filter: &Filter) -> bool {
    match filter {
        Filter::Negated(inner)
            if matches!(inner.as_ref(), Filter::Community(_))
                && !view.supports_community_filter() =>
        {
            false
        }
        Filter::Negated(inner) => !match_route_view_filter(view, inner),
        Filter::OriginAsn(v) => view.matches_origin_asn((*v).into()),
        Filter::OriginAsns(v) => v.iter().any(|asn| view.matches_origin_asn((*asn).into())),
        Filter::Prefix(v, t) => prefix_match(v, &view.prefix().prefix, t),
        Filter::Prefixes(v, t) => v
            .iter()
            .any(|prefix| prefix_match(prefix, &view.prefix().prefix, t)),
        Filter::PeerIp(v) => view.peer_ip() == *v,
        Filter::PeerIps(v) => v.contains(&view.peer_ip()),
        Filter::PeerAsn(v) => view.peer_asn().eq(v),
        Filter::PeerAsns(v) => v.iter().any(|asn| view.peer_asn().eq(asn)),
        Filter::Type(v) => view.elem_type().eq(v),
        Filter::TsStart(v) => view.timestamp() >= *v,
        Filter::TsEnd(v) => view.timestamp() <= *v,
        Filter::AsPath(v) => view
            .as_path()
            .map(|path| v.is_match(path.to_string().as_str()))
            .unwrap_or(false),
        Filter::Community(r) => view.supports_community_filter() && view.matches_community(r),
        Filter::IpVersion(version) => match version {
            IpVersion::Ipv4 => view.prefix().prefix.addr().is_ipv4(),
            IpVersion::Ipv6 => view.prefix().prefix.addr().is_ipv6(),
        },
    }
}

impl RouteFilterView for BgpElem {
    fn timestamp(&self) -> f64 {
        self.timestamp
    }

    fn elem_type(&self) -> ElemType {
        self.elem_type
    }

    fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    fn peer_asn(&self) -> Asn {
        self.peer_asn
    }

    fn prefix(&self) -> &NetworkPrefix {
        &self.prefix
    }

    fn as_path(&self) -> Option<&AsPath> {
        self.as_path.as_ref()
    }

    fn matches_origin_asn(&self, asn: Asn) -> bool {
        self.origin_asns
            .as_ref()
            .map(|origins| origins.contains(&asn))
            .unwrap_or(false)
    }

    fn matches_community(&self, regex: &ComparableRegex) -> bool {
        self.communities
            .as_ref()
            .map(|communities| communities.iter().any(|c| regex.is_match(c.to_string())))
            .unwrap_or(false)
    }

    fn supports_community_filter(&self) -> bool {
        true
    }
}

impl RouteFilterView for BgpRouteElem {
    fn timestamp(&self) -> f64 {
        self.timestamp
    }

    fn elem_type(&self) -> ElemType {
        self.elem_type
    }

    fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    fn peer_asn(&self) -> Asn {
        self.peer_asn
    }

    fn prefix(&self) -> &NetworkPrefix {
        &self.prefix
    }

    fn as_path(&self) -> Option<&AsPath> {
        self.as_path.as_ref()
    }

    fn matches_origin_asn(&self, asn: Asn) -> bool {
        self.as_path
            .as_ref()
            .map(|path| path.iter_origins().any(|origin| origin == asn))
            .unwrap_or(false)
    }
}

impl Filterable for BgpElem {
    fn match_filter(&self, filter: &Filter) -> bool {
        match_route_view_filter(self, filter)
    }
}

impl Filterable for BgpRouteElem {
    fn match_filter(&self, filter: &Filter) -> bool {
        match_route_view_filter(self, filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BgpkitParser;
    use anyhow::Result;
    use std::str::FromStr;

    fn filter_test_elem() -> BgpElem {
        BgpElem {
            timestamp: 1637437798_f64,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: Asn::new_32bit(12345),
            peer_bgp_id: None,
            prefix: NetworkPrefix::new(IpNet::from_str("192.168.1.0/24").unwrap(), None),
            next_hop: None,
            as_path: Some(AsPath::from_sequence(vec![174, 1916, 52888])),
            origin_asns: Some(vec![Asn::new_32bit(52888)]),
            origin: None,
            local_pref: None,
            med: None,
            communities: Some(vec![MetaCommunity::Large(LargeCommunity::new(
                12345,
                [678910, 111213],
            ))]),
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            elem_type: ElemType::ANNOUNCE,
            deprecated: None,
        }
    }

    fn route_projection(elem: &BgpElem) -> BgpRouteElem {
        BgpRouteElem {
            timestamp: elem.timestamp,
            elem_type: elem.elem_type,
            peer_ip: elem.peer_ip,
            peer_asn: elem.peer_asn,
            prefix: elem.prefix,
            as_path: elem.as_path.clone(),
        }
    }

    #[test]
    fn test_route_community_filters_fail_closed() {
        let elem = filter_test_elem();
        let route = route_projection(&elem);
        let community = Filter::new("community", r"12345:.*").unwrap();
        let negated_community = Filter::new("community", r"!12345:.*").unwrap();

        assert!(elem.match_filter(&community));
        assert!(!elem.match_filter(&negated_community));
        assert!(!route.match_filter(&community));
        assert!(!route.match_filter(&negated_community));
    }

    #[test]
    fn test_filters_on_mrt_file() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url).unwrap();
        let elems = parser.into_elem_iter().collect::<Vec<BgpElem>>();

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

        let filters = vec![Filter::new("as_path", r" ?174 1916 52888$").unwrap()];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 12);

        // filter by community starting with some value
        let filters = vec![Filter::new("community", r"60924:.*").unwrap()];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 4243);

        // filter by community ending with some value
        let filters = vec![Filter::new("community", r".+:784$").unwrap()];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 107);

        // filter by community with large community (i.e. with 3 values, separated by ':')
        let filters = vec![Filter::new("community", r"\d+:\d+:\d+$").unwrap()];
        let count = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count, 4397);

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
    fn test_filter_incorrect_filters() {
        // filter by community with large community (i.e. with 3 values, separated by ':')
        let incorrect_filters = [
            Filter::new("community", r"[abc"),
            Filter::new("as_path", r"[0-9"),
            Filter::new("prefix_super_sub", "-192.-168.-1.1/24"),
        ];
        assert!(incorrect_filters
            .iter()
            .all(|f| matches!(f, Err(FilterError(_)))));
    }

    #[test]
    fn test_parsing_time_str() {
        let ts = chrono::NaiveDateTime::from_str("2021-11-20T19:49:58").unwrap();
        assert_eq!(parse_time_str("1637437798"), Some(ts));
        assert_eq!(parse_time_str("2021-11-20T19:49:58Z"), Some(ts));
        assert_eq!(parse_time_str("2021-11-20T19:49:58+00:00"), Some(ts));

        assert_eq!(parse_time_str("2021-11-20T19:49:58"), None);
        assert_eq!(parse_time_str("2021-11-20T19:49:58ZDXV"), None);
        assert_eq!(parse_time_str("2021-11-20 19:49:58"), None);
        assert_eq!(parse_time_str("2021-11-20"), None);
    }

    #[test]
    fn test_filter_iter() -> Result<()> {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url)?
            .add_filter("peer_ip", "185.1.8.50")?
            .add_filter("type", "w")?;
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 39);

        let parser = BgpkitParser::new(url)?
            .add_filter("ts_start", "1637437798")?
            .add_filter("ts_end", "2021-11-20T19:49:58Z")?;
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 13);
        Ok(())
    }

    #[test]
    fn test_filter_iter_with_negation() -> Result<()> {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";

        // Test negative filter with add_filter - exclude peer 185.1.8.65
        // From test_filters_on_mrt_file, peer 185.1.8.65 has 3393 elements out of 8160 total
        let parser = BgpkitParser::new(url)?.add_filter("peer_ip", "!185.1.8.65")?;
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 8160 - 3393);

        // Test negative type filter - get all non-withdrawals
        // From test_filters_on_mrt_file, there are 379 withdrawals out of 8160 total
        let parser = BgpkitParser::new(url)?.add_filter("type", "!w")?;
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 8160 - 379);

        // Test combining positive and negative filters
        // Get elements from peer 185.1.8.50 that are NOT withdrawals
        let parser = BgpkitParser::new(url)?
            .add_filter("peer_ip", "185.1.8.50")?
            .add_filter("type", "!w")?;
        let count = parser.into_elem_iter().count();
        // peer 185.1.8.50 has 1563 total, 39 withdrawals -> 1563 - 39 = 1524 non-withdrawals
        assert_eq!(count, 1563 - 39);

        Ok(())
    }

    #[test]
    fn test_filter_iter_multi_peers() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url)
            .unwrap()
            .add_filter("peer_ips", "185.1.8.65, 2001:7f8:73:0:3:fa4:0:1")
            .unwrap();
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

    #[test]
    fn test_filter_new() {
        let filter = Filter::new("origin_asn", "12345").unwrap();
        assert_eq!(filter, Filter::OriginAsn(12345));

        // Test negated filters (value-based negation syntax)
        let filter = Filter::new("origin_asn", "!12345").unwrap();
        assert_eq!(filter, Filter::Negated(Box::new(Filter::OriginAsn(12345))));

        let filter = Filter::new("prefix", "!192.168.1.0/24").unwrap();
        assert_eq!(
            filter,
            Filter::Negated(Box::new(Filter::Prefix(
                IpNet::from_str("192.168.1.0/24").unwrap(),
                PrefixMatchType::Exact
            )))
        );

        let filter = Filter::new("peer_ip", "!192.168.1.1").unwrap();
        assert_eq!(
            filter,
            Filter::Negated(Box::new(Filter::PeerIp(
                IpAddr::from_str("192.168.1.1").unwrap()
            )))
        );

        let filter = Filter::new("peer_asn", "!12345").unwrap();
        assert_eq!(filter, Filter::Negated(Box::new(Filter::PeerAsn(12345))));

        let filter = Filter::new("type", "!w").unwrap();
        assert_eq!(
            filter,
            Filter::Negated(Box::new(Filter::Type(ElemType::WITHDRAW)))
        );

        let filter = Filter::new("ip_version", "!4").unwrap();
        assert_eq!(
            filter,
            Filter::Negated(Box::new(Filter::IpVersion(IpVersion::Ipv4)))
        );

        let filter = Filter::new("prefix", "192.168.1.0/24").unwrap();
        assert_eq!(
            filter,
            Filter::Prefix(
                IpNet::from_str("192.168.1.0/24").unwrap(),
                PrefixMatchType::Exact
            )
        );
        let filter = Filter::new("prefix_super", "192.168.1.0/24").unwrap();
        assert_eq!(
            filter,
            Filter::Prefix(
                IpNet::from_str("192.168.1.0/24").unwrap(),
                PrefixMatchType::IncludeSuper
            )
        );
        let filter = Filter::new("prefix_sub", "192.168.1.0/24").unwrap();
        assert_eq!(
            filter,
            Filter::Prefix(
                IpNet::from_str("192.168.1.0/24").unwrap(),
                PrefixMatchType::IncludeSub
            )
        );
        let filter = Filter::new("prefix_super_sub", "192.168.1.0/24").unwrap();
        assert_eq!(
            filter,
            Filter::Prefix(
                IpNet::from_str("192.168.1.0/24").unwrap(),
                PrefixMatchType::IncludeSuperSub
            )
        );

        let filter = Filter::new("peer_ip", "192.168.1.1").unwrap();
        assert_eq!(
            filter,
            Filter::PeerIp(IpAddr::from_str("192.168.1.1").unwrap())
        );

        let filter = Filter::new("peer_asn", "12345").unwrap();
        assert_eq!(filter, Filter::PeerAsn(12345));

        let filter = Filter::new("type", "w").unwrap();
        assert_eq!(filter, Filter::Type(ElemType::WITHDRAW));

        let filter = Filter::new("ts_start", "1637437798").unwrap();
        assert_eq!(filter, Filter::TsStart(1637437798_f64));

        let filter = Filter::new("ts_end", "1637437798").unwrap();
        assert_eq!(filter, Filter::TsEnd(1637437798_f64));

        let filter = Filter::new("as_path", r" ?174 1916 52888$").unwrap();
        assert_eq!(
            filter,
            Filter::AsPath(ComparableRegex::new(r" ?174 1916 52888$").unwrap())
        );

        assert!(Filter::new("origin_asn", "not a number").is_err());
        assert!(Filter::new("peer_asn", "not a number").is_err());
        assert!(Filter::new("ts_start", "not a number").is_err());
        assert!(Filter::new("ts_end", "not a number").is_err());
        assert!(Filter::new("prefix", "not a prefix").is_err());
        assert!(Filter::new("prefix_super", "not a prefix").is_err());
        assert!(Filter::new("prefix_sub", "not a prefix").is_err());
        assert!(Filter::new("peer_ip", "not a IP").is_err());
        assert!(Filter::new("peer_ips", "not,a,IP").is_err());
        assert!(Filter::new("type", "not a type").is_err());
        assert!(Filter::new("as_path", "[abc").is_err());
        assert!(Filter::new("ip_version", "5").is_err());
        assert!(Filter::new("unknown_filter", "some_value").is_err());
    }

    #[test]
    fn test_filterable_match_filter() {
        let elem = filter_test_elem();

        let mut filters = vec![];

        let filter = Filter::new("origin_asn", "52888").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("origin_asn", "678910").unwrap();
        assert!(!elem.match_filter(&filter));

        let filter = Filter::new("prefix", "192.168.1.0/24").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("peer_ip", "192.168.1.1").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("peer_asn", "12345").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("type", "a").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("ts_start", "1637437798").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("ts_end", "1637437798").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("as_path", r" ?174 1916 52888$").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("ip_version", "4").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        let filter = Filter::new("ip", "ipv6").unwrap();
        assert!(!elem.match_filter(&filter));

        let filter = Filter::new("community", r"12345:678910:111213$").unwrap();
        filters.push(filter.clone());
        assert!(elem.match_filter(&filter));

        assert!(elem.match_filters(&filters));
    }

    #[test]
    fn test_route_filterable_matches_elem_for_route_level_filters() {
        let elem = filter_test_elem();
        let route = route_projection(&elem);

        let cases = vec![
            (
                "origin_asn matches",
                Filter::new("origin_asn", "52888").unwrap(),
                true,
            ),
            (
                "origin_asn misses",
                Filter::new("origin_asn", "64496").unwrap(),
                false,
            ),
            (
                "origin_asns matches",
                Filter::new("origin_asns", "64496,52888").unwrap(),
                true,
            ),
            (
                "origin_asns misses",
                Filter::new("origin_asns", "64496,64497").unwrap(),
                false,
            ),
            (
                "prefix exact matches",
                Filter::new("prefix", "192.168.1.0/24").unwrap(),
                true,
            ),
            (
                "prefix exact misses",
                Filter::new("prefix", "192.168.2.0/24").unwrap(),
                false,
            ),
            (
                "prefix_super matches",
                Filter::new("prefix_super", "192.168.1.128/25").unwrap(),
                true,
            ),
            (
                "prefix_sub matches",
                Filter::new("prefix_sub", "192.168.0.0/23").unwrap(),
                true,
            ),
            (
                "prefix_super_sub matches",
                Filter::new("prefix_super_sub", "192.168.1.128/25").unwrap(),
                true,
            ),
            (
                "prefixes matches",
                Filter::new("prefixes", "10.0.0.0/8,192.168.1.0/24").unwrap(),
                true,
            ),
            (
                "peer_ip matches",
                Filter::new("peer_ip", "192.168.1.1").unwrap(),
                true,
            ),
            (
                "peer_ips matches",
                Filter::new("peer_ips", "192.168.1.2,192.168.1.1").unwrap(),
                true,
            ),
            (
                "peer_asn matches",
                Filter::new("peer_asn", "12345").unwrap(),
                true,
            ),
            (
                "peer_asns matches",
                Filter::new("peer_asns", "12346,12345").unwrap(),
                true,
            ),
            ("type matches", Filter::new("type", "a").unwrap(), true),
            ("type misses", Filter::new("type", "w").unwrap(), false),
            (
                "ts_start matches",
                Filter::new("ts_start", "1637437797").unwrap(),
                true,
            ),
            (
                "ts_end matches",
                Filter::new("ts_end", "1637437799").unwrap(),
                true,
            ),
            (
                "as_path matches",
                Filter::new("as_path", r"174 1916 52888$").unwrap(),
                true,
            ),
            (
                "as_path misses",
                Filter::new("as_path", r"64496$").unwrap(),
                false,
            ),
            (
                "ip_version matches",
                Filter::new("ip_version", "4").unwrap(),
                true,
            ),
            (
                "ip_version misses",
                Filter::new("ip_version", "6").unwrap(),
                false,
            ),
            (
                "negated origin_asn matches",
                Filter::new("origin_asn", "!64496").unwrap(),
                true,
            ),
            (
                "negated origin_asn misses",
                Filter::new("origin_asn", "!52888").unwrap(),
                false,
            ),
        ];

        for (name, filter, expected) in cases {
            assert_eq!(elem.match_filter(&filter), expected, "{name} BgpElem");
            assert_eq!(route.match_filter(&filter), expected, "{name} BgpRouteElem");
            assert_eq!(
                elem.match_filter(&filter),
                route.match_filter(&filter),
                "{name} parity"
            );
        }

        let filters = vec![
            Filter::new("origin_asn", "52888").unwrap(),
            Filter::new("peer_asn", "!64496").unwrap(),
            Filter::new("prefix_super", "192.168.1.128/25").unwrap(),
        ];
        assert!(elem.match_filters(&filters));
        assert_eq!(elem.match_filters(&filters), route.match_filters(&filters));
    }

    #[test]
    fn test_route_filterable_does_not_match_community_filters() {
        let elem = filter_test_elem();
        let route = route_projection(&elem);
        let filter = Filter::new("community", r"12345:678910:111213$").unwrap();

        assert!(elem.match_filter(&filter));
        assert!(!route.match_filter(&filter));
    }

    #[test]
    fn test_negated_filters() {
        let elem = BgpElem {
            timestamp: 1637437798_f64,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: Asn::new_32bit(12345),
            peer_bgp_id: None,
            prefix: NetworkPrefix::new(IpNet::from_str("192.168.1.0/24").unwrap(), None),
            next_hop: None,
            as_path: Some(AsPath::from_sequence(vec![174, 1916, 52888])),
            origin_asns: Some(vec![Asn::new_16bit(12345)]),
            origin: None,
            local_pref: None,
            med: None,
            communities: Some(vec![MetaCommunity::Large(LargeCommunity::new(
                12345,
                [678910, 111213],
            ))]),
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            elem_type: ElemType::ANNOUNCE,
            deprecated: None,
        };

        // Test negated origin_asn filter (using value-based negation: origin_asn=!12345)
        // elem has origin_asn 12345, so origin_asn=!12345 should NOT match
        let filter = Filter::new("origin_asn", "!12345").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has origin_asn 12345, so origin_asn=!99999 should match
        let filter = Filter::new("origin_asn", "!99999").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated prefix filter
        // elem has prefix 192.168.1.0/24, so prefix=!192.168.1.0/24 should NOT match
        let filter = Filter::new("prefix", "!192.168.1.0/24").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has prefix 192.168.1.0/24, so prefix=!10.0.0.0/8 should match
        let filter = Filter::new("prefix", "!10.0.0.0/8").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated peer_ip filter
        // elem has peer_ip 192.168.1.1, so peer_ip=!192.168.1.1 should NOT match
        let filter = Filter::new("peer_ip", "!192.168.1.1").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has peer_ip 192.168.1.1, so peer_ip=!10.0.0.1 should match
        let filter = Filter::new("peer_ip", "!10.0.0.1").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated peer_asn filter
        // elem has peer_asn 12345, so peer_asn=!12345 should NOT match
        let filter = Filter::new("peer_asn", "!12345").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has peer_asn 12345, so peer_asn=!99999 should match
        let filter = Filter::new("peer_asn", "!99999").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated type filter
        // elem has type ANNOUNCE, so type=!a should NOT match
        let filter = Filter::new("type", "!a").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has type ANNOUNCE, so type=!w should match
        let filter = Filter::new("type", "!w").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated ip_version filter
        // elem has IPv4 prefix, so ip_version=!4 should NOT match
        let filter = Filter::new("ip_version", "!4").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has IPv4 prefix, so ip_version=!6 should match
        let filter = Filter::new("ip_version", "!6").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated as_path filter
        // elem has as_path "174 1916 52888", so negated matching regex should NOT match
        let filter = Filter::new("as_path", r"!174 1916 52888$").unwrap();
        assert!(!elem.match_filter(&filter));

        // elem has as_path "174 1916 52888", so negated non-matching regex should match
        let filter = Filter::new("as_path", r"!99999$").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated community filter
        let filter = Filter::new("community", r"!12345:678910:111213$").unwrap();
        assert!(!elem.match_filter(&filter));

        let filter = Filter::new("community", r"!99999:99999$").unwrap();
        assert!(elem.match_filter(&filter));

        // Test negated peer_ips filter (multi-value uses !value,!value syntax)
        let filter = Filter::new("peer_ips", "!192.168.1.1, !10.0.0.1").unwrap();
        assert!(!elem.match_filter(&filter)); // elem's peer_ip is in the list

        let filter = Filter::new("peer_ips", "!10.0.0.1, !10.0.0.2").unwrap();
        assert!(elem.match_filter(&filter)); // elem's peer_ip is NOT in the list

        // Test combining positive and negated filters
        let filters = vec![
            Filter::new("origin_asn", "12345").unwrap(),   // matches
            Filter::new("peer_asn", "!99999").unwrap(),    // matches (not 99999)
            Filter::new("prefix", "!10.0.0.0/8").unwrap(), // matches (not 10.0.0.0/8)
        ];
        assert!(elem.match_filters(&filters));

        // Test combining filters where one fails
        let filters = vec![
            Filter::new("origin_asn", "12345").unwrap(),  // matches
            Filter::new("origin_asn", "!12345").unwrap(), // does NOT match
        ];
        assert!(!elem.match_filters(&filters));
    }

    #[test]
    fn test_negated_filters_on_mrt_file() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url).unwrap();
        let elems = parser.into_elem_iter().collect::<Vec<BgpElem>>();

        // Count all elems from peer 185.1.8.65
        let filters = vec![Filter::PeerIp(IpAddr::from_str("185.1.8.65").unwrap())];
        let count_with_peer = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_with_peer, 3393);

        // Count all elems NOT from peer 185.1.8.65 (using value-based negation)
        let filters = vec![Filter::new("peer_ip", "!185.1.8.65").unwrap()];
        let count_without_peer = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_without_peer, elems.len() - 3393);

        // Verify total adds up
        assert_eq!(count_with_peer + count_without_peer, elems.len());

        // Test negated type filter
        let filters = vec![Filter::Type(ElemType::WITHDRAW)];
        let count_withdrawals = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_withdrawals, 379);

        let filters = vec![Filter::new("type", "!w").unwrap()];
        let count_not_withdrawals = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_not_withdrawals, elems.len() - 379);

        // Test negated prefix filter (using value-based negation)
        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/22").unwrap(),
            PrefixMatchType::Exact,
        )];
        let count_with_prefix = elems.iter().filter(|e| e.match_filters(&filters)).count();

        let filters = vec![Filter::new("prefix", "!190.115.192.0/22").unwrap()];
        let count_without_prefix = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_with_prefix + count_without_prefix, elems.len());

        // Test negated prefix_super filter (using value-based negation)
        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/24").unwrap(),
            PrefixMatchType::IncludeSuper,
        )];
        let count_with_super = elems.iter().filter(|e| e.match_filters(&filters)).count();

        let filters = vec![Filter::new("prefix_super", "!190.115.192.0/24").unwrap()];
        let count_without_super = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_with_super + count_without_super, elems.len());

        // Test negated prefix_sub filter (using value-based negation)
        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/22").unwrap(),
            PrefixMatchType::IncludeSub,
        )];
        let count_with_sub = elems.iter().filter(|e| e.match_filters(&filters)).count();

        let filters = vec![Filter::new("prefix_sub", "!190.115.192.0/22").unwrap()];
        let count_without_sub = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_with_sub + count_without_sub, elems.len());

        // Test negated prefix_super_sub filter (using value-based negation)
        let filters = vec![Filter::Prefix(
            IpNet::from_str("190.115.192.0/23").unwrap(),
            PrefixMatchType::IncludeSuperSub,
        )];
        let count_with_super_sub = elems.iter().filter(|e| e.match_filters(&filters)).count();

        let filters = vec![Filter::new("prefix_super_sub", "!190.115.192.0/23").unwrap()];
        let count_without_super_sub = elems.iter().filter(|e| e.match_filters(&filters)).count();
        assert_eq!(count_with_super_sub + count_without_super_sub, elems.len());
    }

    #[test]
    fn test_double_negation_rejected() {
        // Double negation should be rejected with a clear error message
        // Value-based negation: origin_asn=!!13335
        let result = Filter::new("origin_asn", "!!13335");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("double negation"));

        let result = Filter::new("prefix", "!!!10.0.0.0/8");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("double negation"));
    }

    #[test]
    fn test_timestamp_negation_rejected() {
        // Timestamp filter negation should be rejected (value-based negation)
        let result = Filter::new("ts_start", "!1637437798");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err
            .to_string()
            .contains("timestamp filter 'ts_start' does not support negation"));

        let result = Filter::new("ts_end", "!1637437798");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err
            .to_string()
            .contains("timestamp filter 'ts_end' does not support negation"));

        let result = Filter::new("start_ts", "!1637437798");
        assert!(result.is_err());

        let result = Filter::new("end_ts", "!1637437798");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_origin_asns() -> Result<()> {
        // Test parsing multiple origin ASNs
        let filter = Filter::new("origin_asns", "12345,67890,13335").unwrap();
        match filter {
            Filter::OriginAsns(asns) => {
                assert_eq!(asns.len(), 3);
                assert!(asns.contains(&12345));
                assert!(asns.contains(&67890));
                assert!(asns.contains(&13335));
            }
            _ => panic!("Expected OriginAsns filter"),
        }

        // Test with spaces in the list
        let filter = Filter::new("origin_asns", "12345, 67890, 13335").unwrap();
        match filter {
            Filter::OriginAsns(asns) => {
                assert_eq!(asns.len(), 3);
            }
            _ => panic!("Expected OriginAsns filter"),
        }

        Ok(())
    }

    #[test]
    fn test_multiple_prefixes() -> Result<()> {
        // Test parsing multiple prefixes
        let prefix1 = IpNet::from_str("190.115.192.0/22").unwrap();
        let prefix2 = IpNet::from_str("2804:100::/32").unwrap();

        let filter = Filter::new("prefixes", "190.115.192.0/22,2804:100::/32").unwrap();
        match filter {
            Filter::Prefixes(prefixes, match_type) => {
                assert_eq!(prefixes.len(), 2);
                assert!(prefixes.contains(&prefix1));
                assert!(prefixes.contains(&prefix2));
                assert_eq!(match_type, PrefixMatchType::Exact);
            }
            _ => panic!("Expected Prefixes filter"),
        }

        // Test with spaces
        let filter = Filter::new("prefixes", "190.115.192.0/22, 2804:100::/32").unwrap();
        match filter {
            Filter::Prefixes(prefixes, _) => {
                assert_eq!(prefixes.len(), 2);
            }
            _ => panic!("Expected Prefixes filter"),
        }

        Ok(())
    }

    #[test]
    fn test_multiple_prefixes_with_match_types() -> Result<()> {
        // Test prefixes_super
        let filter = Filter::new("prefixes_super", "190.115.192.0/24,2804:100::/32").unwrap();
        match filter {
            Filter::Prefixes(prefixes, match_type) => {
                assert_eq!(prefixes.len(), 2);
                assert_eq!(match_type, PrefixMatchType::IncludeSuper);
            }
            _ => panic!("Expected Prefixes filter with IncludeSuper"),
        }

        // Test prefixes_sub
        let filter = Filter::new("prefixes_sub", "190.115.192.0/22,2804:100::/32").unwrap();
        match filter {
            Filter::Prefixes(prefixes, match_type) => {
                assert_eq!(prefixes.len(), 2);
                assert_eq!(match_type, PrefixMatchType::IncludeSub);
            }
            _ => panic!("Expected Prefixes filter with IncludeSub"),
        }

        // Test prefixes_super_sub
        let filter = Filter::new("prefixes_super_sub", "190.115.192.0/23,2804:100::/32").unwrap();
        match filter {
            Filter::Prefixes(prefixes, match_type) => {
                assert_eq!(prefixes.len(), 2);
                assert_eq!(match_type, PrefixMatchType::IncludeSuperSub);
            }
            _ => panic!("Expected Prefixes filter with IncludeSuperSub"),
        }

        Ok(())
    }

    #[test]
    fn test_multiple_peer_asns() -> Result<()> {
        // Test parsing multiple peer ASNs
        let filter = Filter::new("peer_asns", "12345,67890,13335").unwrap();
        match filter {
            Filter::PeerAsns(asns) => {
                assert_eq!(asns.len(), 3);
                assert!(asns.contains(&12345));
                assert!(asns.contains(&67890));
                assert!(asns.contains(&13335));
            }
            _ => panic!("Expected PeerAsns filter"),
        }

        Ok(())
    }

    #[test]
    fn test_negated_multiple_filters() -> Result<()> {
        // Test negated origin_asns (using value-based negation: !value,!value)
        let filter = Filter::new("origin_asns", "!13335,!15169").unwrap();
        assert!(matches!(filter, Filter::Negated(_)));

        // Test negated prefixes
        let filter = Filter::new("prefixes", "!1.1.1.0/24,!8.8.8.0/24").unwrap();
        assert!(matches!(filter, Filter::Negated(_)));

        // Test negated peer_asns
        let filter = Filter::new("peer_asns", "!12345,!67890").unwrap();
        assert!(matches!(filter, Filter::Negated(_)));

        Ok(())
    }

    #[test]
    fn test_invalid_multiple_filters() {
        // Test invalid origin ASN in list
        let result = Filter::new("origin_asns", "12345,not_a_number,67890");
        assert!(result.is_err());

        // Test invalid prefix in list
        let result = Filter::new("prefixes", "1.1.1.0/24,invalid_prefix");
        assert!(result.is_err());

        // Test invalid peer ASN in list
        let result = Filter::new("peer_asns", "12345,invalid,67890");
        assert!(result.is_err());

        // Test invalid peer IP in list
        let result = Filter::new("peer_ips", "192.168.1.1,invalid_ip");
        assert!(result.is_err());

        // Test mixed positive/negative values (not allowed)
        let result = Filter::new("origin_asns", "12345,!67890");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot mix positive and negative values"));

        let result = Filter::new("prefixes", "1.1.1.0/24,!8.8.8.0/24");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot mix positive and negative values"));

        let result = Filter::new("peer_ips", "192.168.1.1,!10.0.0.1");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot mix positive and negative values"));

        let result = Filter::new("peer_asns", "!12345,67890");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot mix positive and negative values"));

        // Test empty ASN list
        let result = Filter::new("origin_asns", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one ASN"));

        // Test empty prefix list
        let result = Filter::new("prefixes", "");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one prefix"));

        // Test empty IP list
        let result = Filter::new("peer_ips", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one IP"));

        // Test only commas in ASN list (should error after filtering empty strings)
        let result = Filter::new("origin_asns", ",,,");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one ASN"));

        // Test only commas in prefix list
        let result = Filter::new("prefixes", ",,,");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one prefix"));

        // Test only commas in IP list
        let result = Filter::new("peer_ips", ",,,");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one IP"));

        // Test trailing commas (should still work by skipping empty strings)
        let result = Filter::new("origin_asns", "12345,67890,");
        assert!(result.is_ok());

        // Test consecutive commas (should still work by skipping empty strings)
        let result = Filter::new("origin_asns", "12345,,67890");
        assert!(result.is_ok());

        // Test trailing commas for peer IPs
        let result = Filter::new("peer_ips", "192.168.1.1,192.168.1.2,");
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_filters_or_logic_behavior() {
        // Create a test element
        let elem = BgpElem {
            timestamp: 1637437798_f64,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: Asn::new_32bit(12345),
            peer_bgp_id: None,
            prefix: NetworkPrefix::new(IpNet::from_str("192.168.1.0/24").unwrap(), None),
            next_hop: None,
            as_path: Some(AsPath::from_sequence(vec![174, 1916, 52888])),
            origin_asns: Some(vec![Asn::new_16bit(12345)]),
            origin: None,
            local_pref: None,
            med: None,
            communities: None,
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            elem_type: ElemType::ANNOUNCE,
            deprecated: None,
        };

        // Test OriginAsns with OR logic - element has origin ASN 12345
        let filter = Filter::new("origin_asns", "12345,67890,99999").unwrap();
        assert!(elem.match_filter(&filter)); // Should match because 12345 is in the list

        let filter = Filter::new("origin_asns", "67890,99999").unwrap();
        assert!(!elem.match_filter(&filter)); // Should NOT match because 12345 is not in the list

        // Test Prefixes with OR logic - element has prefix 192.168.1.0/24
        let filter = Filter::new("prefixes", "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12").unwrap();
        assert!(elem.match_filter(&filter)); // Should match

        let filter = Filter::new("prefixes", "10.0.0.0/8,172.16.0.0/12").unwrap();
        assert!(!elem.match_filter(&filter)); // Should NOT match

        // Test PeerAsns with OR logic - element has peer ASN 12345
        let filter = Filter::new("peer_asns", "12345,67890").unwrap();
        assert!(elem.match_filter(&filter)); // Should match

        let filter = Filter::new("peer_asns", "67890,99999").unwrap();
        assert!(!elem.match_filter(&filter)); // Should NOT match

        // Test negated multiple filters (using value-based negation: !value,!value)
        let filter = Filter::new("origin_asns", "!67890,!99999").unwrap();
        assert!(elem.match_filter(&filter)); // Should match because origin ASN is NOT in the list

        let filter = Filter::new("origin_asns", "!12345,!67890").unwrap();
        assert!(!elem.match_filter(&filter)); // Should NOT match because origin ASN IS in the list
    }
}
