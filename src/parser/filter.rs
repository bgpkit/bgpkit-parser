use std::net::IpAddr;
use std::str::FromStr;
use bgp_models::prelude::*;
use ipnetwork::IpNetwork;
use regex::Regex;
use crate::ParserErrorKind;
use crate::ParserErrorKind::FilterError;

pub enum Filter {
    OriginAsn(Asn),
    Prefix(IpNetwork),
    PeerIp(IpAddr),
    PeerAsn(Asn),
    Type(ElemType),
    TsStart(f64),
    TsEnd(f64),
    Path(Regex),
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
            "ts_start" => {
                match f64::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::TsStart(v))},
                    Err(_) => {
                        Err(FilterError(format!("cannot parse f64 value from {}", filter_value)))
                    }
                }
            }
            "ts_end" => {
                match f64::from_str(filter_value) {
                    Ok(v) => {Ok(Filter::TsEnd(v))},
                    Err(_) => {
                        Err(FilterError(format!("cannot parse f64 value from {}", filter_value)))
                    }
                }
            }
            "path" => {
                match Regex::from_str(filter_value) {
                    Ok(v) => {
                        Ok(Filter::Path(v))
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
            Filter::Path(v) => {
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
        let url = "https://bgpkit-data.sfo3.digitaloceanspaces.com/parser/update-example";
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
        filters.push(Filter::Path(regex));
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
        let url = "https://bgpkit-data.sfo3.digitaloceanspaces.com/parser/update-example";
        let parser = BgpkitParser::new(url).unwrap().add_filter("type", "w").unwrap();
        let count = parser.into_elem_iter().count();
        assert_eq!(count, 379);
    }
}
