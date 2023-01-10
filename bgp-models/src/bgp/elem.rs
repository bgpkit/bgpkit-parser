use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use itertools::Itertools;
use crate::bgp::attributes::{AsPath, AtomicAggregate, Origin};
use crate::bgp::community::*;
use crate::network::{Asn, NetworkPrefix};
use serde::{Serialize, Serializer};

/// Element type.
///
/// - ANNOUNCE: announcement/reachable prefix
/// - WITHDRAW: withdrawn/unreachable prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElemType {
    ANNOUNCE,
    WITHDRAW,
}

impl Serialize for ElemType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        Ok(serializer.serialize_str(match self {
            ElemType::ANNOUNCE => {"announce"}
            ElemType::WITHDRAW => {"withdraw"}
        })?)
    }
}

/// BgpElem represents per-prefix BGP element.
///
/// The information is for per announced/withdrawn prefix.
///
/// Note: it consumes more memory to construct BGP elements due to duplicate information
/// shared between multiple elements of one MRT record.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BgpElem {
    pub timestamp: f64,
    #[serde(rename="type")]
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
    pub communities: Option<Vec<MetaCommunity>>,
    pub atomic: Option<AtomicAggregate>,
    pub aggr_asn: Option<Asn>,
    pub aggr_ip: Option<IpAddr>,
}

impl Eq for BgpElem {}

impl PartialOrd<Self> for BgpElem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BgpElem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.partial_cmp(&other.timestamp).unwrap().then_with(||self.peer_ip.cmp(&other.peer_ip))
    }
}

/// Reference version of the [BgpElem] struct.
#[derive(Debug, Clone, Serialize)]
pub struct BgpElemRef<'a> {
    pub timestamp: &'a f64,
    pub elem_type: &'a ElemType,
    pub peer_ip: &'a IpAddr,
    pub peer_asn: &'a Asn,
    pub prefix: &'a NetworkPrefix,
    pub next_hop: &'a Option<IpAddr>,
    pub as_path: &'a Option<AsPath>,
    pub origin_asns: &'a Option<Vec<Asn>>,
    pub origin: &'a Option<Origin>,
    pub local_pref: &'a Option<u32>,
    pub med: &'a Option<u32>,
    pub communities: &'a Option<Vec<MetaCommunity>>,
    pub atomic: &'a Option<AtomicAggregate>,
    pub aggr_asn: &'a Option<Asn>,
    pub aggr_ip: &'a Option<IpAddr>,
}

impl Default for BgpElem {
    fn default() -> Self {
        BgpElem {
            timestamp: 0.0,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("0.0.0.0").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("0.0.0.0/0").unwrap(),
            next_hop: None,
            as_path: None,
            origin_asns: None,
            origin: None,
            local_pref: None,
            med: None,
            communities: None,
            atomic: None,
            aggr_asn: None,
            aggr_ip: None
        }
    }
}

macro_rules! option_to_string{
    ($a:expr) => {
        if let Some(v) = $a {
            v.to_string()
        } else {
            String::new()
        }
    }
}

#[inline(always)]
pub fn option_to_string_communities(o: &Option<Vec<MetaCommunity>>) -> String {
    if let Some(v) = o {
        v.iter()
            .join(" ")
    } else {
        String::new()
    }
}

impl Display for BgpElem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let t = match self.elem_type {
            ElemType::ANNOUNCE => "A",
            ElemType::WITHDRAW => "W",
        };
        let format = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            t, &self.timestamp,
            &self.peer_ip,
            &self.peer_asn,
            &self.prefix,
            option_to_string!(&self.as_path),
            option_to_string!(&self.origin),
            option_to_string!(&self.next_hop),
            option_to_string!(&self.local_pref),
            option_to_string!(&self.med),
            option_to_string_communities(&self.communities),
            option_to_string!(&self.atomic),
            option_to_string!(&self.aggr_asn),
            option_to_string!(&self.aggr_ip),
        );
        write!(f, "{}", format)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::default::Default;
    use super::*;

    #[test]
    fn test_default() {
        let elem = BgpElem{
            timestamp: 0.0,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };
        println!("{}",serde_json::json!(elem).to_string());
    }

    #[test]
    fn test_sorting() {
        let elem1 = BgpElem{
            timestamp: 1.1,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };
        let elem2 = BgpElem{
            timestamp: 1.2,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };
        let elem3 = BgpElem{
            timestamp: 1.2,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.2").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };

        assert_eq!(elem1<elem2, true);
        assert_eq!(elem2<elem3, true);
    }
}