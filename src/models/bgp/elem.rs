use crate::models::*;
use itertools::Itertools;
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

/// Element type.
///
/// - ANNOUNCE: announcement/reachable prefix
/// - WITHDRAW: withdrawn/unreachable prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename = "lowercase"))]
pub enum ElemType {
    ANNOUNCE,
    WITHDRAW,
}

impl ElemType {
    pub fn is_announce(&self) -> bool {
        match self {
            ElemType::ANNOUNCE => true,
            ElemType::WITHDRAW => false,
        }
    }
}

/// BgpElem represents per-prefix BGP element.
///
/// The information is for per announced/withdrawn prefix.
///
/// Note: it consumes more memory to construct BGP elements due to duplicate information
/// shared between multiple elements of one MRT record.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BgpElem {
    pub timestamp: f64,
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
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
    pub only_to_customer: Option<u32>,
    /// unknown attributes formatted as (TYPE, RAW_BYTES)
    pub unknown: Option<Vec<AttrRaw>>,
    /// deprecated attributes formatted as (TYPE, RAW_BYTES)
    pub deprecated: Option<Vec<AttrRaw>>,
}

impl Eq for BgpElem {}

impl PartialOrd<Self> for BgpElem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BgpElem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .partial_cmp(&other.timestamp)
            .unwrap()
            .then_with(|| self.peer_ip.cmp(&other.peer_ip))
    }
}

/// Reference version of the [BgpElem] struct.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            deprecated: None,
        }
    }
}

macro_rules! option_to_string {
    ($a:expr) => {
        if let Some(v) = $a {
            v.to_string()
        } else {
            String::new()
        }
    };
}

#[inline(always)]
pub fn option_to_string_communities(o: &Option<Vec<MetaCommunity>>) -> String {
    if let Some(v) = o {
        v.iter().join(" ")
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
        write!(
            f,
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            t,
            &self.timestamp,
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
        )
    }
}

impl BgpElem {
    /// Returns true if the element is an announcement.
    ///
    /// Most of the time, users do not really need to get the type out, only needs to know if it is an announcement or a withdrawal.
    pub fn is_announcement(&self) -> bool {
        self.elem_type == ElemType::ANNOUNCE
    }

    /// Returns the AS path as a vector of ASNs in u32 format. Returns None if the AS path is not present or it contains AS set or confederated segments.
    pub fn get_as_path_opt(&self) -> Option<Vec<u32>> {
        match &self.as_path {
            Some(as_path) => as_path.to_u32_vec(),
            None => None,
        }
    }

    /// Returns the origin AS number as u32. Returns None if the origin AS number is not present or it's a AS set.
    pub fn get_origin_asn_opt(&self) -> Option<u32> {
        match &self.origin_asns {
            Some(origin_asns) => {
                if origin_asns.len() == 1 {
                    Some(origin_asns[0].asn)
                } else {
                    None
                }
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::default::Default;
    use std::str::FromStr;

    #[test]
    #[cfg(feature = "serde")]
    fn test_default() {
        let elem = BgpElem {
            timestamp: 0.0,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };
        println!("{}", serde_json::json!(elem).to_string());
    }

    #[test]
    fn test_sorting() {
        let elem1 = BgpElem {
            timestamp: 1.1,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };
        let elem2 = BgpElem {
            timestamp: 1.2,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };
        let elem3 = BgpElem {
            timestamp: 1.2,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("192.168.1.2").unwrap(),
            peer_asn: 0.into(),
            prefix: NetworkPrefix::from_str("8.8.8.0/24").unwrap(),
            ..Default::default()
        };

        assert_eq!(elem1 < elem2, true);
        assert_eq!(elem2 < elem3, true);
    }
}
