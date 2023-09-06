use crate::models::*;
use itertools::Itertools;
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

// TODO(jmeggitt): BgpElem can be converted to an enum. Apply this change during performance PR.

/// Element type.
///
/// - ANNOUNCE: announcement/reachable prefix
/// - WITHDRAW: withdrawn/unreachable prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub atomic: bool,
    pub aggr_asn: Option<Asn>,
    pub aggr_ip: Option<BgpIdentifier>,
    pub only_to_customer: Option<Asn>,
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
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            deprecated: None,
        }
    }
}

struct OptionToStr<'a, T>(&'a Option<T>);

impl<'a, T: Display> Display for OptionToStr<'a, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => Ok(()),
            Some(x) => write!(f, "{}", x),
        }
    }
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
            OptionToStr(&self.as_path),
            OptionToStr(&self.origin),
            OptionToStr(&self.next_hop),
            OptionToStr(&self.local_pref),
            OptionToStr(&self.med),
            option_to_string_communities(&self.communities),
            self.atomic,
            OptionToStr(&self.aggr_asn),
            OptionToStr(&self.aggr_ip),
        )
    }
}

impl BgpElem {
    /// Returns true if the element is an announcement.
    ///
    /// Most of the time, users do not really need to get the type out, only needs to know if it is
    /// an announcement or a withdrawal.
    pub fn is_announcement(&self) -> bool {
        self.elem_type == ElemType::ANNOUNCE
    }

    /// Returns the origin AS number as u32. Returns None if the origin AS number is not present or
    /// it's a AS set.
    pub fn get_origin_asn_opt(&self) -> Option<u32> {
        let origin_asns = self.origin_asns.as_ref()?;
        (origin_asns.len() == 1).then(|| origin_asns[0].into())
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
        println!("{}", serde_json::json!(elem));
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

        assert!(elem1 < elem2);
        assert!(elem2 < elem3);
    }
}
