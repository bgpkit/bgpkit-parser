//! BGP attribute structs
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use itertools::Itertools;
use crate::network::*;
use serde::{Serialize, Serializer};
use crate::bgp::{ExtendedCommunity, LargeCommunity, Community};

/// The high-order bit (bit 0) of the Attribute Flags octet is the
/// Optional bit.  It defines whether the attribute is optional (if
/// set to 1) or well-known (if set to 0).
///
/// The second high-order bit (bit 1) of the Attribute Flags octet
/// is the Transitive bit.  It defines whether an optional
/// attribute is transitive (if set to 1) or non-transitive (if set
/// to 0).
///
/// For well-known attributes, the Transitive bit MUST be set to 1.
/// (See Section 5 for a discussion of transitive attributes.)
///
/// The third high-order bit (bit 2) of the Attribute Flags octet
/// is the Partial bit.  It defines whether the information
/// contained in the optional transitive attribute is partial (if
/// set to 1) or complete (if set to 0).  For well-known attributes
/// and for optional non-transitive attributes, the Partial bit
/// MUST be set to 0.
///
/// The fourth high-order bit (bit 3) of the Attribute Flags octet
/// is the Extended Length bit.  It defines whether the Attribute
/// Length is one octet (if set to 0) or two octets (if set to 1).
pub enum AttributeFlagsBit {
    /// 128 = 0b10000000
    OptionalBit = 0b10000000,
    /// 64 = 0b01000000
    TransitiveBit = 0b01000000,
    /// 32 = 0b00100000
    PartialBit = 0b00100000,
    /// 16 = 0b00010000
    ExtendedLengthBit = 0b00010000,
}

/// Attribute types.
///
/// All attributes currently defined and not Unassigned or Deprecated are included here.
/// To see the full list, check out IANA at:
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2>
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum AttrType {
    RESERVED = 0,
    ORIGIN = 1,
    AS_PATH = 2,
    NEXT_HOP = 3,
    MULTI_EXIT_DISCRIMINATOR = 4,
    LOCAL_PREFERENCE = 5,
    ATOMIC_AGGREGATE = 6,
    AGGREGATOR = 7,
    COMMUNITIES = 8,
    /// <https://tools.ietf.org/html/rfc4456>
    ORIGINATOR_ID = 9,
    CLUSTER_LIST = 10,
    /// <https://tools.ietf.org/html/rfc4760>
    CLUSTER_ID = 13,
    MP_REACHABLE_NLRI = 14,
    MP_UNREACHABLE_NLRI = 15,
    /// <https://datatracker.ietf.org/doc/html/rfc4360>
    EXTENDED_COMMUNITIES = 16,
    AS4_PATH = 17,
    AS4_AGGREGATOR = 18,
    PMSI_TUNNEL = 22,
    TUNNEL_ENCAPSULATION = 23,
    TRAFFIC_ENGINEERING = 24,
    IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES = 25,
    AIGP = 26,
    PE_DISTINGUISHER_LABELS = 27,
    BGP_LS_ATTRIBUTE = 29,
    LARGE_COMMUNITIES = 32,
    BGPSEC_PATH = 33,
    SFP_ATTRIBUTE = 37,
    BFD_DISCRIMINATOR = 38,
    BGP_PREFIX_SID = 40,
    ATTR_SET = 128,
    /// <https://datatracker.ietf.org/doc/html/rfc2042>
    DEVELOPMENT = 255,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
pub enum AtomicAggregate {
    NAG = 0,
    AG = 1,
}

/// BGP Attribute struct with attribute value and flag
#[derive(Debug, PartialEq, Clone, Serialize, Eq)]
pub struct Attribute {
    pub attr_type: AttrType,
    pub value: AttributeValue,
    pub flag: u8,
}

/// The `AttributeValue` enum represents different kinds of Attribute values.
#[derive(Debug, PartialEq, Clone, Serialize, Eq)]
pub enum AttributeValue {
    Origin(Origin),
    AsPath(AsPath),
    As4Path(AsPath),
    NextHop(IpAddr),
    MultiExitDiscriminator(u32),
    LocalPreference(u32),
    AtomicAggregate(AtomicAggregate),
    Aggregator(Asn, IpAddr),
    Communities(Vec<Community>),
    ExtendedCommunities(Vec<ExtendedCommunity>),
    LargeCommunities(Vec<LargeCommunity>),
    OriginatorId(IpAddr),
    Clusters(Vec<IpAddr>),
    MpReachNlri(Nlri),
    MpUnreachNlri(Nlri),
    Development(Vec<u8>),
}

/////////////
// AS PATH //
/////////////

/// Enum of AS path segment.
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum AsPathSegment {
    AsSequence(Vec<Asn>),
    AsSet(Vec<Asn>),
    ConfedSequence(Vec<Asn>),
    ConfedSet(Vec<Asn>),
}

impl AsPathSegment {
    pub fn count_asns(&self) -> usize {
        match self {
            AsPathSegment::AsSequence(v) => {
                v.len()
            },
            AsPathSegment::AsSet(_) => 1,
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)=> 0,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    pub fn new() -> AsPath {
        AsPath { segments: vec![] }
    }

    pub fn from_segments(segments: Vec<AsPathSegment>) -> AsPath {
        AsPath { segments }
    }

    pub fn add_segment(&mut self, segment: AsPathSegment) {
        self.segments.push(segment);
    }

    pub fn segments(&self) -> &Vec<AsPathSegment> {
        &self.segments
    }

    pub fn count_asns(&self) -> usize {
        self.segments.iter().map(AsPathSegment::count_asns).sum()
    }

    /// Construct AsPath from AS_PATH and AS4_PATH
    ///
    /// https://datatracker.ietf.org/doc/html/rfc6793#section-4.2.3
    ///    If the number of AS numbers in the AS_PATH attribute is less than the
    ///    number of AS numbers in the AS4_PATH attribute, then the AS4_PATH
    ///    attribute SHALL be ignored, and the AS_PATH attribute SHALL be taken
    ///    as the AS path information.
    ///
    ///    If the number of AS numbers in the AS_PATH attribute is larger than
    ///    or equal to the number of AS numbers in the AS4_PATH attribute, then
    ///    the AS path information SHALL be constructed by taking as many AS
    ///    numbers and path segments as necessary from the leading part of the
    ///    AS_PATH attribute, and then prepending them to the AS4_PATH attribute
    ///    so that the AS path information has a number of AS numbers identical
    ///    to that of the AS_PATH attribute.  Note that a valid
    ///    AS_CONFED_SEQUENCE or AS_CONFED_SET path segment SHALL be prepended
    ///    if it is either the leading path segment or is adjacent to a path
    ///    segment that is prepended.
    pub fn merge_aspath_as4path(aspath: &AsPath, as4path: &AsPath) -> Option<AsPath> {
        if aspath.count_asns() < as4path.count_asns() {
            return Some(aspath.clone())
        }

        let mut as4iter = as4path.segments.iter();
        let mut as4seg = as4iter.next();
        let mut new_segs: Vec<AsPathSegment> = vec![];
        if as4seg.is_none(){
            new_segs.extend(aspath.segments.clone());
            return Some(AsPath{ segments: new_segs })
        }

        for seg in &aspath.segments {
            let as4seg_unwrapped = as4seg.unwrap();
            if let (AsPathSegment::AsSequence(seq), AsPathSegment::AsSequence(seq4)) = (seg, as4seg_unwrapped) {
                let diff_len = seq.len() - seq4.len();
                let mut new_seq: Vec<Asn> = vec![];
                new_seq.extend(seq.iter().take(diff_len));
                new_seq.extend(seq4);
                new_segs.push(AsPathSegment::AsSequence(new_seq));
            } else {
                new_segs.push(as4seg_unwrapped.clone());
            }
            as4seg = as4iter.next();
        }

        Some(AsPath{ segments: new_segs })
    }

    pub fn get_origin(&self) -> Option<Vec<Asn>> {
        if let Some(seg) = self.segments.last() {
            match seg {
                AsPathSegment::AsSequence(v) => {
                    if let Some(n) = v.last() {
                        Some(vec![n.clone()])
                    } else {
                        None
                    }
                }
                AsPathSegment::AsSet(v) => { Some(v.clone()) }
                AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => { None }
            }
        } else {
            None
        }
    }
}

//////////
// NLRI //
//////////

#[derive(Debug, PartialEq, Clone, Serialize, Eq)]
pub struct Nlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: Option<NextHopAddress>,
    pub prefixes: Vec<NetworkPrefix>,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct MpReachableNlri {
    afi: Afi,
    safi: Safi,
    next_hop: NextHopAddress,
    prefixes: Vec<NetworkPrefix>,
}

impl MpReachableNlri {
    pub fn new(
        afi: Afi,
        safi: Safi,
        next_hop: NextHopAddress,
        prefixes: Vec<NetworkPrefix>,
    ) -> MpReachableNlri {
        MpReachableNlri {
            afi,
            safi,
            next_hop,
            prefixes,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct MpReachableNlriV2 {
    next_hop: NextHopAddress,
}

#[derive(Debug, PartialEq, Clone)]
pub struct MpUnreachableNlri {
    afi: Afi,
    safi: Safi,
    prefixes: Vec<NetworkPrefix>,
}

impl MpUnreachableNlri {
    pub fn new(afi: Afi, safi: Safi, prefixes: Vec<NetworkPrefix>) -> MpUnreachableNlri {
        MpUnreachableNlri {
            afi,
            safi,
            prefixes,
        }
    }
}

///////////////////
// DISPLAY IMPLS //
///////////////////

impl Display for Origin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Origin::IGP => {"IGP"}
            Origin::EGP => {"EGP"}
            Origin::INCOMPLETE => {"INCOMPLETE"}
        };
        write!(f, "{}", s)
    }
}

impl Display for AtomicAggregate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            AtomicAggregate::NAG => {"NAG"}
            AtomicAggregate::AG => {"AG"}
        })
    }
}


impl Display for NextHopAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}",
               match self {
                   NextHopAddress::Ipv4(v) => {v.to_string()}
                   NextHopAddress::Ipv6(v) => {v.to_string()}
                   NextHopAddress::Ipv6LinkLocal(v1, _v2) => {v1.to_string()}
               }
        )
    }
}

impl Display for AsPath {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}",
               self
                   .segments()
                   .iter()
                   .map(|seg| match seg {
                       AsPathSegment::AsSequence(v) | AsPathSegment::ConfedSequence(v) => v
                           .iter()
                           .join(" "),
                       AsPathSegment::AsSet(v) | AsPathSegment::ConfedSet(v) => {
                           format!(
                               "{{{}}}",
                               v.iter()
                                   .join(",")
                           )
                       }
                   })
                   .join(" ")
        )
    }
}

///////////////
// SERIALIZE //
///////////////

impl Serialize for AsPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl Serialize for Origin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl Serialize for AtomicAggregate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(self.to_string().as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::bgp::attributes::{AsPath, AsPathSegment};

    #[test]
    fn test_aspath_as4path_merge() {
        let aspath = AsPath{
            segments: vec![AsPathSegment::AsSequence([1,2,3,5].map(|i|{i.into()}).to_vec())]
        };
        let as4path = AsPath{
            segments: vec![AsPathSegment::AsSequence([2,3,7].map(|i|{i.into()}).to_vec())]
        };
        let newpath = AsPath::merge_aspath_as4path(&aspath, &as4path).unwrap();
        assert_eq!(newpath.segments[0], AsPathSegment::AsSequence([1,2,3,7].map(|i|{i.into()}).to_vec()));
    }

    #[test]
    fn test_get_origin() {
        let aspath = AsPath{
            segments: vec![
                AsPathSegment::AsSequence([1,2,3,5].map(|i|{i.into()}).to_vec()),
            ]
        };
        let origins = aspath.get_origin();
        assert!(origins.is_some());
        assert_eq!(origins.unwrap(), vec![5]);

        let aspath = AsPath{
            segments: vec![
                AsPathSegment::AsSequence([1,2,3,5].map(|i|{i.into()}).to_vec()),
                AsPathSegment::AsSet([7,8].map(|i|{i.into()}).to_vec()),
            ]
        };
        let origins = aspath.get_origin();
        assert!(origins.is_some());
        assert_eq!(origins.unwrap(), vec![7,8]);
    }
}
