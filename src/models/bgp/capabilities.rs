use crate::models::network::{Afi, Safi};
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{BufMut, Bytes, BytesMut};
use num_enum::{FromPrimitive, IntoPrimitive};

#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum BgpCapabilityType {
    MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4 = 1,
    ROUTE_REFRESH_CAPABILITY_FOR_BGP_4 = 2,
    OUTBOUND_ROUTE_FILTERING_CAPABILITY = 3,
    EXTENDED_NEXT_HOP_ENCODING = 5,
    BGP_EXTENDED_MESSAGE = 6,
    BGPSEC_CAPABILITY = 7,
    MULTIPLE_LABELS_CAPABILITY = 8,
    BGP_ROLE = 9,
    GRACEFUL_RESTART_CAPABILITY = 64,
    SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY = 65,
    SUPPORT_FOR_DYNAMIC_CAPABILITY = 67,
    MULTISESSION_BGP_CAPABILITY = 68,
    ADD_PATH_CAPABILITY = 69,
    ENHANCED_ROUTE_REFRESH_CAPABILITY = 70,
    LONG_LIVED_GRACEFUL_RESTART_CAPABILITY = 71,
    ROUTING_POLICY_DISTRIBUTION = 72,
    FQDN_CAPABILITY = 73,

    /// Catch-all type for any deprecated, unassigned, or reserved codes
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl BgpCapabilityType {
    pub const fn is_deprecated(&self) -> bool {
        matches!(
            self,
            BgpCapabilityType::Unknown(4 | 66 | 128 | 129 | 130 | 131 | 184 | 185)
        )
    }

    pub const fn is_reserved(&self) -> bool {
        matches!(self, BgpCapabilityType::Unknown(0 | 255))
    }

    pub const fn is_reserved_for_experimental_use(&self) -> bool {
        matches!(self, BgpCapabilityType::Unknown(239..=254))
    }
}

/// Extended Next Hop capability entry - RFC 8950, Section 3
/// Represents a single <NLRI AFI, NLRI SAFI, NextHop AFI> triple
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedNextHopEntry {
    /// Address Family Identifier for NLRI (typically AFI=1 for IPv4)
    pub nlri_afi: Afi,
    /// Subsequent Address Family Identifier for NLRI (1, 2, 4, 128, 129 per RFC 8950)
    pub nlri_safi: Safi,
    /// Address Family Identifier for Next Hop (typically AFI=2 for IPv6)  
    pub nexthop_afi: Afi,
}

/// Extended Next Hop capability - RFC 8950, Section 3
/// Contains a list of supported NLRI/NextHop AFI/SAFI combinations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedNextHopCapability {
    /// List of supported AFI/SAFI combinations for extended next hop encoding
    pub entries: Vec<ExtendedNextHopEntry>,
}

impl ExtendedNextHopCapability {
    /// Create a new Extended Next Hop capability with the given entries
    pub fn new(entries: Vec<ExtendedNextHopEntry>) -> Self {
        Self { entries }
    }

    /// Check if this capability supports a specific NLRI AFI/SAFI with NextHop AFI combination
    pub fn supports(&self, nlri_afi: Afi, nlri_safi: Safi, nexthop_afi: Afi) -> bool {
        self.entries.iter().any(|entry| {
            entry.nlri_afi == nlri_afi
                && entry.nlri_safi == nlri_safi
                && entry.nexthop_afi == nexthop_afi
        })
    }

    /// Get all supported NLRI AFI/SAFI combinations for a given NextHop AFI
    pub fn supported_nlri_for_nexthop(&self, nexthop_afi: Afi) -> Vec<(Afi, Safi)> {
        self.entries
            .iter()
            .filter(|entry| entry.nexthop_afi == nexthop_afi)
            .map(|entry| (entry.nlri_afi, entry.nlri_safi))
            .collect()
    }

    /// Parse Extended Next Hop capability from raw bytes - RFC 8950, Section 3
    ///
    /// Format: Series of 6-byte entries, each containing:
    /// - NLRI AFI (2 bytes)
    /// - NLRI SAFI (2 bytes)
    /// - NextHop AFI (2 bytes)
    pub fn parse(mut data: Bytes) -> Result<Self, ParserError> {
        let mut entries = Vec::new();

        // Each entry is 6 bytes (2 + 2 + 2)
        if data.len() % 6 != 0 {
            return Err(ParserError::ParseError(format!(
                "Extended Next Hop capability length {} is not divisible by 6",
                data.len()
            )));
        }

        while data.len() >= 6 {
            let nlri_afi = data.read_afi()?;
            // SAFI is encoded as 2 bytes in capability, but SAFI enum is u8
            let nlri_safi_u16 = data.read_u16()?;
            let nlri_safi = Safi::try_from(nlri_safi_u16 as u8).map_err(|_| {
                ParserError::ParseError(format!("Unknown SAFI type: {}", nlri_safi_u16))
            })?;
            let nexthop_afi = data.read_afi()?;

            entries.push(ExtendedNextHopEntry {
                nlri_afi,
                nlri_safi,
                nexthop_afi,
            });
        }

        Ok(ExtendedNextHopCapability::new(entries))
    }

    /// Encode Extended Next Hop capability to raw bytes - RFC 8950, Section 3
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.entries.len() * 6);

        for entry in &self.entries {
            bytes.put_u16(entry.nlri_afi as u16); // NLRI AFI (2 bytes)
            bytes.put_u16(entry.nlri_safi as u8 as u16); // NLRI SAFI (2 bytes in capability, but SAFI is u8)
            bytes.put_u16(entry.nexthop_afi as u16); // NextHop AFI (2 bytes)
        }

        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing_capability() {
        // reserved
        assert!(BgpCapabilityType::from(0).is_reserved());
        assert!(BgpCapabilityType::from(255).is_reserved());

        // deprecated
        for code in [4, 66, 128, 129, 130, 131, 184, 185] {
            assert!(BgpCapabilityType::from(code).is_deprecated());
        }

        // unassigned
        let unassigned_ranges = [10..=63, 74..=127, 132..=183, 186..=238];
        for code in <[_; 4]>::into_iter(unassigned_ranges).flatten() {
            let ty = BgpCapabilityType::from(code);
            assert_eq!(ty, BgpCapabilityType::Unknown(code));
            assert!(!ty.is_deprecated() && !ty.is_reserved());
        }

        // valid capabilities
        assert_eq!(
            BgpCapabilityType::from(1),
            BgpCapabilityType::MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4
        );
        assert_eq!(
            BgpCapabilityType::from(2),
            BgpCapabilityType::ROUTE_REFRESH_CAPABILITY_FOR_BGP_4
        );
        assert_eq!(
            BgpCapabilityType::from(3),
            BgpCapabilityType::OUTBOUND_ROUTE_FILTERING_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(5),
            BgpCapabilityType::EXTENDED_NEXT_HOP_ENCODING
        );
        assert_eq!(
            BgpCapabilityType::from(6),
            BgpCapabilityType::BGP_EXTENDED_MESSAGE
        );
        assert_eq!(
            BgpCapabilityType::from(7),
            BgpCapabilityType::BGPSEC_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(8),
            BgpCapabilityType::MULTIPLE_LABELS_CAPABILITY
        );
        assert_eq!(BgpCapabilityType::from(9), BgpCapabilityType::BGP_ROLE);

        assert_eq!(
            BgpCapabilityType::from(64),
            BgpCapabilityType::GRACEFUL_RESTART_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(65),
            BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(67),
            BgpCapabilityType::SUPPORT_FOR_DYNAMIC_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(68),
            BgpCapabilityType::MULTISESSION_BGP_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(69),
            BgpCapabilityType::ADD_PATH_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(70),
            BgpCapabilityType::ENHANCED_ROUTE_REFRESH_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(71),
            BgpCapabilityType::LONG_LIVED_GRACEFUL_RESTART_CAPABILITY
        );
        assert_eq!(
            BgpCapabilityType::from(72),
            BgpCapabilityType::ROUTING_POLICY_DISTRIBUTION
        );
        assert_eq!(
            BgpCapabilityType::from(73),
            BgpCapabilityType::FQDN_CAPABILITY
        );
    }

    #[test]
    fn test_reserved_for_experimental() {
        let experimental_ranges = [239..=254];
        for code in <[_; 1]>::into_iter(experimental_ranges).flatten() {
            let ty = BgpCapabilityType::from(code);
            assert_eq!(ty, BgpCapabilityType::Unknown(code));
            assert!(ty.is_reserved_for_experimental_use());
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        let ty = BgpCapabilityType::MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4;
        let serialized = serde_json::to_string(&ty).unwrap();
        let deserialized: BgpCapabilityType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(ty, deserialized);
    }

    #[test]
    fn test_extended_next_hop_capability() {
        use crate::models::network::{Afi, Safi};

        // Create capability with RFC 8950 standard combinations
        let entries = vec![
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                nexthop_afi: Afi::Ipv6,
            },
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::MplsVpn,
                nexthop_afi: Afi::Ipv6,
            },
        ];

        let capability = ExtendedNextHopCapability::new(entries);

        // Test supports() method
        assert!(capability.supports(Afi::Ipv4, Safi::Unicast, Afi::Ipv6));
        assert!(capability.supports(Afi::Ipv4, Safi::MplsVpn, Afi::Ipv6));
        assert!(!capability.supports(Afi::Ipv4, Safi::Multicast, Afi::Ipv6));
        assert!(!capability.supports(Afi::Ipv6, Safi::Unicast, Afi::Ipv6));

        // Test supported_nlri_for_nexthop() method
        let supported = capability.supported_nlri_for_nexthop(Afi::Ipv6);
        assert_eq!(supported.len(), 2);
        assert!(supported.contains(&(Afi::Ipv4, Safi::Unicast)));
        assert!(supported.contains(&(Afi::Ipv4, Safi::MplsVpn)));

        let no_support = capability.supported_nlri_for_nexthop(Afi::Ipv4);
        assert!(no_support.is_empty());
    }

    #[test]
    fn test_extended_next_hop_capability_parsing() {
        use crate::models::network::{Afi, Safi};

        // Test parsing valid capability data
        // Entry 1: IPv4 Unicast (AFI=1, SAFI=1) with IPv6 NextHop (AFI=2)
        // Entry 2: IPv4 MPLS VPN (AFI=1, SAFI=128) with IPv6 NextHop (AFI=2)
        let capability_bytes = Bytes::from(vec![
            0x00, 0x01, // NLRI AFI = 1 (IPv4)
            0x00, 0x01, // NLRI SAFI = 1 (Unicast)
            0x00, 0x02, // NextHop AFI = 2 (IPv6)
            0x00, 0x01, // NLRI AFI = 1 (IPv4)
            0x00, 0x80, // NLRI SAFI = 128 (MPLS VPN)
            0x00, 0x02, // NextHop AFI = 2 (IPv6)
        ]);

        let parsed = ExtendedNextHopCapability::parse(capability_bytes).unwrap();

        assert_eq!(parsed.entries.len(), 2);

        // Check first entry
        assert_eq!(parsed.entries[0].nlri_afi, Afi::Ipv4);
        assert_eq!(parsed.entries[0].nlri_safi, Safi::Unicast);
        assert_eq!(parsed.entries[0].nexthop_afi, Afi::Ipv6);

        // Check second entry
        assert_eq!(parsed.entries[1].nlri_afi, Afi::Ipv4);
        assert_eq!(parsed.entries[1].nlri_safi, Safi::MplsVpn);
        assert_eq!(parsed.entries[1].nexthop_afi, Afi::Ipv6);

        // Test functionality
        assert!(parsed.supports(Afi::Ipv4, Safi::Unicast, Afi::Ipv6));
        assert!(parsed.supports(Afi::Ipv4, Safi::MplsVpn, Afi::Ipv6));
        assert!(!parsed.supports(Afi::Ipv4, Safi::Multicast, Afi::Ipv6));
    }

    #[test]
    fn test_extended_next_hop_capability_encoding() {
        use crate::models::network::{Afi, Safi};

        let entries = vec![
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                nexthop_afi: Afi::Ipv6,
            },
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::MplsVpn,
                nexthop_afi: Afi::Ipv6,
            },
        ];

        let capability = ExtendedNextHopCapability::new(entries);
        let encoded = capability.encode();

        let expected = vec![
            0x00, 0x01, // NLRI AFI = 1 (IPv4)
            0x00, 0x01, // NLRI SAFI = 1 (Unicast)
            0x00, 0x02, // NextHop AFI = 2 (IPv6)
            0x00, 0x01, // NLRI AFI = 1 (IPv4)
            0x00, 0x80, // NLRI SAFI = 128 (MPLS VPN)
            0x00, 0x02, // NextHop AFI = 2 (IPv6)
        ];

        assert_eq!(encoded.to_vec(), expected);
    }

    #[test]
    fn test_extended_next_hop_capability_round_trip() {
        use crate::models::network::{Afi, Safi};

        let original_entries = vec![
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                nexthop_afi: Afi::Ipv6,
            },
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::MulticastVpn,
                nexthop_afi: Afi::Ipv6,
            },
        ];

        let original = ExtendedNextHopCapability::new(original_entries);
        let encoded = original.encode();
        let parsed = ExtendedNextHopCapability::parse(encoded).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_extended_next_hop_capability_invalid_length() {
        // Test with invalid length (not divisible by 6)
        let invalid_bytes = Bytes::from(vec![0x00, 0x01, 0x00, 0x01, 0x00]); // 5 bytes
        let result = ExtendedNextHopCapability::parse(invalid_bytes);
        assert!(result.is_err());

        if let Err(ParserError::ParseError(msg)) = result {
            assert!(msg.contains("not divisible by 6"));
        } else {
            panic!("Expected ParseError with divisibility message");
        }
    }

    #[test]
    fn test_extended_next_hop_capability_empty() {
        // Test with empty capability (valid - no entries)
        let empty_bytes = Bytes::from(vec![]);
        let parsed = ExtendedNextHopCapability::parse(empty_bytes).unwrap();
        assert_eq!(parsed.entries.len(), 0);

        // Test encoding empty capability
        let empty_capability = ExtendedNextHopCapability::new(vec![]);
        let encoded = empty_capability.encode();
        assert_eq!(encoded.len(), 0);
    }
}
