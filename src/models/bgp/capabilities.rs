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
}
