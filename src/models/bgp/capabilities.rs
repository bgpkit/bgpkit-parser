use num_traits::FromPrimitive;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// BGP capability parsing error
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum BgpCapabilityParsingError {
    Unassigned(u8),
    DeprecatedCode(u8),
    ReservedCode(u8),
    ReservedExperimentalCode(u8),
}

impl Display for BgpCapabilityParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpCapabilityParsingError::Unassigned(v) => {
                write!(f, "unassigned BGP capability code: {}", v)
            }
            BgpCapabilityParsingError::DeprecatedCode(v) => {
                write!(f, "deprecated BGP capability code: {}", v)
            }
            BgpCapabilityParsingError::ReservedCode(v) => {
                write!(f, "reserved BGP capability code: {}", v)
            }
            BgpCapabilityParsingError::ReservedExperimentalCode(v) => {
                write!(
                    f,
                    "reserved BGP capability code for experimental use: {}",
                    v
                )
            }
        }
    }
}

impl Error for BgpCapabilityParsingError {}

#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
}

pub fn parse_capability(
    capability_code: &u8,
) -> Result<BgpCapabilityType, BgpCapabilityParsingError> {
    match BgpCapabilityType::from_u8(*capability_code) {
        Some(v) => Ok(v),
        None => {
            if [4, 66, 128, 129, 130, 131, 184, 185].contains(capability_code) {
                Err(BgpCapabilityParsingError::DeprecatedCode(*capability_code))
            } else if *capability_code == 0 || *capability_code == 255 {
                Err(BgpCapabilityParsingError::ReservedCode(*capability_code))
            } else if *capability_code >= 239 && *capability_code <= 254 {
                Err(BgpCapabilityParsingError::ReservedExperimentalCode(
                    *capability_code,
                ))
            } else {
                Err(BgpCapabilityParsingError::Unassigned(*capability_code))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing_capability() {
        let mut code;

        // reserved
        code = 0;
        assert_eq!(
            parse_capability(&code),
            Err(BgpCapabilityParsingError::ReservedCode(code))
        );
        code = 255;
        assert_eq!(
            parse_capability(&code),
            Err(BgpCapabilityParsingError::ReservedCode(code))
        );

        // deprecated
        for code in [4, 66, 128, 129, 130, 131, 184, 185] {
            assert_eq!(
                parse_capability(&code),
                Err(BgpCapabilityParsingError::DeprecatedCode(code))
            );
        }

        // unassigned
        for code in 10..=63 {
            assert_eq!(
                parse_capability(&code),
                Err(BgpCapabilityParsingError::Unassigned(code))
            );
        }
        for code in 74..=127 {
            assert_eq!(
                parse_capability(&code),
                Err(BgpCapabilityParsingError::Unassigned(code))
            );
        }
        for code in 132..=183 {
            assert_eq!(
                parse_capability(&code),
                Err(BgpCapabilityParsingError::Unassigned(code))
            );
        }
        for code in 186..=238 {
            assert_eq!(
                parse_capability(&code),
                Err(BgpCapabilityParsingError::Unassigned(code))
            );
        }

        // valid capabilities
        code = 1;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4)
        );
        code = 2;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::ROUTE_REFRESH_CAPABILITY_FOR_BGP_4)
        );
        code = 3;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::OUTBOUND_ROUTE_FILTERING_CAPABILITY)
        );
        code = 5;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::EXTENDED_NEXT_HOP_ENCODING)
        );
        code = 6;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::BGP_EXTENDED_MESSAGE)
        );
        code = 7;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::BGPSEC_CAPABILITY)
        );
        code = 8;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::MULTIPLE_LABELS_CAPABILITY)
        );
        code = 9;
        assert_eq!(parse_capability(&code), Ok(BgpCapabilityType::BGP_ROLE));

        code = 64;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::GRACEFUL_RESTART_CAPABILITY)
        );
        code = 65;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY)
        );
        code = 67;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::SUPPORT_FOR_DYNAMIC_CAPABILITY)
        );
        code = 68;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::MULTISESSION_BGP_CAPABILITY)
        );
        code = 69;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::ADD_PATH_CAPABILITY)
        );
        code = 70;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::ENHANCED_ROUTE_REFRESH_CAPABILITY)
        );
        code = 71;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::LONG_LIVED_GRACEFUL_RESTART_CAPABILITY)
        );
        code = 72;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::ROUTING_POLICY_DISTRIBUTION)
        );
        code = 73;
        assert_eq!(
            parse_capability(&code),
            Ok(BgpCapabilityType::FQDN_CAPABILITY)
        );
    }
}
