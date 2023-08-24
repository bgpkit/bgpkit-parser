//! BGP error code module that maintains explicit error codes assigned by IANA.
//!
//! The full list of IANA error code assignments for BGP can be viewed at here:
//! <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-3>.
use num_traits::FromPrimitive;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Error for parsing BGP error code
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpErrorCodeParsingError {
    UnknownCode(u8),
    UnknownSubcode(u8),
    DeprecatedCode(u8),
    DeprecatedSubcode(u8),
}

impl Display for BgpErrorCodeParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpErrorCodeParsingError::UnknownCode(v) => {
                write!(f, "unknown BGP error code {}", v)
            }
            BgpErrorCodeParsingError::UnknownSubcode(v) => {
                write!(f, "unknown BGP error subcode {}", v)
            }
            BgpErrorCodeParsingError::DeprecatedCode(v) => {
                write!(f, "deprecated BGP error code {}", v)
            }
            BgpErrorCodeParsingError::DeprecatedSubcode(v) => {
                write!(f, "deprecated BGP error subcode {}", v)
            }
        }
    }
}

impl Error for BgpErrorCodeParsingError {}

/// Utility function to parse a pair of BGP error code and subcode (both u8) into a defined struct.
pub fn parse_error_codes(
    error_code: &u8,
    error_subcode: &u8,
) -> Result<BgpError, BgpErrorCodeParsingError> {
    match error_code {
        0 => Ok(BgpError::Reserved),
        1 => match MessageHeaderErrorSubcode::from_u8(*error_subcode) {
            Some(v) => Ok(BgpError::MessageHeaderError(v)),
            None => Err(BgpErrorCodeParsingError::UnknownSubcode(*error_subcode)),
        },
        2 => {
            if [5, 8, 9, 10].contains(error_subcode) {
                return Err(BgpErrorCodeParsingError::DeprecatedSubcode(*error_subcode));
            }
            match OpenMessageErrorSubcode::from_u8(*error_subcode) {
                Some(v) => Ok(BgpError::OpenMessageError(v)),
                None => Err(BgpErrorCodeParsingError::UnknownSubcode(*error_subcode)),
            }
        }
        3 => {
            if [7].contains(error_subcode) {
                return Err(BgpErrorCodeParsingError::DeprecatedSubcode(*error_subcode));
            }
            match UpdateMessageErrorSubcode::from_u8(*error_subcode) {
                Some(v) => Ok(BgpError::UpdateMessageError(v)),
                None => Err(BgpErrorCodeParsingError::UnknownSubcode(*error_subcode)),
            }
        }
        4 => Ok(BgpError::HoldTimerExpired),
        5 => match BgpFiniteStateMachineErrorSubcode::from_u8(*error_subcode) {
            Some(v) => Ok(BgpError::BgpFiniteStateMachineError(v)),
            None => Err(BgpErrorCodeParsingError::UnknownSubcode(*error_subcode)),
        },
        6 => match BgpCeaseNotificationMessageSubcode::from_u8(*error_subcode) {
            Some(v) => Ok(BgpError::BgpCeaseNotification(v)),
            None => Err(BgpErrorCodeParsingError::UnknownSubcode(*error_subcode)),
        },
        7 => match BgpRouteRefreshMessageErrorSubcode::from_u8(*error_subcode) {
            Some(v) => Ok(BgpError::BgpRouteFreshMessageError(v)),
            None => Err(BgpErrorCodeParsingError::UnknownSubcode(*error_subcode)),
        },
        v => Err(BgpErrorCodeParsingError::UnknownCode(*v)),
    }
}

/// BGP Error Subcode enum.
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-4>
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpError {
    Reserved,
    MessageHeaderError(MessageHeaderErrorSubcode),
    OpenMessageError(OpenMessageErrorSubcode),
    UpdateMessageError(UpdateMessageErrorSubcode),
    HoldTimerExpired,
    BgpFiniteStateMachineError(BgpFiniteStateMachineErrorSubcode),
    BgpCeaseNotification(BgpCeaseNotificationMessageSubcode),
    BgpRouteFreshMessageError(BgpRouteRefreshMessageErrorSubcode),
}

/// Message Header Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-5>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MessageHeaderErrorSubcode {
    UNSPECIFIC = 0,
    CONNECTION_NOT_SYNCHRONIZED = 1,
    BAD_MESSAGE_LENGTH = 2,
    BAD_MESSAGE_TYPE = 3,
    // 4 - 255: unassigned
}

/// OPEN Message Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-6>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OpenMessageErrorSubcode {
    UNSPECIFIC = 0,
    UNSUPPORTED_VERSION_NUMBER = 1,
    BAD_PEER_AS = 2,
    BAD_BGP_IDENTIFIER = 3,
    UNSUPPORTED_OPTIONAL_PARAMETER = 4,
    // 5 -- deprecated
    UNACCEPTABLE_HOLD_TIME = 6,
    UNSUPPORTED_CAPACITY = 7,
    // 8 -- deprecated
    // 9 -- deprecated
    // 10 -- deprecated
    ROLE_MISMATCH = 11,
    // 12 - 255: unassinged
}

/// UPDATE Message Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-finite-state-machine-error-subcodes>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdateMessageErrorSubcode {
    UNSPECIFIC = 0,
    MALFORMED_ATTRIBUTE_LIST = 1,
    UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE = 2,
    MISSING_WELL_KNOWN_ATTRIBUTE = 3,
    ATTRIBUTE_FLAGS_ERROR = 4,
    ATTRIBUTE_LENGTH_ERROR = 5,
    INVALID_ORIGIN_ERROR = 6,
    // 7 - deprecated
    INVALID_NEXT_HOP_ATTRIBUTE = 8,
    OPTIONAL_ATTRIBUTE_ERROR = 9,
    INVALID_NETWORK_FIELD = 10,
    MALFORMED_AS_PATH = 11,
    // 12 - 255: unassigned
}

/// BGP Finite State Machine Error Subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-finite-state-machine-error-subcodes>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpFiniteStateMachineErrorSubcode {
    UNSPECIFIED = 0,
    RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_State = 1,
    RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE = 2,
    RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE = 3,
    // 4 - 255: unassigned
}

/// BGP Cease NOTIFICATION message subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-8>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpCeaseNotificationMessageSubcode {
    RESERVED = 0,
    MAXIMUM_NUMBER_OF_PREFIXES_REACHED = 1,
    ADMINISTRATIVE_SHUTDOWN = 2,
    PEER_DE_CONFIGURED = 3,
    ADMINISTRATIVE_RESET = 4,
    CONNECTION_REJECTED = 5,
    OTHER_CONFIGURATION_CHANGE = 6,
    CONNECTION_COLLISION_RESOLUTION = 7,
    OUT_OF_RESOURCES = 8,
    HARD_RESET = 9,
    BFD_DOWN = 10, // TEMPORARY - registered 2022-02-23, expires 2023-02-23
                   // 11 - 255: unassigned
}

/// BGP ROUTE-REFRESH Message Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#route-refresh-error-subcodes>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, Primitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpRouteRefreshMessageErrorSubcode {
    RESERVED = 0,
    INVALID_MESSAGE_LENGTH = 1,
    // 2 - 255: unassigned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        let mut error_code: u8;
        let mut error_subcode: u8;
        error_code = 0;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::Reserved)
        );

        error_code = 1;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::MessageHeaderError(
                MessageHeaderErrorSubcode::UNSPECIFIC
            ))
        );
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::MessageHeaderError(
                MessageHeaderErrorSubcode::CONNECTION_NOT_SYNCHRONIZED
            ))
        );
        error_subcode = 2;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::MessageHeaderError(
                MessageHeaderErrorSubcode::BAD_MESSAGE_LENGTH
            ))
        );
        error_subcode = 3;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::MessageHeaderError(
                MessageHeaderErrorSubcode::BAD_MESSAGE_TYPE
            ))
        );
        error_subcode = 4;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownSubcode(4))
        );

        error_code = 2;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::UNSPECIFIC
            ))
        );
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::UNSUPPORTED_VERSION_NUMBER
            ))
        );
        error_subcode = 2;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::BAD_PEER_AS
            ))
        );
        error_subcode = 3;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::BAD_BGP_IDENTIFIER
            ))
        );
        error_subcode = 4;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::UNSUPPORTED_OPTIONAL_PARAMETER
            ))
        );
        error_subcode = 6;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::UNACCEPTABLE_HOLD_TIME
            ))
        );
        error_subcode = 7;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::UNSUPPORTED_CAPACITY
            ))
        );
        error_subcode = 11;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::OpenMessageError(
                OpenMessageErrorSubcode::ROLE_MISMATCH
            ))
        );
        // deprecated subcodes
        for n in [5, 8, 9, 10] {
            error_subcode = n as u8;
            assert_eq!(
                parse_error_codes(&error_code, &error_subcode),
                Err(BgpErrorCodeParsingError::DeprecatedSubcode(error_subcode))
            );
        }
        error_subcode = 12;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownSubcode(12))
        );

        error_code = 3;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::UNSPECIFIC
            ))
        );
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::MALFORMED_ATTRIBUTE_LIST
            ))
        );
        error_subcode = 2;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE
            ))
        );
        error_subcode = 3;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::MISSING_WELL_KNOWN_ATTRIBUTE
            ))
        );
        error_subcode = 4;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::ATTRIBUTE_FLAGS_ERROR
            ))
        );
        error_subcode = 5;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::ATTRIBUTE_LENGTH_ERROR
            ))
        );
        error_subcode = 6;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::INVALID_ORIGIN_ERROR
            ))
        );
        error_subcode = 8;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::INVALID_NEXT_HOP_ATTRIBUTE
            ))
        );
        error_subcode = 9;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::OPTIONAL_ATTRIBUTE_ERROR
            ))
        );
        error_subcode = 10;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::INVALID_NETWORK_FIELD
            ))
        );
        error_subcode = 11;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::MALFORMED_AS_PATH
            ))
        );
        // deprecated subcodes
        for n in [7] {
            error_subcode = n as u8;
            assert_eq!(
                parse_error_codes(&error_code, &error_subcode),
                Err(BgpErrorCodeParsingError::DeprecatedSubcode(error_subcode))
            );
        }
        error_subcode = 12;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownSubcode(12))
        );

        error_code = 4;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::HoldTimerExpired)
        );
        // subcode should not matter here
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::HoldTimerExpired)
        );

        error_code = 5;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::UNSPECIFIED
            ))
        );
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_State
            ))
        );
        error_subcode = 2;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE
            ))
        );
        error_subcode = 3;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE
            ))
        );
        error_subcode = 4;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownSubcode(4))
        );

        error_code = 6;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::RESERVED
            ))
        );
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::MAXIMUM_NUMBER_OF_PREFIXES_REACHED
            ))
        );
        error_subcode = 2;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::ADMINISTRATIVE_SHUTDOWN
            ))
        );
        error_subcode = 3;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::PEER_DE_CONFIGURED
            ))
        );
        error_subcode = 4;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::ADMINISTRATIVE_RESET
            ))
        );
        error_subcode = 5;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::CONNECTION_REJECTED
            ))
        );
        error_subcode = 6;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::OTHER_CONFIGURATION_CHANGE
            ))
        );
        error_subcode = 7;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::CONNECTION_COLLISION_RESOLUTION
            ))
        );
        error_subcode = 8;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::OUT_OF_RESOURCES
            ))
        );
        error_subcode = 9;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::HARD_RESET
            ))
        );
        error_subcode = 10;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::BFD_DOWN
            ))
        );
        error_subcode = 11;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownSubcode(11))
        );

        error_code = 7;
        error_subcode = 0;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpRouteFreshMessageError(
                BgpRouteRefreshMessageErrorSubcode::RESERVED
            ))
        );
        error_subcode = 1;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Ok(BgpError::BgpRouteFreshMessageError(
                BgpRouteRefreshMessageErrorSubcode::INVALID_MESSAGE_LENGTH
            ))
        );
        error_subcode = 2;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownSubcode(2))
        );

        error_code = 8;
        assert_eq!(
            parse_error_codes(&error_code, &error_subcode),
            Err(BgpErrorCodeParsingError::UnknownCode(8))
        );
    }
}
