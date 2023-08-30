//! BGP error code module that maintains explicit error codes assigned by IANA.
//!
//! The full list of IANA error code assignments for BGP can be viewed at here:
//! <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-3>.
use log::warn;
use num_enum::{FromPrimitive, IntoPrimitive};

// TODO(jmeggitt): Come back to review file and reduce type/variant name lengths

#[derive(Copy, Clone, Debug, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum BgpErrorCode {
    Reserved = 0,
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    BgpFiniteStateMachineError = 5,
    BgpCeaseNotification = 6,
    BgpRouteFreshMessageError = 7,
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// BGP Error Subcode enum.
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-4>
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BgpError {
    /// Includes subcode. Currently, no subcodes have been assigned.
    Reserved(u8),
    MessageHeaderError(MessageHeaderErrorSubcode),
    OpenMessageError(OpenMessageErrorSubcode),
    UpdateMessageError(UpdateMessageErrorSubcode),
    /// Includes subcode. Currently, no subcodes have been assigned.
    HoldTimerExpired(u8),
    BgpFiniteStateMachineError(BgpFiniteStateMachineErrorSubcode),
    BgpCeaseNotification(BgpCeaseNotificationMessageSubcode),
    BgpRouteFreshMessageError(BgpRouteRefreshMessageErrorSubcode),
    Unknown(u8, u8),
}

impl BgpError {
    pub fn new(code: u8, subcode: u8) -> Self {
        match BgpErrorCode::from(code) {
            BgpErrorCode::Reserved => BgpError::Reserved(subcode),
            BgpErrorCode::MessageHeaderError => {
                BgpError::MessageHeaderError(MessageHeaderErrorSubcode::from(subcode))
            }
            BgpErrorCode::OpenMessageError => {
                BgpError::OpenMessageError(OpenMessageErrorSubcode::from(subcode))
            }
            BgpErrorCode::UpdateMessageError => {
                BgpError::UpdateMessageError(UpdateMessageErrorSubcode::from(subcode))
            }
            BgpErrorCode::HoldTimerExpired => BgpError::HoldTimerExpired(subcode),
            BgpErrorCode::BgpFiniteStateMachineError => BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::from(subcode),
            ),
            BgpErrorCode::BgpCeaseNotification => {
                BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::from(subcode))
            }
            BgpErrorCode::BgpRouteFreshMessageError => BgpError::BgpRouteFreshMessageError(
                BgpRouteRefreshMessageErrorSubcode::from(subcode),
            ),
            BgpErrorCode::Unknown(_) => {
                warn!(
                    "error parsing BGP notification error code: {}, subcode: {}",
                    code, subcode
                );
                BgpError::Unknown(code, subcode)
            }
        }
    }
}

/// Message Header Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-5>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MessageHeaderErrorSubcode {
    UNSPECIFIC = 0,
    CONNECTION_NOT_SYNCHRONIZED = 1,
    BAD_MESSAGE_LENGTH = 2,
    BAD_MESSAGE_TYPE = 3,
    // 4 - 255: unassigned
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// OPEN Message Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-6>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
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
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl OpenMessageErrorSubcode {
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, OpenMessageErrorSubcode::Unknown(5 | 8 | 9 | 10))
    }
}

/// UPDATE Message Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-finite-state-machine-error-subcodes>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
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
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl UpdateMessageErrorSubcode {
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, UpdateMessageErrorSubcode::Unknown(7))
    }
}

/// BGP Finite State Machine Error Subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-finite-state-machine-error-subcodes>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum BgpFiniteStateMachineErrorSubcode {
    UNSPECIFIED = 0,
    RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_State = 1,
    RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE = 2,
    RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE = 3,
    // 4 - 255: unassigned
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// BGP Cease NOTIFICATION message subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-8>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
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
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// BGP ROUTE-REFRESH Message Error subcodes
///
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#route-refresh-error-subcodes>
///
/// *See source code for number assignment*
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq, Hash, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum BgpRouteRefreshMessageErrorSubcode {
    RESERVED = 0,
    INVALID_MESSAGE_LENGTH = 1,
    // 2 - 255: unassigned
    #[num_enum(catch_all)]
    Unknown(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        assert_eq!(BgpError::new(0, 0), BgpError::Reserved(0));

        assert_eq!(
            BgpError::new(1, 0),
            BgpError::MessageHeaderError(MessageHeaderErrorSubcode::UNSPECIFIC)
        );
        assert_eq!(
            BgpError::new(1, 1),
            BgpError::MessageHeaderError(MessageHeaderErrorSubcode::CONNECTION_NOT_SYNCHRONIZED)
        );
        assert_eq!(
            BgpError::new(1, 2),
            BgpError::MessageHeaderError(MessageHeaderErrorSubcode::BAD_MESSAGE_LENGTH)
        );
        assert_eq!(
            BgpError::new(1, 3),
            BgpError::MessageHeaderError(MessageHeaderErrorSubcode::BAD_MESSAGE_TYPE)
        );
        assert_eq!(
            BgpError::new(1, 4),
            BgpError::MessageHeaderError(MessageHeaderErrorSubcode::Unknown(4)),
        );

        assert_eq!(
            BgpError::new(2, 0),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::UNSPECIFIC)
        );
        assert_eq!(
            BgpError::new(2, 1),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::UNSUPPORTED_VERSION_NUMBER)
        );
        assert_eq!(
            BgpError::new(2, 2),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::BAD_PEER_AS)
        );
        assert_eq!(
            BgpError::new(2, 3),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::BAD_BGP_IDENTIFIER)
        );
        assert_eq!(
            BgpError::new(2, 4),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::UNSUPPORTED_OPTIONAL_PARAMETER)
        );
        assert_eq!(
            BgpError::new(2, 6),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::UNACCEPTABLE_HOLD_TIME)
        );
        assert_eq!(
            BgpError::new(2, 7),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::UNSUPPORTED_CAPACITY)
        );
        assert_eq!(
            BgpError::new(2, 11),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::ROLE_MISMATCH)
        );
        // deprecated subcodes
        for n in [5, 8, 9, 10] {
            assert_eq!(
                BgpError::new(2, n),
                BgpError::OpenMessageError(OpenMessageErrorSubcode::Unknown(n))
            );
            assert!(OpenMessageErrorSubcode::Unknown(n).is_deprecated());
        }
        assert_eq!(
            BgpError::new(2, 12),
            BgpError::OpenMessageError(OpenMessageErrorSubcode::Unknown(12))
        );

        assert_eq!(
            BgpError::new(3, 0),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::UNSPECIFIC)
        );
        assert_eq!(
            BgpError::new(3, 1),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::MALFORMED_ATTRIBUTE_LIST)
        );
        assert_eq!(
            BgpError::new(3, 2),
            BgpError::UpdateMessageError(
                UpdateMessageErrorSubcode::UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE
            )
        );
        assert_eq!(
            BgpError::new(3, 3),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::MISSING_WELL_KNOWN_ATTRIBUTE)
        );
        assert_eq!(
            BgpError::new(3, 4),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::ATTRIBUTE_FLAGS_ERROR)
        );
        assert_eq!(
            BgpError::new(3, 5),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::ATTRIBUTE_LENGTH_ERROR)
        );
        assert_eq!(
            BgpError::new(3, 6),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::INVALID_ORIGIN_ERROR)
        );
        assert_eq!(
            BgpError::new(3, 8),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::INVALID_NEXT_HOP_ATTRIBUTE)
        );
        assert_eq!(
            BgpError::new(3, 9),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::OPTIONAL_ATTRIBUTE_ERROR)
        );
        assert_eq!(
            BgpError::new(3, 10),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::INVALID_NETWORK_FIELD)
        );
        assert_eq!(
            BgpError::new(3, 11),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::MALFORMED_AS_PATH)
        );
        // deprecated subcodes
        for n in [7] {
            assert_eq!(
                BgpError::new(3, n),
                BgpError::UpdateMessageError(UpdateMessageErrorSubcode::Unknown(n))
            );
            assert!(UpdateMessageErrorSubcode::Unknown(n).is_deprecated());
        }
        assert_eq!(
            BgpError::new(3, 12),
            BgpError::UpdateMessageError(UpdateMessageErrorSubcode::Unknown(12))
        );

        assert_eq!(BgpError::new(4, 0), BgpError::HoldTimerExpired(0));
        // subcode should not matter here
        assert_eq!(BgpError::new(4, 1), BgpError::HoldTimerExpired(1));

        assert_eq!(
            BgpError::new(5, 0),
            BgpError::BgpFiniteStateMachineError(BgpFiniteStateMachineErrorSubcode::UNSPECIFIED)
        );
        assert_eq!(
            BgpError::new(5, 1),
            BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_State
            )
        );
        assert_eq!(
            BgpError::new(5, 2),
            BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE
            )
        );
        assert_eq!(
            BgpError::new(5, 3),
            BgpError::BgpFiniteStateMachineError(
                BgpFiniteStateMachineErrorSubcode::RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE
            )
        );
        assert_eq!(
            BgpError::new(5, 4),
            BgpError::BgpFiniteStateMachineError(BgpFiniteStateMachineErrorSubcode::Unknown(4))
        );

        assert_eq!(
            BgpError::new(6, 0),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::RESERVED)
        );
        assert_eq!(
            BgpError::new(6, 1),
            BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::MAXIMUM_NUMBER_OF_PREFIXES_REACHED
            )
        );
        assert_eq!(
            BgpError::new(6, 2),
            BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::ADMINISTRATIVE_SHUTDOWN
            )
        );
        assert_eq!(
            BgpError::new(6, 3),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::PEER_DE_CONFIGURED)
        );
        assert_eq!(
            BgpError::new(6, 4),
            BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::ADMINISTRATIVE_RESET
            )
        );
        assert_eq!(
            BgpError::new(6, 5),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::CONNECTION_REJECTED)
        );
        assert_eq!(
            BgpError::new(6, 6),
            BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::OTHER_CONFIGURATION_CHANGE
            )
        );
        assert_eq!(
            BgpError::new(6, 7),
            BgpError::BgpCeaseNotification(
                BgpCeaseNotificationMessageSubcode::CONNECTION_COLLISION_RESOLUTION
            )
        );
        assert_eq!(
            BgpError::new(6, 8),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::OUT_OF_RESOURCES)
        );
        assert_eq!(
            BgpError::new(6, 9),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::HARD_RESET)
        );
        assert_eq!(
            BgpError::new(6, 10),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::BFD_DOWN)
        );
        assert_eq!(
            BgpError::new(6, 11),
            BgpError::BgpCeaseNotification(BgpCeaseNotificationMessageSubcode::Unknown(11))
        );

        assert_eq!(
            BgpError::new(7, 0),
            BgpError::BgpRouteFreshMessageError(BgpRouteRefreshMessageErrorSubcode::RESERVED)
        );
        assert_eq!(
            BgpError::new(7, 1),
            BgpError::BgpRouteFreshMessageError(
                BgpRouteRefreshMessageErrorSubcode::INVALID_MESSAGE_LENGTH
            )
        );
        assert_eq!(
            BgpError::new(7, 2),
            BgpError::BgpRouteFreshMessageError(BgpRouteRefreshMessageErrorSubcode::Unknown(2))
        );

        assert_eq!(BgpError::new(8, 2), BgpError::Unknown(8, 2));
    }
}
