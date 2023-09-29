use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Hash, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum PeerDownReason {
    /// The local system closed the session.  Following the reason is a BGP PDU containing a BGP
    /// NOTIFICATION message that would have been sent to the peer.
    LocalSystemClosedSession = 1,
    /// The local system closed the session.  No notification message was sent.  Following the
    /// reason code is a 2-byte field containing the code corresponding to the Finite State Machine
    /// (FSM) Event that caused the system to close the session (see Section 8.1 of [RFC4271]).  Two
    /// bytes both set to 0 are used to indicate that no relevant Event code is defined.
    LocalSystemClosedSessionWithoutNotification = 2,
    /// The remote system closed the session with a notification message.  Following the Reason is a
    /// BGP PDU containing the BGP NOTIFICATION message as received from the peer.
    RemoteSystemClosedSession = 3,
    /// The remote system closed the session without a notification message.  This includes any
    /// unexpected termination of the transport session, so in some cases both the local and remote
    /// systems might consider this to apply.
    RemoteSystemClosedSessionWithoutNotification = 4,
    /// Information for this peer will no longer be sent to the monitoring station for configuration
    /// reasons.  This does not, strictly speaking, indicate that the peer has gone down, but it
    /// does indicate that the monitoring station will not receive updates for the peer.
    DisabledDueToConfig = 5,
}

#[derive(Debug)]
pub struct PeerDownNotification {
    pub reason: PeerDownReason,
    pub data: Option<Vec<u8>>,
}

pub fn parse_peer_down_notification(
    data: &mut Bytes,
) -> Result<PeerDownNotification, ParserBmpError> {
    let reason = PeerDownReason::try_from(data.read_u8()?)?;
    let bytes_left = data.remaining();
    let data = match reason {
        PeerDownReason::LocalSystemClosedSession => Some(data.read_n_bytes(bytes_left)?),
        PeerDownReason::LocalSystemClosedSessionWithoutNotification => {
            Some(data.read_n_bytes(bytes_left)?)
        }
        PeerDownReason::RemoteSystemClosedSession => Some(data.read_n_bytes(bytes_left)?),
        PeerDownReason::RemoteSystemClosedSessionWithoutNotification => None,
        PeerDownReason::DisabledDueToConfig => None,
    };
    Ok(PeerDownNotification { reason, data })
}
