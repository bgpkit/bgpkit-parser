use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use std::io::Cursor;

#[derive(Debug)]
pub struct PeerDownNotification {
    pub reason: u8,
    pub data: Option<Vec<u8>>,
}

pub fn parse_peer_down_notification(
    reader: &mut Cursor<&[u8]>,
) -> Result<PeerDownNotification, ParserBmpError> {
    let reason = reader.read_8b()?;
    let bytes_left = reader.get_ref().len() - (reader.position() as usize);
    let data: Option<Vec<u8>> = match reason {
        1 => {
            /*
            The local system closed the session.  Following the
            Reason is a BGP PDU containing a BGP NOTIFICATION message that
            would have been sent to the peer.
            */
            Some(reader.read_n_bytes(bytes_left)?)
        }
        2 => {
            /*
            The local system closed the session.  No notification
            message was sent.  Following the reason code is a 2-byte field
            containing the code corresponding to the Finite State Machine
            (FSM) Event that caused the system to close the session (see
            Section 8.1 of [RFC4271]).  Two bytes both set to 0 are used to
            indicate that no relevant Event code is defined.
             */
            Some(reader.read_n_bytes(bytes_left)?)
        }
        3 => {
            /*
            The remote system closed the session with a notification
            message.  Following the Reason is a BGP PDU containing the BGP
            NOTIFICATION message as received from the peer.
             */
            Some(reader.read_n_bytes(bytes_left)?)
        }
        4 => {
            /*
            The remote system closed the session without a
            notification message.  This includes any unexpected termination of
            the transport session, so in some cases both the local and remote
            systems might consider this to apply.
             */
            None
        }
        5 => {
            /*
            Information for this peer will no longer be sent to the
            monitoring station for configuration reasons.  This does not,
            strictly speaking, indicate that the peer has gone down, but it
            does indicate that the monitoring station will not receive updates
            for the peer.
             */
            None
        }
        _ => return Err(ParserBmpError::CorruptedBmpMessage),
    };
    Ok(PeerDownNotification { reason, data })
}
