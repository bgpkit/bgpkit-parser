use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};

#[derive(Debug)]
pub struct PeerDownNotification {
    pub reason: u8,
    pub data: Option<Vec<u8>>,
}

pub fn parse_peer_down_notification(
    data: &mut Bytes,
) -> Result<PeerDownNotification, ParserBmpError> {
    let reason = data.read_u8()?;
    let bytes_left = data.remaining();
    let data: Option<Vec<u8>> = match reason {
        1 => {
            /*
            The local system closed the session.  Following the
            Reason is a BGP PDU containing a BGP NOTIFICATION message that
            would have been sent to the peer.
            */
            Some(data.read_n_bytes(bytes_left)?)
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
            Some(data.read_n_bytes(bytes_left)?)
        }
        3 => {
            /*
            The remote system closed the session with a notification
            message.  Following the Reason is a BGP PDU containing the BGP
            NOTIFICATION message as received from the peer.
             */
            Some(data.read_n_bytes(bytes_left)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_parse_peer_down_notification() {
        // Test with reason `1`
        let mut data = bytes::BytesMut::new();
        data.put_u8(1);
        data.put_slice(&[0u8; 10]);
        let mut data = data.freeze();
        let result = parse_peer_down_notification(&mut data);
        assert!(result.is_ok());
        let peer_down_notification = result.unwrap();
        assert_eq!(peer_down_notification.reason, 1);
        assert_eq!(peer_down_notification.data.unwrap(), vec![0u8; 10]);

        // Test with reason `2`
        let mut data = bytes::BytesMut::new();
        data.put_u8(2);
        data.put_slice(&[0u8; 10]);
        let mut data = data.freeze();
        let result = parse_peer_down_notification(&mut data);
        assert!(result.is_ok());
        let peer_down_notification = result.unwrap();
        assert_eq!(peer_down_notification.reason, 2);
        assert_eq!(peer_down_notification.data.unwrap(), vec![0u8; 10]);

        // Test with reason `3`
        let mut data = bytes::BytesMut::new();
        data.put_u8(3);
        data.put_slice(&[0u8; 10]);
        let mut data = data.freeze();
        let result = parse_peer_down_notification(&mut data);
        assert!(result.is_ok());
        let peer_down_notification = result.unwrap();
        assert_eq!(peer_down_notification.reason, 3);
        assert_eq!(peer_down_notification.data.unwrap(), vec![0u8; 10]);

        // Test with reason `4`
        let mut data = bytes::BytesMut::new();
        data.put_u8(4);
        let mut data = data.freeze();
        let result = parse_peer_down_notification(&mut data);
        assert!(result.is_ok());
        let peer_down_notification = result.unwrap();
        assert_eq!(peer_down_notification.reason, 4);
        assert!(peer_down_notification.data.is_none());

        // Test with reason `5`
        let mut data = bytes::BytesMut::new();
        data.put_u8(5);
        let mut data = data.freeze();
        let result = parse_peer_down_notification(&mut data);
        assert!(result.is_ok());
        let peer_down_notification = result.unwrap();
        assert_eq!(peer_down_notification.reason, 5);
        assert!(peer_down_notification.data.is_none());

        // Test with invalid reason
        let mut data = bytes::BytesMut::new();
        data.put_u8(6);
        let mut data = data.freeze();
        let result = parse_peer_down_notification(&mut data);
        assert!(result.is_err());
    }
}
