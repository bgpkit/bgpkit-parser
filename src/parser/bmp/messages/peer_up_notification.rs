use crate::bgp::parse_bgp_message;
use crate::models::*;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::net::IpAddr;

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerUpNotification {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub sent_open: BgpMessage,
    pub received_open: BgpMessage,
    pub tlvs: Vec<PeerUpNotificationTlv>,
}

///Type-Length-Value Type
///
/// https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#initiation-peer-up-tlvs
#[derive(Debug, TryFromPrimitive, IntoPrimitive, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum PeerUpTlvType {
    String = 0,
    SysDescr = 1,
    SysName = 2,
    VrTableName = 3,
    AdminLabel = 4,
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerUpNotificationTlv {
    pub info_type: PeerUpTlvType,
    pub info_len: u16,
    pub info_value: String,
}

pub fn parse_peer_up_notification(
    data: &mut Bytes,
    afi: &Afi,
    asn_len: &AsnLength,
) -> Result<PeerUpNotification, ParserBmpError> {
    let local_addr: IpAddr = match afi {
        Afi::Ipv4 => {
            data.advance(12);
            let ip = data.read_ipv4_address()?;
            ip.into()
        }
        Afi::Ipv6 => data.read_ipv6_address()?.into(),
    };

    let local_port = data.read_u16()?;
    let remote_port = data.read_u16()?;

    let sent_open = parse_bgp_message(data, false, asn_len)?;
    let received_open = parse_bgp_message(data, false, asn_len)?;
    // let received_open = parse_bgp_open_message(data)?;
    let mut tlvs = vec![];
    while data.remaining() >= 4 {
        let info_type = PeerUpTlvType::try_from(data.read_u16()?)?;
        let info_len = data.read_u16()?;
        let info_value = data.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(PeerUpNotificationTlv {
            info_type,
            info_len,
            info_value,
        })
    }
    Ok(PeerUpNotification {
        local_addr,
        local_port,
        remote_port,
        sent_open,
        received_open,
        tlvs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_parse_peer_up_notification() {
        let mut data = BytesMut::new();
        // Assuming setup for test where local address is "10.1.1.1" IPv4
        // local port is 8000, remote port is 9000. Adjust accordingly.
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x01,
            0x01, 0x01,
        ]);
        data.extend_from_slice(&[0x1F, 0x40]); // 8000 in network byte order
        data.extend_from_slice(&[0x23, 0x28]); // 9000 in network byte order

        let bgp_open_message = crate::models::BgpMessage::Open(BgpOpenMessage {
            version: 0,
            asn: Default::default(),
            hold_time: 0,
            sender_ip: Ipv4Addr::new(0, 0, 0, 0),
            extended_length: false,
            opt_params: vec![],
        });
        let bgp_open_message_bytes = bgp_open_message.encode(false, AsnLength::Bits32);
        data.extend_from_slice(&bgp_open_message_bytes);
        data.extend_from_slice(&bgp_open_message_bytes);

        // add tlv
        data.extend_from_slice(&[0x00, 0x01]); // info_type
        data.extend_from_slice(&[0x00, 0x02]); // info_len
        data.extend_from_slice(&[0x00, 0x03]); // info_value

        let afi = Afi::Ipv4;
        let asn_len = AsnLength::Bits32;

        let result = parse_peer_up_notification(&mut data.freeze(), &afi, &asn_len);

        match result {
            Ok(peer_notification) => {
                assert_eq!(
                    peer_notification.local_addr,
                    IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1))
                );
                assert_eq!(peer_notification.local_port, 8000);
                assert_eq!(peer_notification.remote_port, 9000);

                // Continue to check other values from peer_notification like sent_open, received_open, tlvs
                let tlv = peer_notification.tlvs.first().unwrap();
                assert_eq!(tlv.info_type, PeerUpTlvType::SysDescr);
                assert_eq!(tlv.info_len, 2);
                assert_eq!(tlv.info_value, "\u{0}\u{3}");
            }
            Err(_) => {
                panic!("parse_peer_up_notification should return Ok");
            }
        }
    }
}
