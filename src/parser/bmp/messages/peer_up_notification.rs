use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_open_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use std::net::IpAddr;

#[derive(Debug)]
pub struct PeerUpNotification {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub sent_open: BgpOpenMessage,
    pub received_open: BgpOpenMessage,
    pub tlvs: Vec<PeerUpNotificationTlv>,
}

#[derive(Debug)]
pub struct PeerUpNotificationTlv {
    pub info_type: u16,
    pub info_len: u16,
    pub info_value: String,
}

pub fn parse_peer_up_notification(
    data: &mut &[u8],
    afi: &Afi,
) -> Result<PeerUpNotification, ParserBmpError> {
    let local_addr: IpAddr = match afi {
        Afi::Ipv4 => {
            data.advance(12)?;
            let ip = data.read_ipv4_address()?;
            ip.into()
        }
        Afi::Ipv6 => data.read_ipv6_address()?.into(),
    };

    let local_port = data.read_u16()?;
    let remote_port = data.read_u16()?;

    let sent_open = parse_bgp_open_message(data)?;
    let received_open = parse_bgp_open_message(data)?;
    let mut tlvs = vec![];
    while data.remaining() >= 4 {
        let info_type = data.read_u16()?;
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
