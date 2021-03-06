use std::net::IpAddr;
use bgp_models::bgp::BgpOpenMessage;
use bgp_models::network::Afi;
use crate::parser::bgp::messages::parse_bgp_open_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::DataBytes;

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

pub fn parse_peer_up_notification(reader: &mut DataBytes, afi: &Afi) -> Result<PeerUpNotification, ParserBmpError> {
    let local_addr: IpAddr = match afi {
        Afi::Ipv4 => {
            reader.read_and_drop_n_bytes(12)?;
            let ip= reader.read_ipv4_address()?;
            ip.into()
        }
        Afi::Ipv6 => {
            reader.read_ipv6_address()?.into()
        }
    };

    let local_port = reader.read_16b()?;
    let remote_port = reader.read_16b()?;
    let sent_open = parse_bgp_open_message(reader)?;
    let received_open = parse_bgp_open_message(reader)?;
    let mut tlvs = vec![];
    while reader.bytes_left()>=4 {
        let info_type = reader.read_16b()?;
        let info_len = reader.read_16b()?;
        let info_value = reader.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(PeerUpNotificationTlv{
            info_type,
            info_len,
            info_value
        })
    }
    Ok(
        PeerUpNotification{
            local_addr,
            local_port,
            remote_port,
            sent_open,
            received_open,
            tlvs
        }
    )
}