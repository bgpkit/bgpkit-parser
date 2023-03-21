use crate::parser::bgp::messages::parse_bgp_open_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bgp_models::prelude::*;
use std::io::{Cursor, Seek, SeekFrom};
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
    reader: &mut Cursor<&[u8]>,
    afi: &Afi,
) -> Result<PeerUpNotification, ParserBmpError> {
    let local_addr: IpAddr = match afi {
        Afi::Ipv4 => {
            reader.seek(SeekFrom::Current(12))?;
            let ip = reader.read_ipv4_address()?;
            ip.into()
        }
        Afi::Ipv6 => reader.read_ipv6_address()?.into(),
    };

    let local_port = reader.read_16b()?;
    let remote_port = reader.read_16b()?;

    let sent_open = parse_bgp_open_message(reader)?;
    let received_open = parse_bgp_open_message(reader)?;
    let mut tlvs = vec![];
    let total = reader.get_ref().len() as u64;
    while total - reader.position() >= 4 {
        let info_type = reader.read_16b()?;
        let info_len = reader.read_16b()?;
        let info_value = reader.read_n_bytes_to_string(info_len as usize)?;
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
