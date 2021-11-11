use std::io::Read;
use bgp_models::bgp::BgpMessage;
use bgp_models::network::{Afi, AsnLength};
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::bmp::error::ParserBmpError;

#[derive(Debug)]
pub struct RouteMonitoring {
    pub bgp_update: BgpMessage
}

pub fn parse_route_monitoring<T: Read>(reader: &mut T, afi: &Afi, asn_len: &AsnLength, total_len: u64) -> Result<RouteMonitoring, ParserBmpError> {
    // let bgp_update = parse_bgp_update_message(reader, false, afi, asn_len, total_len)?;
    let bgp_update = parse_bgp_message(reader, false, afi, asn_len, total_len as usize)?;
    Ok(RouteMonitoring{
        bgp_update
    })
}