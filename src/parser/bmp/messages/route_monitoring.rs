use bgp_models::bgp::BgpMessage;
use bgp_models::network::AsnLength;
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::DataBytes;

#[derive(Debug)]
pub struct RouteMonitoring {
    pub bgp_message: BgpMessage
}

pub fn parse_route_monitoring(reader: &mut DataBytes, asn_len: &AsnLength) -> Result<RouteMonitoring, ParserBmpError> {
    // let bgp_update = parse_bgp_update_message(reader, false, afi, asn_len, total_len)?;
    let bgp_update = parse_bgp_message(reader, false, asn_len, reader.bytes_left())?;
    Ok(RouteMonitoring{
        bgp_message: bgp_update
    })
}