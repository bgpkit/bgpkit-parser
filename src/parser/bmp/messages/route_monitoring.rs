use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::bmp::error::ParserBmpError;

#[derive(Debug)]
pub struct RouteMonitoring {
    pub bgp_message: BgpMessage,
}

pub fn parse_route_monitoring(
    data: &mut &[u8],
    asn_len: &AsnLength,
) -> Result<RouteMonitoring, ParserBmpError> {
    // let bgp_update = parse_bgp_update_message(reader, false, afi, asn_len, total_len)?;
    let bgp_update = parse_bgp_message(data, false, asn_len)?;
    Ok(RouteMonitoring {
        bgp_message: bgp_update,
    })
}
