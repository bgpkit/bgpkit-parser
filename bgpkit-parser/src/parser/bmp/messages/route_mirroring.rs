use bgp_models::bgp::BgpUpdateMessage;
use bgp_models::network::AsnLength;
use crate::parser::bgp::messages::parse_bgp_update_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::num_traits::FromPrimitive;
use crate::parser::DataBytes;

#[derive(Debug)]
pub struct RouteMirroring {
    pub tlvs: Vec<RouteMirroringTlv>
}

#[derive(Debug)]
pub struct RouteMirroringTlv {
    pub info_len: u16,
    pub value: RouteMirroringValue
}

#[derive(Debug)]
pub enum RouteMirroringValue {
    BgpMessage(BgpUpdateMessage),
    Information(RouteMirroringInfo),
}

#[derive(Debug, Primitive)]
pub enum RouteMirroringInfo {
    ErroredPdu=0,
    MessageLost=1,
}

pub fn parse_route_mirroring(reader: &mut DataBytes, asn_len: &AsnLength) -> Result<RouteMirroring, ParserBmpError> {
    let mut tlvs = vec![];
    while reader.bytes_left() > 4 {
        match reader.read_16b()? {
            0 => {
                let info_len = reader.read_16b()?;
                let bytes = reader.read_n_bytes(info_len as usize)?;
                let mut data = DataBytes::new(&bytes);
                let value = parse_bgp_update_message(&mut data, false, asn_len, info_len as u64)?;
                tlvs.push(RouteMirroringTlv{ info_len, value: RouteMirroringValue::BgpMessage(value)});
            }
            1 => {
                let info_len = reader.read_16b()?;
                let value = RouteMirroringInfo::from_u16(reader.read_16b()?).unwrap();
                tlvs.push(RouteMirroringTlv{ info_len, value: RouteMirroringValue::Information(value)});
            }
            _ => {return Err(ParserBmpError::CorruptedBmpMessage)}
        }
    }
    Ok(RouteMirroring{
        tlvs
    })
}