use crate::bgp::parse_bgp_message;
use crate::models::*;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::TryFrom;

#[derive(Debug)]
pub struct RouteMirroring {
    pub tlvs: Vec<RouteMirroringTlv>,
}

#[derive(Debug)]
pub struct RouteMirroringTlv {
    pub info_len: u16,
    pub value: RouteMirroringValue,
}

#[derive(Debug)]
pub enum RouteMirroringValue {
    BgpMessage(BgpMessage),
    Information(RouteMirroringInfo),
}

#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum RouteMirroringInfo {
    ErroredPdu = 0,
    MessageLost = 1,
}

pub fn parse_route_mirroring(
    data: &mut Bytes,
    asn_len: &AsnLength,
) -> Result<RouteMirroring, ParserBmpError> {
    let mut tlvs = vec![];
    while data.remaining() > 4 {
        match data.read_u16()? {
            0 => {
                let info_len = data.read_u16()?;
                let mut bytes = data.split_to(info_len as usize);
                let value = parse_bgp_message(&mut bytes, false, asn_len)?;
                tlvs.push(RouteMirroringTlv {
                    info_len,
                    value: RouteMirroringValue::BgpMessage(value),
                });
            }
            1 => {
                let info_len = data.read_u16()?;
                let value = RouteMirroringInfo::try_from(data.read_u16()?)?;
                tlvs.push(RouteMirroringTlv {
                    info_len,
                    value: RouteMirroringValue::Information(value),
                });
            }
            _ => return Err(ParserBmpError::CorruptedBmpMessage),
        }
    }
    Ok(RouteMirroring { tlvs })
}
