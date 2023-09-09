use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_update_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::Bytes;
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
    BgpMessage(BgpUpdateMessage),
    Information(RouteMirroringInfo),
}

impl RouteMirroringValue {
    pub const fn mirroring_type(&self) -> RouteMirroringTlvType {
        match self {
            RouteMirroringValue::BgpMessage(_) => RouteMirroringTlvType::BgpMessage,
            RouteMirroringValue::Information(_) => RouteMirroringTlvType::Information,
        }
    }
}

#[derive(Debug, TryFromPrimitive, IntoPrimitive, Hash, Eq, PartialEq)]
#[repr(u16)]
pub enum RouteMirroringTlvType {
    BgpMessage = 0,
    Information = 1,
}

#[derive(Debug, TryFromPrimitive, IntoPrimitive, Hash, Eq, PartialEq)]
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
    while !data.is_empty() {
        match RouteMirroringTlvType::try_from(data.read_u16()?)? {
            RouteMirroringTlvType::BgpMessage => {
                let info_len = data.read_u16()?;
                let bytes = data.split_to(info_len as usize);
                let value = parse_bgp_update_message(bytes, false, asn_len)?;
                tlvs.push(RouteMirroringTlv {
                    info_len,
                    value: RouteMirroringValue::BgpMessage(value),
                });
            }
            RouteMirroringTlvType::Information => {
                let info_len = data.read_u16()?;
                let value = RouteMirroringInfo::try_from(data.read_u16()?)?;
                tlvs.push(RouteMirroringTlv {
                    info_len,
                    value: RouteMirroringValue::Information(value),
                });
            }
        }
    }
    Ok(RouteMirroring { tlvs })
}
