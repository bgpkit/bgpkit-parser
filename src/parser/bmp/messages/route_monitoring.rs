use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::bmp::messages::BmpPeerType;
use bytes::Bytes;
use log::warn;

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RouteMonitoring {
    pub bgp_message: BgpMessage,
}

pub fn parse_route_monitoring(
    data: &mut Bytes,
    asn_len: &AsnLength,
    peer_type: Option<&BmpPeerType>,
) -> Result<RouteMonitoring, ParserBmpError> {
    // RFC 9069: Local RIB MUST use 4-byte ASN encoding
    if let Some(BmpPeerType::LocalRib) = peer_type {
        if *asn_len != AsnLength::Bits32 {
            warn!("RFC 9069 violation: Local RIB route monitoring MUST use 4-byte ASN encoding");
        }
    }

    let bgp_update = parse_bgp_message(data, false, asn_len)?;
    Ok(RouteMonitoring {
        bgp_message: bgp_update,
    })
}

impl RouteMonitoring {
    /// Check if the BMP route-monitoring message is an End-of-RIB marker.
    pub fn is_end_of_rib(&self) -> bool {
        if let BgpMessage::Update(u) = &self.bgp_message {
            u.is_end_of_rib()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_of_rib() {
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: Attributes::default(),
            announced_prefixes: vec![],
        };
        assert!(msg.is_end_of_rib());

        let mon_msg = RouteMonitoring {
            bgp_message: BgpMessage::Update(msg),
        };
        assert!(mon_msg.is_end_of_rib());

        let mon_msg = RouteMonitoring {
            bgp_message: BgpMessage::KeepAlive,
        };
        assert!(!mon_msg.is_end_of_rib());
    }

    #[test]
    fn test_debug() {
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: Attributes::default(),
            announced_prefixes: vec![],
        };
        let mon_msg = RouteMonitoring {
            bgp_message: BgpMessage::Update(msg),
        };
        assert_eq!(
            format!("{mon_msg:?}"),
            "RouteMonitoring { bgp_message: Update(BgpUpdateMessage { withdrawn_prefixes: [], attributes: Attributes { inner: [] }, announced_prefixes: [] }) }"
        );
    }
}
