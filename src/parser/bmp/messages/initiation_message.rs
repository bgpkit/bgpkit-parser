use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use bytes::{Buf, Bytes};
use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitiationMessage {
    pub tlvs: Vec<InitiationTlv>,
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitiationTlv {
    pub info_type: InitiationTlvType,
    pub info_len: u16,
    pub info: String,
}

/// BMP Initiation Information TLV Type
///
/// <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#initiation-information-tlvs>
///
/// Per RFC 9736, the "BMP Initiation and Peer Up Information TLVs" registry was renamed
/// to "BMP Initiation Information TLVs", and types 3, 4, and 65535 are reserved in this
/// namespace. The VrTableName and AdminLabel variants are retained for backward compatibility
/// with pre-RFC 9736 implementations.
#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum InitiationTlvType {
    String = 0,
    SysDescr = 1,
    SysName = 2,
    /// Reserved per RFC 9736, retained for backward compatibility.
    VrTableName = 3,
    /// Reserved per RFC 9736, retained for backward compatibility.
    AdminLabel = 4,
    #[num_enum(catch_all)]
    Unknown(u16) = 65535,
}

/// Parse BMP initiation message
///
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.3>
pub fn parse_initiation_message(data: &mut Bytes) -> Result<InitiationMessage, ParserBmpError> {
    let mut tlvs = vec![];

    while data.remaining() > 4 {
        let info_type = InitiationTlvType::from(data.read_u16()?);
        let info_len = data.read_u16()?;
        if data.remaining() < info_len as usize {
            // not enough bytes to read
            break;
        }
        let info = data.read_n_bytes_to_string(info_len as usize)?;
        tlvs.push(InitiationTlv {
            info_type,
            info_len,
            info,
        });
    }

    Ok(InitiationMessage { tlvs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_parse_initiation_message() {
        let mut buffer = BytesMut::new();
        buffer.put_u16(1); // InitiationTlvType::SysDescr
        buffer.put_u16(5); // Length of following info
        buffer.put_slice(b"Test1"); // Info

        let mut bytes = buffer.freeze();

        match parse_initiation_message(&mut bytes) {
            Ok(initiation_message) => {
                for tlv in initiation_message.tlvs {
                    assert_eq!(tlv.info_type, InitiationTlvType::SysDescr);
                    assert_eq!(tlv.info_len, 5);
                    assert_eq!(tlv.info, "Test1".to_string());
                }
            }
            Err(_) => panic!("Failed to parse initiation message"),
        }
    }

    #[test]
    fn test_parse_unknown_initiation_tlv() {
        let mut buffer = BytesMut::new();
        // Known TLV (SysDescr)
        buffer.put_u16(1); // InitiationTlvType::SysDescr
        buffer.put_u16(4);
        buffer.put_slice(b"Test");
        // Unknown TLV (unassigned type 255)
        buffer.put_u16(255);
        buffer.put_u16(3);
        buffer.put_slice(b"Foo");

        let mut bytes = buffer.freeze();
        let result = parse_initiation_message(&mut bytes).unwrap();

        assert_eq!(result.tlvs.len(), 2);
        assert_eq!(result.tlvs[0].info_type, InitiationTlvType::SysDescr);
        assert_eq!(result.tlvs[0].info, "Test");
        assert_eq!(result.tlvs[1].info_type, InitiationTlvType::Unknown(255));
        assert_eq!(result.tlvs[1].info_len, 3);
        assert_eq!(result.tlvs[1].info, "Foo");
    }

    #[test]
    fn test_debug() {
        let initiation_message = InitiationMessage {
            tlvs: vec![InitiationTlv {
                info_type: InitiationTlvType::SysDescr,
                info_len: 5,
                info: "Test1".to_string(),
            }],
        };
        assert_eq!(
            format!("{initiation_message:?}"),
            "InitiationMessage { tlvs: [InitiationTlv { info_type: SysDescr, info_len: 5, info: \"Test1\" }] }"
        );
    }
}
