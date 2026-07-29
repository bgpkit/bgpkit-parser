use crate::models::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;
use std::net::Ipv4Addr;

use crate::error::{BgpValidationWarning, EncodingError, ParserError};
use crate::models::capabilities::{
    AddPathCapability, BgpCapabilityType, BgpExtendedMessageCapability, BgpRoleCapability,
    ExtendedNextHopCapability, FourOctetAsCapability, GracefulRestartCapability,
    MultiprotocolExtensionsCapability, RouteRefreshCapability,
};
use crate::models::error::BgpError;
use crate::parser::bgp::attributes::parse_attributes;
use crate::parser::{encode_nlri_prefixes, parse_nlri_list, ReadUtils};
use log::warn;
use zerocopy::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// On-wire BGP OPEN fixed header layout (10 bytes, network byte order).
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct RawBgpOpenHeader {
    version: u8,
    asn: U16,
    hold_time: U16,
    bgp_identifier: U32,
    opt_params_len: u8,
}

const _: () = assert!(size_of::<RawBgpOpenHeader>() == 10);

pub(crate) fn read_and_validate_bgp_marker(data: &mut Bytes) -> Result<(), ParserError> {
    data.has_n_remaining(16)?;

    let mut marker = [0u8; 16];
    data.copy_to_slice(&mut marker);
    if marker != [0xFF; 16] {
        warn!("BGP message marker is not all 0xFF bytes (invalid per RFC 4271)");
    }

    Ok(())
}

/// BGP message
///
/// Format:
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                           Marker                              |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Length               |      Type     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_bgp_message(
    data: &mut Bytes,
    add_path: bool,
    asn_len: &AsnLength,
) -> Result<BgpMessage, ParserError> {
    let total_size = data.len();
    data.has_n_remaining(19)?;
    read_and_validate_bgp_marker(data)?;

    /*
    This 2-octet unsigned integer indicates the total length of the
    message, including the header in octets.  Thus, it allows one
    to locate the (Marker field of the) next message in the TCP
    stream.  The value of the Length field MUST always be at least
    19 and no greater than 4096, and MAY be further constrained,
    depending on the message type.  "padding" of extra data after
    the message is not allowed.  Therefore, the Length field MUST
    have the smallest value required, given the rest of the
    message.
    */
    let length = data.read_u16()?;

    // Validate message length according to RFC 8654
    // For now, we allow extended messages for all message types except when we know
    // for certain that extended messages are not supported.
    // RFC 8654: Extended messages up to 65535 bytes are allowed for all message types
    // except OPEN and KEEPALIVE (which remain limited to 4096 bytes).
    // However, since we're parsing MRT data without session context, we'll be permissive.
    let max_length = 65535; // RFC 8654 maximum
    if !(19..=max_length).contains(&length) {
        return Err(ParserError::ParseError(format!(
            "invalid BGP message length {length}"
        )));
    }

    // Validate length >= 19 before any arithmetic to prevent underflow
    let length_usize = length as usize;
    let bgp_msg_length = if length_usize > total_size {
        total_size.saturating_sub(19)
    } else {
        length_usize.saturating_sub(19)
    };

    let msg_type: BgpMessageType = match BgpMessageType::try_from(data.read_u8()?) {
        Ok(t) => t,
        Err(_) => {
            return Err(ParserError::ParseError(
                "Unknown BGP Message Type".to_string(),
            ))
        }
    };

    // Additional validation for OPEN and KEEPALIVE messages per RFC 8654
    // These message types cannot exceed 4096 bytes even with extended message capability
    match msg_type {
        BgpMessageType::OPEN | BgpMessageType::KEEPALIVE => {
            if length > 4096 {
                return Err(ParserError::ParseError(format!(
                    "BGP {} message length {} exceeds maximum allowed 4096 bytes (RFC 8654)",
                    match msg_type {
                        BgpMessageType::OPEN => "OPEN",
                        BgpMessageType::KEEPALIVE => "KEEPALIVE",
                        _ => unreachable!(),
                    },
                    length
                )));
            }
        }
        BgpMessageType::UPDATE | BgpMessageType::NOTIFICATION => {
            // These can be extended messages up to 65535 bytes when capability is negotiated
            // Since we're parsing MRT data, we allow extended lengths
        }
    }

    if data.remaining() != bgp_msg_length {
        warn!(
            "BGP message length {} does not match the actual length {} (parsing BGP message)",
            bgp_msg_length,
            data.remaining()
        );
    }
    data.has_n_remaining(bgp_msg_length)?;
    let mut msg_data = data.split_to(bgp_msg_length);

    Ok(match msg_type {
        BgpMessageType::OPEN => BgpMessage::Open(parse_bgp_open_message(&mut msg_data)?),
        BgpMessageType::UPDATE => {
            BgpMessage::Update(parse_bgp_update_message(msg_data, add_path, asn_len)?)
        }
        BgpMessageType::NOTIFICATION => {
            BgpMessage::Notification(parse_bgp_notification_message(msg_data)?)
        }
        BgpMessageType::KEEPALIVE => BgpMessage::KeepAlive,
    })
}

/// Parse BGP NOTIFICATION message.
///
/// The BGP NOTIFICATION messages contains BGP error codes received from a connected BGP router. The
/// error code is parsed into [BgpError] data structure and any unknown codes will produce warning
/// messages, but not critical errors.
///
pub fn parse_bgp_notification_message(
    mut input: Bytes,
) -> Result<BgpNotificationMessage, ParserError> {
    let error_code = input.read_u8()?;
    let error_subcode = input.read_u8()?;

    Ok(BgpNotificationMessage {
        error: BgpError::new(error_code, error_subcode),
        data: input.read_n_bytes(input.len())?,
    })
}

impl BgpNotificationMessage {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let (code, subcode) = self.error.get_codes();
        buf.put_u8(code);
        buf.put_u8(subcode);
        buf.put_slice(&self.data);
        buf.freeze()
    }
}

/// Parse BGP OPEN message.
///
/// The parsing of BGP OPEN message also includes decoding the BGP capabilities.
///
/// RFC 4271: <https://datatracker.ietf.org/doc/html/rfc4271>
/// ```text
///       0                   1                   2                   3
///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+
///       |    Version    |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |     My Autonomous System      |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |           Hold Time           |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                         BGP Identifier                        |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       | Opt Parm Len  |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                                                               |
///       |             Optional Parameters (variable)                    |
///       |                                                               |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///       0                   1
///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
///       |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
/// ```
pub fn parse_bgp_open_message(input: &mut Bytes) -> Result<BgpOpenMessage, ParserError> {
    input.has_n_remaining(10)?;
    let mut header_bytes = [0u8; 10];
    input.copy_to_slice(&mut header_bytes);
    // Single bounds check via zerocopy instead of five sequential cursor reads.
    let raw = RawBgpOpenHeader::ref_from_bytes(&header_bytes)
        .expect("header_bytes is exactly 10 bytes with no alignment requirement");

    let version = raw.version;
    let asn = Asn::new_16bit(raw.asn.get());
    let hold_time = raw.hold_time.get();
    let bgp_identifier = Ipv4Addr::from(raw.bgp_identifier.get());
    let mut opt_params_len: u16 = raw.opt_params_len as u16;

    let mut extended_length = false;
    let mut first = true;

    let mut params: Vec<OptParam> = vec![];
    while input.remaining() >= 2 {
        let mut param_type = input.read_u8()?;
        if first {
            if opt_params_len == 0 && param_type == 255 {
                return Err(ParserError::ParseError(
                    "RFC 9072 violation: Non-Extended Optional Parameters Length must not be 0 when using extended format".to_string()
                ));
            }
            // first parameter, check if it is extended length message
            if opt_params_len != 0 && param_type == 255 {
                // RFC 9072: https://datatracker.ietf.org/doc/rfc9072/
                //
                // 0                   1                   2                   3
                // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                //     +-+-+-+-+-+-+-+-+
                //     |    Version    |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |     My Autonomous System      |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |           Hold Time           |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |                         BGP Identifier                        |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |Non-Ext OP Len.|Non-Ext OP Type|  Extended Opt. Parm. Length   |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //     |                                                               |
                //     |             Optional Parameters (variable)                    |
                //     |                                                               |
                //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                //
                //         Figure 1: Extended Encoding OPEN Format
                extended_length = true;
                opt_params_len = input.read_u16()?;
                if opt_params_len == 0 {
                    break;
                }
                // let pos_end = input.position() + opt_params_len as u64;
                if input.remaining() != opt_params_len as usize {
                    warn!(
                    "BGP open message length {} does not match the actual length {} (parsing BGP OPEN message)",
                    opt_params_len,
                    input.remaining()
                );
                }

                param_type = input.read_u8()?;
            }
            first = false;
        }
        // reaching here means all the remain params are regular non-extended-length parameters

        let param_len = match extended_length {
            true => input.read_u16()?,
            false => input.read_u8()? as u16,
        };

        // https://tools.ietf.org/html/rfc3392
        // https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11

        let param_value = match param_type {
            2 => {
                let mut capacities = vec![];

                // Split off only the bytes for this parameter to avoid consuming other parameters
                input.has_n_remaining(param_len as usize)?;
                let mut param_data = input.split_to(param_len as usize);

                while param_data.remaining() >= 2 {
                    // capability codes:
                    // https://www.iana.org/assignments/capability-codes/capability-codes.xhtml#capability-codes-2
                    let code = param_data.read_u8()?;
                    let len = param_data.read_u8()? as u16; // Capability length is ALWAYS 1 byte per RFC 5492

                    let capability_data = param_data.read_n_bytes(len as usize)?;
                    let capability_type = BgpCapabilityType::from(code);

                    // Parse specific capability types with fallback to raw bytes
                    macro_rules! parse_capability {
                        ($parser:path, $variant:ident) => {
                            match $parser(Bytes::from(capability_data.clone())) {
                                Ok(parsed) => CapabilityValue::$variant(parsed),
                                Err(_) => CapabilityValue::Raw(capability_data),
                            }
                        };
                    }

                    let capability_value = match capability_type {
                        BgpCapabilityType::MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4 => {
                            parse_capability!(
                                MultiprotocolExtensionsCapability::parse,
                                MultiprotocolExtensions
                            )
                        }
                        BgpCapabilityType::ROUTE_REFRESH_CAPABILITY_FOR_BGP_4 => {
                            parse_capability!(RouteRefreshCapability::parse, RouteRefresh)
                        }
                        BgpCapabilityType::EXTENDED_NEXT_HOP_ENCODING => {
                            parse_capability!(ExtendedNextHopCapability::parse, ExtendedNextHop)
                        }
                        BgpCapabilityType::GRACEFUL_RESTART_CAPABILITY => {
                            parse_capability!(GracefulRestartCapability::parse, GracefulRestart)
                        }
                        BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY => {
                            parse_capability!(FourOctetAsCapability::parse, FourOctetAs)
                        }
                        BgpCapabilityType::ADD_PATH_CAPABILITY => {
                            parse_capability!(AddPathCapability::parse, AddPath)
                        }
                        BgpCapabilityType::BGP_ROLE => {
                            parse_capability!(BgpRoleCapability::parse, BgpRole)
                        }
                        BgpCapabilityType::BGP_EXTENDED_MESSAGE => {
                            parse_capability!(
                                BgpExtendedMessageCapability::parse,
                                BgpExtendedMessage
                            )
                        }
                        _ => CapabilityValue::Raw(capability_data),
                    };

                    capacities.push(Capability {
                        ty: capability_type,
                        value: capability_value,
                    });
                }

                ParamValue::Capacities(capacities)
            }
            _ => {
                // unsupported param, read as raw bytes
                let bytes = input.read_n_bytes(param_len as usize)?;
                ParamValue::Raw(bytes)
            }
        };
        params.push(OptParam {
            param_type,
            param_value,
        });
    }

    Ok(BgpOpenMessage {
        version,
        asn,
        hold_time,
        bgp_identifier,
        extended_length,
        opt_params: params,
    })
}

fn encode_bgp_open_param_value(param: &OptParam) -> Result<Bytes, EncodingError> {
    let mut buf = BytesMut::new();
    match &param.param_value {
        ParamValue::Capacities(capacities) => {
            for cap in capacities {
                buf.put_u8(cap.ty.into());
                let encoded_value = match &cap.value {
                    CapabilityValue::MultiprotocolExtensions(mp) => mp.encode(),
                    CapabilityValue::RouteRefresh(rr) => rr.encode(),
                    CapabilityValue::ExtendedNextHop(enh) => enh.encode(),
                    CapabilityValue::GracefulRestart(gr) => gr.encode(),
                    CapabilityValue::FourOctetAs(foa) => foa.encode(),
                    CapabilityValue::AddPath(ap) => ap.encode(),
                    CapabilityValue::BgpRole(br) => br.encode(),
                    CapabilityValue::BgpExtendedMessage(bem) => bem.encode(),
                    CapabilityValue::Raw(raw) => Bytes::from(raw.clone()),
                };
                let capability_len = u8::try_from(encoded_value.len()).map_err(|_| {
                    EncodingError::ValueTooLarge {
                        field: "BGP capability value length",
                        actual: encoded_value.len(),
                        max: u8::MAX as usize,
                    }
                })?;
                buf.put_u8(capability_len);
                buf.put_slice(&encoded_value);
            }
        }
        ParamValue::Raw(bytes) => buf.put_slice(bytes),
    }
    Ok(buf.freeze())
}

impl BgpOpenMessage {
    /// Fallible encoding: returns [`EncodingError`] when a value is too large
    /// for its wire-format field instead of panicking or silently truncating.
    pub fn try_encode(&self) -> Result<Bytes, EncodingError> {
        let mut encoded_params: Vec<(u8, Bytes)> = Vec::with_capacity(self.opt_params.len());
        for param in &self.opt_params {
            encoded_params.push((param.param_type, encode_bgp_open_param_value(param)?));
        }

        let values_len: usize = encoded_params.iter().map(|(_, value)| value.len()).sum();
        // Non-extended framing spends 2 header octets (type + 1-octet length) per
        // parameter; if that would overflow the single-octet aggregate length field
        // we must switch to RFC 9072 extended framing (3 header octets each).
        let non_extended_params_len = 2 * encoded_params.len() + values_len;
        let use_extended_length =
            self.extended_length || non_extended_params_len > u8::MAX as usize;
        let per_param_header = if use_extended_length { 3 } else { 2 };
        let encoded_params_len = per_param_header * encoded_params.len() + values_len;

        let mut buf = BytesMut::with_capacity(
            size_of::<RawBgpOpenHeader>()
                + encoded_params_len
                + if use_extended_length { 3 } else { 0 },
        );
        let raw_header = RawBgpOpenHeader {
            version: self.version,
            asn: U16::new(self.asn.into()),
            hold_time: U16::new(self.hold_time),
            bgp_identifier: U32::new(u32::from(self.bgp_identifier)),
            opt_params_len: if use_extended_length {
                u8::MAX
            } else {
                // GUARANTEED by use_extended_length logic: non_extended_params_len <= u8::MAX
                // and encoded_params_len == non_extended_params_len when not extended.
                encoded_params_len as u8
            },
        };
        buf.extend_from_slice(raw_header.as_bytes());

        if use_extended_length {
            // RFC 9072: type 255 signals a two-octet aggregate length and
            // two-octet lengths for each optional parameter.
            let agg_len =
                u16::try_from(encoded_params_len).map_err(|_| EncodingError::ValueTooLarge {
                    field: "BGP OPEN extended optional parameters total length",
                    actual: encoded_params_len,
                    max: u16::MAX as usize,
                })?;
            buf.put_u8(u8::MAX);
            buf.put_u16(agg_len);
        }

        for (param_type, value) in encoded_params {
            buf.put_u8(param_type);
            if use_extended_length {
                let val_len =
                    u16::try_from(value.len()).map_err(|_| EncodingError::ValueTooLarge {
                        field: "BGP OPEN extended optional parameter length",
                        actual: value.len(),
                        max: u16::MAX as usize,
                    })?;
                buf.put_u16(val_len);
            } else {
                // Fits in a u8: use_extended_length is set above whenever the
                // non-extended framing (2 + value.len() per param) would exceed u8::MAX.
                debug_assert!(value.len() <= u8::MAX as usize);
                buf.put_u8(value.len() as u8);
            }
            buf.put_slice(&value);
        }
        Ok(buf.freeze())
    }

    /// Infinitely convenient infallible encoding wrapper.
    ///
    /// Panics if encoding fails (e.g. oversized capability values). For
    /// untrusted input use [`BgpOpenMessage::try_encode`] instead.
    pub fn encode(&self) -> Bytes {
        self.try_encode()
            .expect("BGP OPEN encoding failed; use try_encode() for fallible handling")
    }
}

/// read nlri portion of a bgp update message.
///
/// Returns `Ok(vec![])` for empty NLRI. Returns `Err` for malformed NLRI
/// (invalid prefix lengths, truncated data), so that the caller
/// in `parse_bgp_update_message` can convert it to a `MalformedNlri` warning.
fn read_nlri(input: Bytes, afi: &Afi, add_path: bool) -> Result<Vec<NetworkPrefix>, ParserError> {
    let length = input.len();
    if length == 0 {
        return Ok(vec![]);
    }
    if length == 1 && input[0] != 0 {
        // A single non-zero byte cannot be a valid NLRI: a valid 1-byte NLRI
        // encodes only the default route (prefix length 0, no prefix octets).
        warn!("seeing strange one-byte NLRI field (parsing NLRI in BGP UPDATE message)");
        return Err(ParserError::ParseError(
            "one-byte NLRI field with non-zero value is not a valid encoding".to_string(),
        ));
    }

    parse_nlri_list(input, add_path, afi)
}

/// read bgp update message.
///
/// RFC: <https://tools.ietf.org/html/rfc4271#section-4.3>
///
/// Per RFC 7606, NLRI parse errors are non-fatal: the message is returned with
/// partial data and a [`BgpValidationWarning::MalformedNlri`] appended to
/// `attributes.validation_warnings`. Callers that want RFC 7606 treat-as-withdrawal
/// semantics can inspect the warnings and act accordingly. Attribute-section
/// framing errors (wrong length fields, truncated data) remain fatal.
pub fn parse_bgp_update_message(
    mut input: Bytes,
    add_path: bool,
    asn_len: &AsnLength,
) -> Result<BgpUpdateMessage, ParserError> {
    // NOTE: AFI for routes outside attributes are IPv4 ONLY.
    let afi = Afi::Ipv4;

    // parse withdrawn prefixes NLRI
    let withdrawn_bytes_length_raw = input.read_u16()?;
    let withdrawn_bytes_length = withdrawn_bytes_length_raw as usize;
    input.has_n_remaining(withdrawn_bytes_length)?;
    let withdrawn_bytes = input.split_to(withdrawn_bytes_length);
    let (withdrawn_prefixes, withdrawn_nlri_error) =
        match read_nlri(withdrawn_bytes.clone(), &afi, add_path) {
            Ok(pfxs) => (pfxs, None),
            Err(e) => (
                Vec::new(),
                Some(BgpValidationWarning::MalformedNlri {
                    nlri_type: "withdrawn",
                    reason: e.to_string(),
                    raw_bytes: withdrawn_bytes.to_vec(),
                }),
            ),
        };

    // parse attributes
    let attribute_length_raw = input.read_u16()?;
    // Defensive check: ensure attribute_length fits in usize
    // u16 to usize conversion is always safe on 32/64-bit platforms,
    // but this check ensures safety on all architectures
    let attribute_length = attribute_length_raw as usize;

    input.has_n_remaining(attribute_length)?;
    let attr_data_slice = input.split_to(attribute_length);
    let mut attributes = parse_attributes(attr_data_slice, asn_len, add_path, None, None, None)?;

    // parse announced prefixes nlri.
    // the remaining bytes are announced prefixes.
    let announced_bytes_present = !input.is_empty();
    let (announced_prefixes, announced_nlri_error) = match read_nlri(input.clone(), &afi, add_path)
    {
        Ok(pfxs) => (pfxs, None),
        Err(e) => (
            Vec::new(),
            Some(BgpValidationWarning::MalformedNlri {
                nlri_type: "announced",
                reason: e.to_string(),
                raw_bytes: input.to_vec(),
            }),
        ),
    };

    // validate mandatory attributes.
    // Use `announced_bytes_present` (wire-level) rather than
    // `!announced_prefixes.is_empty()` (parse result) so that a malformed
    // NLRI section still triggers mandatory-attribute validation — the
    // UPDATE clearly intended to announce routes.
    let is_announcement =
        announced_bytes_present || attributes.has_attr(AttrType::MP_REACHABLE_NLRI);
    let has_standard_nlri = announced_bytes_present;
    attributes.check_mandatory_attributes(is_announcement, has_standard_nlri);

    // Attach NLRI parse warnings (RFC 7606 §5.3 treat-as-withdrawal evidence)
    if let Some(w) = withdrawn_nlri_error {
        attributes.add_validation_warning(w);
    }
    if let Some(w) = announced_nlri_error {
        attributes.add_validation_warning(w);
    }

    Ok(BgpUpdateMessage {
        withdrawn_prefixes,
        attributes,
        announced_prefixes,
    })
}

impl BgpUpdateMessage {
    /// Fallible encoding: returns [`EncodingError`] when a value is too large
    /// for its wire-format field instead of silently truncating.
    pub fn try_encode(&self, asn_len: AsnLength) -> Result<Bytes, EncodingError> {
        let mut bytes = BytesMut::new();

        // withdrawn prefixes
        let withdrawn_bytes = encode_nlri_prefixes(&self.withdrawn_prefixes);
        let w_len =
            u16::try_from(withdrawn_bytes.len()).map_err(|_| EncodingError::ValueTooLarge {
                field: "BGP UPDATE withdrawn prefixes length",
                actual: withdrawn_bytes.len(),
                max: u16::MAX as usize,
            })?;
        bytes.put_u16(w_len);
        bytes.put_slice(&withdrawn_bytes);

        // attributes
        let attr_bytes = self.attributes.try_encode(asn_len)?;
        let a_len = u16::try_from(attr_bytes.len()).map_err(|_| EncodingError::ValueTooLarge {
            field: "BGP UPDATE path attributes length",
            actual: attr_bytes.len(),
            max: u16::MAX as usize,
        })?;
        bytes.put_u16(a_len);
        bytes.put_slice(&attr_bytes);

        bytes.extend(encode_nlri_prefixes(&self.announced_prefixes));
        Ok(bytes.freeze())
    }

    pub fn encode(&self, asn_len: AsnLength) -> Bytes {
        self.try_encode(asn_len)
            .expect("BGP UPDATE encoding failed; use try_encode() for fallible handling")
    }

    /// Check if this is an end-of-rib message.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc4724#section-2>
    /// End-of-rib message is a special update message that contains no NLRI or withdrawal NLRI prefixes.
    pub fn is_end_of_rib(&self) -> bool {
        // there are two cases for end-of-rib message:
        // 1. IPv4 unicast address family: no announced, no withdrawn, no attributes
        // 2. Other cases: no announced, no withdrawal, only MP_UNREACH_NRLI with no prefixes

        if !self.announced_prefixes.is_empty() || !self.withdrawn_prefixes.is_empty() {
            // has announced or withdrawal IPv4 unicast prefixes:
            // definitely not end-of-rib

            return false;
        }

        if self.attributes.inner.is_empty() {
            // no attributes, no prefixes:
            // case 1 end-of-rib
            return true;
        }

        // has some attributes, it can only be withdrawal with no prefixes

        if self.attributes.inner.len() > 1 {
            // has more than one attributes, not end-of-rib
            return false;
        }

        // has only one attribute, check if it is withdrawal attribute
        if let AttributeValue::MpUnreachNlri(nlri) = &self.attributes.inner.first().unwrap().value {
            if nlri.prefixes.is_empty() {
                // the only attribute is MP_UNREACH_NLRI with no prefixes:
                // case 2 end-of-rib
                return true;
            }
        }

        // all other cases: not end-of-rib
        false
    }
}

impl BgpMessage {
    /// BGP marker value: 16 bytes of 0xFF (RFC 4271)
    const MARKER: [u8; 16] = [0xFF; 16];

    /// Fallible encoding: returns [`EncodingError`] when a value is too large
    /// for its wire-format field.
    pub fn try_encode(&self, asn_len: AsnLength) -> Result<Bytes, EncodingError> {
        let mut bytes = BytesMut::new();
        // RFC 4271: Marker is 16 bytes of 0xFF
        bytes.put_slice(&Self::MARKER);

        let (msg_type, msg_bytes) = match self {
            BgpMessage::Open(msg) => (BgpMessageType::OPEN, msg.try_encode()?),
            BgpMessage::Update(msg) => (BgpMessageType::UPDATE, msg.try_encode(asn_len)?),
            BgpMessage::Notification(msg) => (BgpMessageType::NOTIFICATION, msg.encode()),
            BgpMessage::KeepAlive => (BgpMessageType::KEEPALIVE, Bytes::new()),
        };

        // msg total bytes length = msg bytes + 16 bytes marker + 2 bytes length + 1 byte type
        let total = msg_bytes.len() + 16 + 2 + 1;
        let total_u16 = u16::try_from(total).map_err(|_| EncodingError::ValueTooLarge {
            field: "BGP message total length",
            actual: total,
            max: u16::MAX as usize,
        })?;
        bytes.put_u16(total_u16);
        bytes.put_u8(msg_type as u8);
        bytes.put_slice(&msg_bytes);
        Ok(bytes.freeze())
    }

    pub fn encode(&self, asn_len: AsnLength) -> Bytes {
        self.try_encode(asn_len)
            .expect("BGP message encoding failed; use try_encode() for fallible handling")
    }
}

impl From<&BgpElem> for BgpUpdateMessage {
    fn from(elem: &BgpElem) -> Self {
        BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: Attributes::from(elem),
            announced_prefixes: vec![],
        }
    }
}

impl From<BgpUpdateMessage> for BgpMessage {
    fn from(value: BgpUpdateMessage) -> Self {
        BgpMessage::Update(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_end_of_rib() {
        // No prefixes and empty attributes: end-of-rib
        let attrs = Attributes::default();
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(msg.is_end_of_rib());

        // single MP_UNREACH_NLRI attribute with no prefixes: end-of-rib
        let attrs = Attributes::from_iter(vec![AttributeValue::MpUnreachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(msg.is_end_of_rib());

        // message with announced prefixes
        let prefix = NetworkPrefix::from_str("192.168.1.0/24").unwrap();
        let attrs = Attributes::default();
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![prefix],
        };
        assert!(!msg.is_end_of_rib());

        // message with withdrawn prefixes
        let prefix = NetworkPrefix::from_str("192.168.1.0/24").unwrap();
        let attrs = Attributes::default();
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![prefix],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // NLRI attribute with empty prefixes: NOT end-of-rib
        let attrs = Attributes::from_iter(vec![AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // NLRI attribute with non-empty prefixes
        let attrs = Attributes::from_iter(vec![AttributeValue::MpReachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![prefix],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // Unreachable NLRI attribute with non-empty prefixes
        let attrs = Attributes::from_iter(vec![AttributeValue::MpUnreachNlri(Nlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: None,
            prefixes: vec![prefix],
            labeled_prefixes: None,
            link_state_nlris: None,
            flowspec_nlris: None,
        })]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());

        // message with more than one attributes
        let attrs = Attributes::from_iter(vec![
            AttributeValue::MpUnreachNlri(Nlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: None,
                prefixes: vec![],
                labeled_prefixes: None,
                link_state_nlris: None,
                flowspec_nlris: None,
            }),
            AttributeValue::AtomicAggregate,
        ]);
        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: vec![],
        };
        assert!(!msg.is_end_of_rib());
    }

    #[test]
    fn test_invlaid_length() {
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, // length
            0x05, // type
        ]);
        let mut data = bytes.clone();
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_err());

        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x28, // length
            0x05, // type
        ]);
        let mut data = bytes.clone();
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_err());
    }

    #[test]
    fn test_invlaid_type() {
        let bytes = Bytes::from_static(&[
            0xFF, 0xFF, 0xFF, 0xFF, // marker (valid RFC 4271)
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0x00, 0x28, // length
            0x05, // type
        ]);
        let mut data = bytes.clone();
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_err());
    }

    #[test]
    fn test_bgp_message_length_underflow_protection() {
        // Test that length values less than 19 are properly rejected
        // without causing arithmetic underflow
        for len in [0u16, 1, 18] {
            let bytes = Bytes::from(vec![
                0xFF,
                0xFF,
                0xFF,
                0xFF, // marker
                0xFF,
                0xFF,
                0xFF,
                0xFF, // marker
                0xFF,
                0xFF,
                0xFF,
                0xFF, // marker
                0xFF,
                0xFF,
                0xFF,
                0xFF, // marker
                (len >> 8) as u8,
                (len & 0xFF) as u8, // length field
                0x01,               // type = OPEN
            ]);
            let mut data = bytes.clone();
            let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
            assert!(
                result.is_err(),
                "Length {} should be rejected as invalid",
                len
            );
        }
    }

    #[test]
    fn test_bgp_marker_encoding_rfc4271() {
        // Test that BgpMessage::encode produces correct RFC 4271 marker (all 0xFF)
        let msg = BgpMessage::KeepAlive;
        let encoded = msg.encode(AsnLength::Bits16);

        // First 16 bytes should be all 0xFF
        assert_eq!(
            &encoded[..16],
            &[0xFF; 16],
            "BGP marker should be all 0xFF bytes"
        );
    }

    #[test]
    fn test_bgp_marker_validation() {
        // Test that message with valid marker (all 0xFF) parses correctly
        let valid_bytes = Bytes::from(vec![
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0xFF, 0xFF, 0xFF, 0xFF, // marker
            0x00, 0x13, // length = 19 (minimum)
            0x04, // type = KEEPALIVE
        ]);
        let mut data = valid_bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        assert!(result.is_ok(), "Valid marker should parse successfully");

        // Test that message with invalid marker (all zeros) is handled
        // Parser should warn but still process (for MRT compatibility)
        let invalid_bytes = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x00, // marker (invalid - should be 0xFF)
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x13, // length = 19
            0x04, // type = KEEPALIVE
        ]);
        let mut data = invalid_bytes.clone();
        // Should still parse (with warning) for compatibility
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        assert!(
            result.is_ok(),
            "Invalid marker should still parse (with warning)"
        );
    }

    #[test]
    fn test_attribute_length_overflow_protection() {
        // Test that large attribute length values are handled correctly
        // without causing overflow issues

        // Create a BGP UPDATE message with attribute_length that exceeds available data
        let update_bytes = Bytes::from(vec![
            0x00, 0x00, // withdrawn length = 0
            0xFF,
            0xFF, // attribute length = 65535 (largest u16, but not enough data)
                  // No actual attribute data follows
        ]);

        let result = parse_bgp_update_message(update_bytes, false, &AsnLength::Bits16);
        assert!(
            result.is_err(),
            "Should fail when attribute_length exceeds available data"
        );
        assert!(
            matches!(result, Err(ParserError::TruncatedMsg(_))),
            "Should fail with TruncatedMsg error"
        );

        // Test valid attribute length parsing
        let valid_update = Bytes::from(vec![
            0x00, 0x00, // withdrawn length = 0
            0x00,
            0x00, // attribute length = 0
                  // No attributes, valid empty UPDATE
        ]);
        let result = parse_bgp_update_message(valid_update, false, &AsnLength::Bits16);
        assert!(result.is_ok(), "Should parse valid empty UPDATE");
    }

    #[test]
    fn test_parse_bgp_notification_message() {
        let bytes = Bytes::from_static(&[
            0x01, // error code
            0x02, // error subcode
            0x00, 0x00, // data
        ]);
        let msg = parse_bgp_notification_message(bytes).unwrap();
        matches!(
            msg.error,
            BgpError::MessageHeaderError(MessageHeaderError::BAD_MESSAGE_LENGTH)
        );
        assert_eq!(msg.data, Bytes::from_static(&[0x00, 0x00]));
    }

    #[test]
    fn test_encode_bgp_notification_messsage() {
        let msg = BgpNotificationMessage {
            error: BgpError::MessageHeaderError(MessageHeaderError::BAD_MESSAGE_LENGTH),
            data: vec![0x00, 0x00],
        };
        let bytes = msg.encode();
        assert_eq!(bytes, Bytes::from_static(&[0x01, 0x02, 0x00, 0x00]));
    }

    #[test]
    fn test_parse_bgp_open_message() {
        let bytes = Bytes::from_static(&[
            0x04, // version
            0x00, 0x01, // asn
            0x00, 0xb4, // hold time
            0xc0, 0x00, 0x02, 0x01, // sender ip
            0x00, // opt params length
        ]);
        let msg = parse_bgp_open_message(&mut bytes.clone()).unwrap();
        assert_eq!(msg.version, 4);
        assert_eq!(msg.asn, Asn::new_16bit(1));
        assert_eq!(msg.hold_time, 180);
        assert_eq!(msg.bgp_identifier, Ipv4Addr::new(192, 0, 2, 1));
        assert!(!msg.extended_length);
        assert_eq!(msg.opt_params.len(), 0);
    }

    #[test]
    fn test_encode_bgp_open_message() {
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(1),
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![],
        };
        let bytes = msg.encode();
        assert_eq!(
            bytes,
            Bytes::from_static(&[
                0x04, // version
                0x00, 0x01, // asn
                0x00, 0xb4, // hold time
                0xc0, 0x00, 0x02, 0x01, // sender ip
                0x00, // opt params length
            ])
        );
    }

    #[test]
    fn test_bgp_open_wire_fixtures_round_trip_byte_identically() {
        // test vectors from sessions with RIS RRC00
        let fixtures = [
            (
                "no optional parameters",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF001D01",
                "048826005A02380BFE00",
                0x00,
            ),
            (
                "two capability parameters",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF002501",
                "045BA0005A66433801080202800002020200",
                0x08,
            ),
            (
                "five capability parameters",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003901",
                "04947100B4CBD0B16E1C02060104000200010202800002020200020246000206410400009471",
                0x1C,
            ),
            (
                "one 22-byte capability parameter",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003501",
                "045BA000F05D9FBB0118021601040001000102004002007841040003215C46004700",
                0x18,
            ),
            (
                "one 26-byte capability parameter",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003901",
                "045BA0012CB901A6321C021A0104000100010200400600780001010041040003167D46004700",
                0x1C,
            ),
        ];

        for (name, header, body, expected_opt_params_len) in fixtures {
            let wire = Bytes::from(hex::decode(format!("{header}{body}")).unwrap());
            assert_eq!(wire[28], expected_opt_params_len, "{name}");

            let mut input = wire.clone();
            let parsed =
                parse_bgp_message(&mut input, false, &AsnLength::Bits16).unwrap_or_else(|error| {
                    panic!("failed to parse {name}: {error}");
                });
            let encoded = parsed.encode(AsnLength::Bits16);

            assert_eq!(encoded, wire, "{name}");
        }
    }

    #[test]
    fn test_bgp_open_encoding_recomputes_parameter_lengths() {
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64512),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 254,
                param_value: ParamValue::Raw(vec![0xAA, 0xBB, 0xCC]),
            }],
        };

        let encoded = msg.encode();

        assert_eq!(encoded[9], 5);
        assert_eq!(&encoded[10..], &[254, 3, 0xAA, 0xBB, 0xCC]);
        let parsed = parse_bgp_open_message(&mut encoded.clone()).unwrap();
        assert_eq!(parsed.encode(), encoded);
    }

    #[test]
    fn test_bgp_open_encoding_rejects_oversized_add_path_capability() {
        use crate::models::capabilities::{AddPathAddressFamily, AddPathSendReceive};

        let address_family = AddPathAddressFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathSendReceive::SendReceive,
        };
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64512),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 2,
                param_value: ParamValue::Capacities(vec![Capability {
                    ty: BgpCapabilityType::ADD_PATH_CAPABILITY,
                    value: CapabilityValue::AddPath(AddPathCapability::new(vec![
                        address_family;
                        64
                    ])),
                }]),
            }],
        };

        // try_encode returns Err instead of panicking
        let result = msg.try_encode();
        assert!(
            result.is_err(),
            "try_encode should reject oversized capability"
        );
        match result.unwrap_err() {
            crate::error::EncodingError::ValueTooLarge { field, actual, max } => {
                assert!(field.contains("capability value length"), "field: {field}");
                assert_eq!(max, 255);
                assert!(actual > 255, "actual={actual}");
            }
        }

        // encode() (infallible wrapper) panics with a helpful message
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            msg.encode();
        }));
        assert!(
            result.is_err(),
            "encode() should panic on oversized capability"
        );
    }

    #[test]
    fn test_bgp_open_forced_extended_parameter_encoding() {
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64512),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: true,
            opt_params: vec![OptParam {
                param_type: 254,
                param_value: ParamValue::Raw(vec![0xAA, 0xBB]),
            }],
        };

        let encoded = msg.encode();

        assert_eq!(
            &encoded[9..],
            &[0xFF, 0xFF, 0x00, 0x05, 254, 0x00, 0x02, 0xAA, 0xBB]
        );
        let parsed = parse_bgp_open_message(&mut encoded.clone()).unwrap();
        assert!(parsed.extended_length);
        assert_eq!(parsed.encode(), encoded);
    }

    #[test]
    fn test_bgp_open_automatically_uses_extended_parameter_encoding() {
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64512),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 254,
                param_value: ParamValue::Raw(vec![0xAA; 256]),
            }],
        };

        let encoded = msg.encode();

        assert_eq!(encoded.len(), 272);
        assert_eq!(&encoded[9..16], &[0xFF, 0xFF, 0x01, 0x03, 254, 0x01, 0x00]);
        let parsed = parse_bgp_open_message(&mut encoded.clone()).unwrap();
        assert!(parsed.extended_length);
        assert_eq!(parsed.encode(), encoded);
    }

    #[test]
    fn test_fallible_encoding_as_path_overflow() {
        // An AS_PATH segment with >255 ASes overflows the 1-octet segment-length
        // field. Before the fix this silently truncated; now try_encode returns Err.
        let path = AsPath::from_sequence((1u32..=300).collect::<Vec<_>>());
        let attr = Attribute {
            flag: AttrFlags::TRANSITIVE,
            value: AttributeValue::AsPath { path, is_as4: true },
        };

        let result = attr.try_encode(AsnLength::Bits32);
        assert!(
            result.is_err(),
            "try_encode should reject AS_PATH with >255 ASes"
        );
    }

    #[test]
    fn test_fallible_encoding_open_raw_capability_oversize() {
        // A CapabilityValue::Raw with >255 bytes should fail gracefully via
        // try_encode, not panic.
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64512),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 2,
                param_value: ParamValue::Capacities(vec![Capability {
                    ty: BgpCapabilityType::Unknown(99),
                    value: CapabilityValue::Raw(vec![0xAA; 300]),
                }]),
            }],
        };

        assert!(msg.try_encode().is_err());
    }

    #[test]
    fn test_fallible_encoding_open_extended_param_oversize() {
        // An OPEN with extended-length params that exceed u16::MAX should fail.
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(64512),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: true,
            opt_params: vec![OptParam {
                param_type: 254,
                param_value: ParamValue::Raw(vec![0xBB; 70000]),
            }],
        };

        let result = msg.try_encode();
        assert!(
            result.is_err(),
            "try_encode should reject oversized extended param"
        );
    }

    #[test]
    fn test_fallible_encoding_update_attributes_oversize() {
        // An UPDATE whose total attributes exceed u16::MAX should fail.
        use crate::models::{AttrFlags, AttrRaw, Attribute, AttributeValue};

        // Each Raw attribute is 4 bytes header + 1000 bytes value = 1004 bytes.
        // 70 of them ≈ 70280 bytes > 65535.
        let attrs: Vec<Attribute> = (0..70)
            .map(|_| Attribute {
                flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
                value: AttributeValue::Raw(AttrRaw {
                    code: 200,
                    bytes: vec![0; 1000].into(),
                }),
            })
            .collect();

        let msg = BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: Attributes {
                inner: attrs,
                validation_warnings: vec![],
                attr_mask: [0; 4],
            },
            announced_prefixes: vec![],
        };

        let result = msg.try_encode(AsnLength::Bits32);
        assert!(
            result.is_err(),
            "try_encode should reject oversized UPDATE attributes"
        );
    }

    #[test]
    fn test_encode_bgp_notification_message() {
        let bgp_message = BgpMessage::Notification(BgpNotificationMessage {
            error: BgpError::MessageHeaderError(MessageHeaderError::BAD_MESSAGE_LENGTH),
            data: vec![0x00, 0x00],
        });
        let bytes = bgp_message.encode(AsnLength::Bits16);
        // RFC 4271: Marker is 16 bytes of 0xFF
        assert_eq!(
            bytes,
            Bytes::from_static(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // marker (8 bytes)
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // marker (8 bytes)
                0x00, 0x17, // length = 23 (16 marker + 2 len + 1 type + 4 msg)
                0x03, // type = NOTIFICATION
                0x01, 0x02, // error code, subcode
                0x00, 0x00 // data
            ])
        );
    }

    #[test]
    fn test_bgp_message_from_bgp_update_message() {
        let msg = BgpMessage::from(BgpUpdateMessage::default());
        assert!(matches!(msg, BgpMessage::Update(_)));
    }

    #[test]
    fn test_parse_bgp_open_message_with_extended_next_hop_capability() {
        use crate::models::{Afi, Safi};

        // BGP OPEN message with Extended Next Hop capability - RFC 8950, Section 3
        // Version=4, ASN=65001, HoldTime=180, BGP-ID=192.0.2.1
        // One capability: Extended Next Hop (type=5) with two entries:
        // 1) IPv4 Unicast (AFI=1, SAFI=1) can use IPv6 NextHop (AFI=2)
        // 2) IPv4 MPLS VPN (AFI=1, SAFI=128) can use IPv6 NextHop (AFI=2)
        let bytes = Bytes::from(vec![
            0x04, // version
            0xfd, 0xe9, // asn = 65001
            0x00, 0xb4, // hold time = 180
            0xc0, 0x00, 0x02, 0x01, // sender ip = 192.0.2.1
            0x10, // opt params length = 16
            0x02, // param type = 2 (capability)
            0x0e, // param length = 14
            0x05, // capability type = 5 (Extended Next Hop)
            0x0c, // capability length = 12 (2 entries * 6 bytes each)
            0x00, 0x01, // NLRI AFI = 1 (IPv4)
            0x00, 0x01, // NLRI SAFI = 1 (Unicast)
            0x00, 0x02, // NextHop AFI = 2 (IPv6)
            0x00, 0x01, // NLRI AFI = 1 (IPv4) - second entry
            0x00, 0x80, // NLRI SAFI = 128 (MPLS VPN)
            0x00, 0x02, // NextHop AFI = 2 (IPv6)
        ]);

        let msg = parse_bgp_open_message(&mut bytes.clone()).unwrap();
        assert_eq!(msg.version, 4);
        assert_eq!(msg.asn, Asn::new_16bit(65001));
        assert_eq!(msg.hold_time, 180);
        assert_eq!(msg.bgp_identifier, Ipv4Addr::new(192, 0, 2, 1));
        assert!(!msg.extended_length);
        assert_eq!(msg.opt_params.len(), 1);

        // Check the capability
        if let ParamValue::Capacities(cap) = &msg.opt_params[0].param_value {
            assert_eq!(cap[0].ty, BgpCapabilityType::EXTENDED_NEXT_HOP_ENCODING);

            if let CapabilityValue::ExtendedNextHop(enh_cap) = &cap[0].value {
                assert_eq!(enh_cap.entries.len(), 2);

                // Check first entry: IPv4 Unicast can use IPv6 NextHop
                let entry1 = &enh_cap.entries[0];
                assert_eq!(entry1.nlri_afi, Afi::Ipv4);
                assert_eq!(entry1.nlri_safi, Safi::Unicast);
                assert_eq!(entry1.nexthop_afi, Afi::Ipv6);

                // Check second entry: IPv4 MPLS VPN can use IPv6 NextHop
                let entry2 = &enh_cap.entries[1];
                assert_eq!(entry2.nlri_afi, Afi::Ipv4);
                assert_eq!(entry2.nlri_safi, Safi::MplsVpn);
                assert_eq!(entry2.nexthop_afi, Afi::Ipv6);

                // Test functionality
                assert!(enh_cap.supports(Afi::Ipv4, Safi::Unicast, Afi::Ipv6));
                assert!(enh_cap.supports(Afi::Ipv4, Safi::MplsVpn, Afi::Ipv6));
                assert!(!enh_cap.supports(Afi::Ipv4, Safi::Multicast, Afi::Ipv6));
            } else {
                panic!("Expected ExtendedNextHop capability value");
            }
        } else {
            panic!("Expected capability parameter");
        }
    }

    #[test]
    fn test_rfc8654_extended_message_length_validation() {
        // Test valid extended UPDATE message (within 65535 limit)
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x13, 0x00, // length = 4864 (0x1300) (extended message)
            0x02, // type = UPDATE
            0x00, 0x00, // withdrawn length = 0
            0x00,
            0x00, // path attribute length = 0
                  // No NLRI data needed for this test
        ]);
        let mut data = bytes.clone();
        // This should succeed because UPDATE messages can be extended
        assert!(parse_bgp_message(&mut data, false, &AsnLength::Bits16).is_ok());

        // Test OPEN message exceeding 4096 bytes (should fail)
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x13, 0x00, // length = 4864 (0x1300) (exceeds 4096 for OPEN)
            0x01, // type = OPEN
        ]);
        let mut data = bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        assert!(result.is_err());
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(msg.contains("BGP OPEN message length"));
            assert!(msg.contains("4096 bytes"));
        }

        // Test KEEPALIVE message exceeding 4096 bytes (should fail)
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x13, 0x00, // length = 4864 (0x1300) (exceeds 4096 for KEEPALIVE)
            0x04, // type = KEEPALIVE
        ]);
        let mut data = bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        assert!(result.is_err());
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(msg.contains("BGP KEEPALIVE message length"));
            assert!(msg.contains("4096 bytes"));
        }

        // Test message exceeding 65535 bytes (maximum allowed)
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0xFF, 0xFF, // length = 65535 (0xFFFF) (maximum allowed)
            0x02, // type = UPDATE
        ]);
        let mut data = bytes.clone();
        // This might fail due to insufficient data, but should not fail on length validation
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        if let Err(ParserError::ParseError(msg)) = result {
            // Should not be a length validation error
            assert!(!msg.contains("invalid BGP message length"));
        }
    }

    #[test]
    fn test_bgp_extended_message_capability_parsing() {
        use crate::models::CapabilityValue;

        // Test BGP OPEN message with Extended Message capability (capability code 6)
        let bytes = Bytes::from(vec![
            0x04, // version
            0x00, 0x01, // asn
            0x00, 0xb4, // hold time
            0xc0, 0x00, 0x02, 0x01, // sender ip
            0x04, // opt params length = 4
            0x02, // param type = 2 (capability)
            0x02, // param length = 2
            0x06, // capability type = 6 (Extended Message)
            0x00, // capability length = 0 (no parameters)
        ]);

        let msg = parse_bgp_open_message(&mut bytes.clone()).unwrap();
        assert_eq!(msg.version, 4);
        assert_eq!(msg.asn, Asn::new_16bit(1));
        assert_eq!(msg.opt_params.len(), 1);

        // Check that we have the extended message capability
        if let ParamValue::Capacities(cap) = &msg.opt_params[0].param_value {
            assert_eq!(cap[0].ty, BgpCapabilityType::BGP_EXTENDED_MESSAGE);
            if let CapabilityValue::BgpExtendedMessage(_) = &cap[0].value {
                // Extended Message capability should have no parameters
            } else {
                panic!("Expected BgpExtendedMessage capability value");
            }
        } else {
            panic!("Expected capability parameter");
        }
    }

    #[test]
    fn test_rfc8654_edge_cases() {
        // Test NOTIFICATION message with extended length (should be allowed)
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x20, 0x00, // length = 8192 (extended NOTIFICATION message)
            0x03, // type = NOTIFICATION
            0x06, // error code (Cease)
            0x00, // error subcode
                  // Additional data would go here
        ]);
        let mut data = bytes.clone();
        // This should succeed because NOTIFICATION messages can be extended
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        // May fail due to insufficient data, but not due to length validation
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(!msg.contains("invalid BGP message length"));
            assert!(!msg.contains("exceeds maximum allowed 4096 bytes"));
        }

        // Test message exactly at 4096 bytes for OPEN (should be allowed)
        let open_data = vec![
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x10, 0x00, // length = 4096 (exactly at limit for OPEN)
            0x01, // type = OPEN
        ];
        let bytes = Bytes::from(open_data);
        let mut data = bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        // Should not fail on length validation (may fail on parsing due to insufficient data)
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(!msg.contains("exceeds maximum allowed 4096 bytes"));
        }

        // Test message exactly at 65535 bytes for UPDATE (should be allowed)
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0xFF, 0xFF, // length = 65535 (0xFFFF) (maximum allowed)
            0x02, // type = UPDATE
        ]);
        let mut data = bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        // Should not fail on length validation
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(!msg.contains("invalid BGP message length"));
        }
    }

    #[test]
    fn test_rfc8654_capability_encoding_path() {
        use crate::models::capabilities::BgpExtendedMessageCapability;

        // Test that the encoding path for BgpExtendedMessage capability is covered
        // This specifically tests the line: CapabilityValue::BgpExtendedMessage(bem) => bem.encode()
        let capability_value =
            CapabilityValue::BgpExtendedMessage(BgpExtendedMessageCapability::new());
        let capability = Capability {
            ty: BgpCapabilityType::BGP_EXTENDED_MESSAGE,
            value: capability_value,
        };

        let opt_param = OptParam {
            param_type: 2, // capability
            param_value: ParamValue::Capacities(vec![capability]),
        };

        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(65001),
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![opt_param],
        };

        // This will exercise the encoding path we need to test
        let encoded = msg.encode();
        assert!(!encoded.is_empty());

        // Verify we can parse it back (exercises the parsing path too)
        let parsed = parse_bgp_open_message(&mut encoded.clone()).unwrap();
        assert_eq!(parsed.opt_params.len(), 1);
        if let ParamValue::Capacities(cap) = &parsed.opt_params[0].param_value {
            assert_eq!(cap[0].ty, BgpCapabilityType::BGP_EXTENDED_MESSAGE);
        }
    }

    #[test]
    fn test_rfc8654_error_message_formatting() {
        // Test the error message formatting paths that include message type names
        // This tests the match arms for OPEN and KEEPALIVE in error messages

        // Test OPEN message error path
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x20, 0x01, // length = 8193 (exceeds 4096 for OPEN)
            0x01, // type = OPEN
        ]);
        let mut data = bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        assert!(result.is_err());
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(msg.contains("BGP OPEN message length"));
            assert!(msg.contains("exceeds maximum allowed 4096 bytes"));
        }

        // Test KEEPALIVE message error path
        let bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x00, 0x00, 0x00, 0x00, // marker
            0x20, 0x01, // length = 8193 (exceeds 4096 for KEEPALIVE)
            0x04, // type = KEEPALIVE
        ]);
        let mut data = bytes.clone();
        let result = parse_bgp_message(&mut data, false, &AsnLength::Bits16);
        assert!(result.is_err());
        if let Err(ParserError::ParseError(msg)) = result {
            assert!(msg.contains("BGP KEEPALIVE message length"));
            assert!(msg.contains("exceeds maximum allowed 4096 bytes"));
        }
    }

    #[test]
    fn test_encode_bgp_open_message_with_extended_message_capability() {
        use crate::models::capabilities::BgpExtendedMessageCapability;

        // Create Extended Message capability
        let extended_msg_capability = BgpExtendedMessageCapability::new();

        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(65001),
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 2, // capability
                param_value: ParamValue::Capacities(vec![Capability {
                    ty: BgpCapabilityType::BGP_EXTENDED_MESSAGE,
                    value: CapabilityValue::BgpExtendedMessage(extended_msg_capability),
                }]),
            }],
        };

        let encoded = msg.encode();

        // Parse the encoded message back and verify it matches
        let parsed = parse_bgp_open_message(&mut encoded.clone()).unwrap();
        assert_eq!(parsed.version, msg.version);
        assert_eq!(parsed.asn, msg.asn);
        assert_eq!(parsed.hold_time, msg.hold_time);
        assert_eq!(parsed.bgp_identifier, msg.bgp_identifier);
        assert_eq!(parsed.opt_params.len(), 1);

        // Verify the capability was encoded and parsed correctly
        if let ParamValue::Capacities(cap) = &parsed.opt_params[0].param_value {
            assert_eq!(cap[0].ty, BgpCapabilityType::BGP_EXTENDED_MESSAGE);
            if let CapabilityValue::BgpExtendedMessage(_) = &cap[0].value {
                // Extended Message capability should have no parameters
            } else {
                panic!("Expected BgpExtendedMessage capability value after round trip");
            }
        } else {
            panic!("Expected capability parameter after round trip");
        }
    }

    #[test]
    fn test_encode_bgp_open_message_with_extended_next_hop_capability() {
        use crate::models::capabilities::{ExtendedNextHopCapability, ExtendedNextHopEntry};
        use crate::models::{Afi, Safi};

        // Create Extended Next Hop capability
        let entries = vec![
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                nexthop_afi: Afi::Ipv6,
            },
            ExtendedNextHopEntry {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::MplsVpn,
                nexthop_afi: Afi::Ipv6,
            },
        ];
        let enh_capability = ExtendedNextHopCapability::new(entries);

        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_16bit(65001),
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 2, // capability
                param_value: ParamValue::Capacities(vec![Capability {
                    ty: BgpCapabilityType::EXTENDED_NEXT_HOP_ENCODING,
                    value: CapabilityValue::ExtendedNextHop(enh_capability),
                }]),
            }],
        };

        let encoded = msg.encode();

        // Parse the encoded message back and verify it matches
        let parsed = parse_bgp_open_message(&mut encoded.clone()).unwrap();
        assert_eq!(parsed.version, msg.version);
        assert_eq!(parsed.asn, msg.asn);
        assert_eq!(parsed.hold_time, msg.hold_time);
        assert_eq!(parsed.bgp_identifier, msg.bgp_identifier);
        assert_eq!(parsed.extended_length, msg.extended_length);
        assert_eq!(parsed.opt_params.len(), 1);

        // Verify the capability was encoded and parsed correctly
        if let ParamValue::Capacities(cap) = &parsed.opt_params[0].param_value {
            assert_eq!(cap[0].ty, BgpCapabilityType::EXTENDED_NEXT_HOP_ENCODING);
            if let CapabilityValue::ExtendedNextHop(enh_cap) = &cap[0].value {
                assert_eq!(enh_cap.entries.len(), 2);
                assert!(enh_cap.supports(Afi::Ipv4, Safi::Unicast, Afi::Ipv6));
                assert!(enh_cap.supports(Afi::Ipv4, Safi::MplsVpn, Afi::Ipv6));
            } else {
                panic!("Expected ExtendedNextHop capability value after round trip");
            }
        } else {
            panic!("Expected capability parameter after round trip");
        }
    }

    #[test]
    fn test_parse_bgp_open_message_with_multiple_capabilities() {
        // Create a BGP OPEN message with multiple capabilities in a single optional parameter
        // This tests RFC 5492 support for multiple capabilities per parameter

        // Build capabilities: Extended Message, Route Refresh, and 4-octet AS
        let extended_msg_cap = Capability {
            ty: BgpCapabilityType::BGP_EXTENDED_MESSAGE,
            value: CapabilityValue::BgpExtendedMessage(BgpExtendedMessageCapability {}),
        };

        let route_refresh_cap = Capability {
            ty: BgpCapabilityType::ROUTE_REFRESH_CAPABILITY_FOR_BGP_4,
            value: CapabilityValue::RouteRefresh(RouteRefreshCapability {}),
        };

        let four_octet_as_cap = Capability {
            ty: BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY,
            value: CapabilityValue::FourOctetAs(FourOctetAsCapability { asn: 65536 }),
        };

        // Create OPEN message with all three capabilities in one parameter
        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_32bit(65000),
            hold_time: 180,
            bgp_identifier: "10.0.0.1".parse().unwrap(),
            extended_length: false,
            opt_params: vec![OptParam {
                param_type: 2, // capability
                param_value: ParamValue::Capacities(vec![
                    extended_msg_cap,
                    route_refresh_cap,
                    four_octet_as_cap,
                ]),
            }],
        };

        // Encode the message
        let encoded = msg.encode();

        // Parse it back
        let mut encoded_bytes = encoded.clone();
        let parsed = parse_bgp_open_message(&mut encoded_bytes).unwrap();

        // Verify basic fields
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.asn, Asn::new_32bit(65000));
        assert_eq!(parsed.hold_time, 180);
        assert_eq!(
            parsed.bgp_identifier,
            "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(parsed.opt_params.len(), 1);

        // Verify we have all three capabilities
        if let ParamValue::Capacities(caps) = &parsed.opt_params[0].param_value {
            assert_eq!(caps.len(), 3, "Should have 3 capabilities");

            // Check first capability: Extended Message
            assert_eq!(caps[0].ty, BgpCapabilityType::BGP_EXTENDED_MESSAGE);
            assert!(matches!(
                caps[0].value,
                CapabilityValue::BgpExtendedMessage(_)
            ));

            // Check second capability: Route Refresh
            assert_eq!(
                caps[1].ty,
                BgpCapabilityType::ROUTE_REFRESH_CAPABILITY_FOR_BGP_4
            );
            assert!(matches!(caps[1].value, CapabilityValue::RouteRefresh(_)));

            // Check third capability: 4-octet AS
            assert_eq!(
                caps[2].ty,
                BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY
            );
            if let CapabilityValue::FourOctetAs(foa) = &caps[2].value {
                assert_eq!(foa.asn, 65536);
            } else {
                panic!("Expected FourOctetAs capability value");
            }
        } else {
            panic!("Expected Capacities parameter");
        }
    }

    #[test]
    fn test_parse_bgp_open_message_with_multiple_capability_parameters() {
        // Test parsing OPEN message with multiple optional parameters, each containing capabilities
        // This is less common but still valid per RFC 5492

        let msg = BgpOpenMessage {
            version: 4,
            asn: Asn::new_32bit(65001),
            hold_time: 90,
            bgp_identifier: "192.168.1.1".parse().unwrap(),
            extended_length: false,
            opt_params: vec![
                OptParam {
                    param_type: 2, // capability
                    param_value: ParamValue::Capacities(vec![Capability {
                        ty: BgpCapabilityType::BGP_EXTENDED_MESSAGE,
                        value: CapabilityValue::BgpExtendedMessage(BgpExtendedMessageCapability {}),
                    }]),
                },
                OptParam {
                    param_type: 2, // capability
                    param_value: ParamValue::Capacities(vec![Capability {
                        ty: BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY,
                        value: CapabilityValue::FourOctetAs(FourOctetAsCapability {
                            asn: 4200000000,
                        }),
                    }]),
                },
            ],
        };

        // Encode and parse back
        let encoded = msg.encode();
        let mut encoded_bytes = encoded.clone();
        let parsed = parse_bgp_open_message(&mut encoded_bytes).unwrap();

        // Verify we have 2 optional parameters
        assert_eq!(parsed.opt_params.len(), 2);

        // Check first parameter
        if let ParamValue::Capacities(caps) = &parsed.opt_params[0].param_value {
            assert_eq!(caps.len(), 1);
            assert_eq!(caps[0].ty, BgpCapabilityType::BGP_EXTENDED_MESSAGE);
        } else {
            panic!("Expected Capacities in first parameter");
        }

        // Check second parameter
        if let ParamValue::Capacities(caps) = &parsed.opt_params[1].param_value {
            assert_eq!(caps.len(), 1);
            assert_eq!(
                caps[0].ty,
                BgpCapabilityType::SUPPORT_FOR_4_OCTET_AS_NUMBER_CAPABILITY
            );
            if let CapabilityValue::FourOctetAs(foa) = &caps[0].value {
                assert_eq!(foa.asn, 4200000000);
            }
        } else {
            panic!("Expected Capacities in second parameter");
        }
    }

    #[test]
    fn test_encoding_error_tunnel_encap_subtlv_oversize() {
        use crate::models::tunnel_encap::{
            SubTlv, SubTlvType, TunnelEncapAttribute, TunnelEncapTlv,
        };

        let encap = TunnelEncapAttribute {
            tunnel_tlvs: vec![TunnelEncapTlv {
                tunnel_type: crate::models::tunnel_encap::TunnelType::Vxlan,
                sub_tlvs: vec![SubTlv {
                    sub_tlv_type: SubTlvType::Color,
                    value: vec![0; 300],
                }],
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::TunnelEncapsulation(encap),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_tunnel_encap_ext_subtlv_oversize() {
        use crate::models::tunnel_encap::{
            SubTlv, SubTlvType, TunnelEncapAttribute, TunnelEncapTlv,
        };

        let encap = TunnelEncapAttribute {
            tunnel_tlvs: vec![TunnelEncapTlv {
                tunnel_type: crate::models::tunnel_encap::TunnelType::Vxlan,
                sub_tlvs: vec![SubTlv {
                    sub_tlv_type: SubTlvType::SegmentList,
                    value: vec![0; 70000],
                }],
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::TunnelEncapsulation(encap),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_tunnel_encap_tunnel_total_oversize() {
        use crate::models::tunnel_encap::{
            SubTlv, SubTlvType, TunnelEncapAttribute, TunnelEncapTlv,
        };

        let encap = TunnelEncapAttribute {
            tunnel_tlvs: vec![TunnelEncapTlv {
                tunnel_type: crate::models::tunnel_encap::TunnelType::Vxlan,
                sub_tlvs: vec![
                    SubTlv {
                        sub_tlv_type: SubTlvType::SegmentList,
                        value: vec![0; 40000],
                    };
                    2
                ],
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::TunnelEncapsulation(encap),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_linkstate_oversize() {
        use crate::models::linkstate::{LinkStateAttribute, NodeAttributeType};

        let mut ls = LinkStateAttribute::new();
        ls.add_node_attribute(NodeAttributeType::NodeName, vec![0; 70000]);
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::LinkState(ls),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());

        let mut ls2 = LinkStateAttribute::new();
        ls2.add_unknown_attribute(crate::models::linkstate::Tlv::new(1, vec![0; 70000]));
        let attr2 = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::LinkState(ls2),
        };
        assert!(attr2.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_bfd_discriminator_oversize() {
        use crate::models::{BfdDiscriminatorAttribute, RawTlv8};

        let attr_val = BfdDiscriminatorAttribute {
            mode: 0,
            discriminator: 0,
            tlvs: vec![RawTlv8 {
                tlv_type: 1,
                value: vec![0; 300].into(),
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::BfdDiscriminator(attr_val),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_bgp_prefix_sid_oversize() {
        use crate::models::{BgpPrefixSidAttribute, RawTlv8Ext};

        let attr_val = BgpPrefixSidAttribute {
            tlvs: vec![RawTlv8Ext {
                tlv_type: 1,
                value: vec![0; 70000].into(),
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::BgpPrefixSid(attr_val),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_bier_oversize() {
        use crate::models::{BierAttribute, RawTlv16};

        let attr_val = BierAttribute {
            tlvs: vec![RawTlv16 {
                tlv_type: 1,
                value: vec![0; 70000].into(),
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::Bier(attr_val),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_sfp_oversize() {
        use crate::models::{RawTlv8Ext, SfpAttribute};

        let attr_val = SfpAttribute {
            tlvs: vec![RawTlv8Ext {
                tlv_type: 1,
                value: vec![0; 70000].into(),
            }],
        };
        let attr = Attribute {
            flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
            value: AttributeValue::Sfp(attr_val),
        };
        assert!(attr.try_encode(AsnLength::Bits32).is_err());
    }

    #[test]
    fn test_encoding_error_mrt_table_dump_oversize() {
        use crate::models::{AttrFlags, AttrRaw, Attribute, AttributeValue, TableDumpMessage};

        let attrs: Vec<Attribute> = (0..70)
            .map(|_| Attribute {
                flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
                value: AttributeValue::Raw(AttrRaw {
                    code: 200,
                    bytes: vec![0; 1000].into(),
                }),
            })
            .collect();

        let msg = TableDumpMessage {
            view_number: 0,
            sequence_number: 0,
            prefix: "10.0.0.0/24".parse().unwrap(),
            status: 0,
            originated_time: 0,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_asn: Asn::new_16bit(65000),
            attributes: Attributes {
                inner: attrs,
                validation_warnings: vec![],
                attr_mask: [0; 4],
            },
        };
        assert!(msg.try_encode().is_err());
    }

    #[test]
    fn test_encoding_error_rib_entry_oversize() {
        use crate::models::{AttrFlags, AttrRaw, Attribute, AttributeValue, RibEntry};

        let attrs: Vec<Attribute> = (0..70)
            .map(|_| Attribute {
                flag: AttrFlags::OPTIONAL | AttrFlags::PARTIAL,
                value: AttributeValue::Raw(AttrRaw {
                    code: 200,
                    bytes: vec![0; 1000].into(),
                }),
            })
            .collect();

        let entry = RibEntry {
            peer_index: 0,
            originated_time: 0,
            path_id: None,
            attributes: Attributes {
                inner: attrs,
                validation_warnings: vec![],
                attr_mask: [0; 4],
            },
        };
        assert!(entry.try_encode().is_err());
    }

    #[test]
    fn test_encoding_error_peer_index_table_oversize() {
        use crate::models::PeerIndexTable;

        let table = PeerIndexTable {
            collector_bgp_id: std::net::Ipv4Addr::new(0, 0, 0, 0),
            view_name: "x".repeat(70000),
            id_peer_map: std::collections::HashMap::new(),
            peer_ip_id_map: std::collections::HashMap::new(),
        };
        assert!(table.try_encode().is_err());
    }

    #[test]
    fn test_encoding_error_geo_peer_table_oversize() {
        use crate::models::GeoPeerTable;

        let table = GeoPeerTable {
            collector_bgp_id: std::net::Ipv4Addr::new(0, 0, 0, 0),
            view_name: "x".repeat(70000),
            collector_latitude: 0.0,
            collector_longitude: 0.0,
            geo_peers: vec![],
        };
        assert!(table.try_encode().is_err());
    }
}
