use crate::error::{check_max, EncodingError};
use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Octets per domain: 4-octet Global Administrator, 2-octet Local
/// Administrator, and 1-octet ISF_SAFI_TYPE (RFC 10039 §4).
const DOMAIN_OCTETS: usize = 7;

/// Smallest valid D-PATH value: one domain segment holding one domain.
/// RFC 10039 §4 marks a total attribute length below 8 octets as malformed.
const MIN_VALUE_OCTETS: usize = 1 + DOMAIN_OCTETS;

pub fn parse_domain_path(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    if input.remaining() < MIN_VALUE_OCTETS {
        return Err(ParserError::TruncatedMsg(format!(
            "BGP Domain Path attribute value is {} octets, must be at least {MIN_VALUE_OCTETS}",
            input.remaining()
        )));
    }

    let mut segments = Vec::new();

    while input.remaining() > 0 {
        let domain_count = input.read_u8()? as usize;
        // RFC 10039 §4: a domain segment MUST contain at least one domain.
        if domain_count == 0 {
            return Err(ParserError::ParseError(
                "BGP Domain Path domain segment length must be at least 1".to_string(),
            ));
        }
        let required = domain_count * DOMAIN_OCTETS;
        if input.remaining() < required {
            return Err(ParserError::TruncatedMsg(format!(
                "truncated BGP Domain Path domain segment: need {required} octets for {domain_count} domains, have {}",
                input.remaining()
            )));
        }

        let mut domains = Vec::with_capacity(domain_count);
        for _ in 0..domain_count {
            let global_admin = input.read_u32()?;
            let local_admin = input.read_u16()?;
            let isf_safi_type = input.read_u8()?;
            domains.push(DomainPathDomain {
                global_admin,
                local_admin,
                isf_safi_type,
            });
        }
        segments.push(DomainPathSegment { domains });
    }

    Ok(AttributeValue::DomainPath(DomainPathAttribute { segments }))
}

pub fn encode_domain_path(
    attr: &DomainPathAttribute,
    buf: &mut BytesMut,
) -> Result<(), EncodingError> {
    if attr.segments.is_empty() {
        return Err(EncodingError::unencodable(
            "BGP Domain Path attribute",
            "a domain path must contain at least one domain segment (RFC 10039)",
        ));
    }
    for segment in &attr.segments {
        if segment.domains.is_empty() {
            return Err(EncodingError::unencodable(
                "BGP Domain Path domain segment",
                "a domain segment must contain at least 1 domain (RFC 10039)",
            ));
        }
        // The segment length field counts domains, not octets (RFC 10039 §4).
        check_max(
            "BGP Domain Path segment domain count",
            segment.domains.len(),
            u8::MAX as usize,
        )?;
        buf.put_u8(segment.domains.len() as u8);
        for domain in &segment.domains {
            buf.put_u32(domain.global_admin);
            buf.put_u16(domain.local_admin);
            buf.put_u8(domain.isf_safi_type);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BgpValidationWarning;

    #[test]
    fn test_parse_domain_path_single_segment_single_domain_round_trip() {
        let input = Bytes::from_static(&[
            0x01, // Domain Segment Length: 1 domain
            0x00, 0x00, 0xFD, 0xE8, // Global Administrator: ASN 65000
            0x00, 0x01, // Local Administrator: 1
            0x46, // ISF_SAFI_TYPE: 70 (EVPN)
        ]);
        let value = parse_domain_path(input.clone()).unwrap();
        match value {
            AttributeValue::DomainPath(attr) => {
                assert_eq!(attr.segments.len(), 1);
                assert_eq!(attr.segments[0].domains.len(), 1);
                assert_eq!(
                    attr.segments[0].domains[0],
                    DomainPathDomain {
                        global_admin: 65000,
                        local_admin: 1,
                        isf_safi_type: 70,
                    }
                );
                let mut buf = BytesMut::new();
                encode_domain_path(&attr, &mut buf).unwrap();
                assert_eq!(buf.freeze(), input);
            }
            value => panic!("expected BGP Domain Path, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_domain_path_multi_segment_multi_domain_round_trip() {
        let input = Bytes::from_static(&[
            0x02, // Domain Segment Length: 2 domains
            0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x80, // ASN 10 / 2 / 128 (IPVPN)
            0x00, 0x00, 0x00, 0x0B, 0x00, 0x03, 0x46, // ASN 11 / 3 / 70 (EVPN)
            0x01, // Domain Segment Length: 1 domain
            0x00, 0x00, 0x00, 0x0C, 0x00, 0x04, 0x00, // ASN 12 / 4 / 0 (gateway local)
        ]);
        let value = parse_domain_path(input.clone()).unwrap();
        match value {
            AttributeValue::DomainPath(attr) => {
                assert_eq!(attr.segments.len(), 2);
                assert_eq!(attr.segments[0].domains.len(), 2);
                assert_eq!(attr.segments[1].domains.len(), 1);
                assert_eq!(
                    attr.segments[0].domains[1],
                    DomainPathDomain {
                        global_admin: 11,
                        local_admin: 3,
                        isf_safi_type: 70,
                    }
                );
                assert_eq!(
                    attr.segments[1].domains[0],
                    DomainPathDomain {
                        global_admin: 12,
                        local_admin: 4,
                        isf_safi_type: 0,
                    }
                );
                let mut buf = BytesMut::new();
                encode_domain_path(&attr, &mut buf).unwrap();
                assert_eq!(buf.freeze(), input);
            }
            value => panic!("expected BGP Domain Path, got {value:?}"),
        }
    }

    #[test]
    fn test_parse_domain_path_rejects_truncated_domain() {
        // The segment claims 2 domains (14 octets), but only 7 follow.
        let input = Bytes::from_static(&[
            0x02, //
            0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x80,
        ]);
        assert!(matches!(
            parse_domain_path(input),
            Err(ParserError::TruncatedMsg(_))
        ));
    }

    #[test]
    fn test_parse_domain_path_rejects_short_value() {
        // Fewer than 8 octets cannot hold a single domain (RFC 10039 §4).
        assert!(parse_domain_path(Bytes::new()).is_err());
        assert!(parse_domain_path(Bytes::from_static(&[0x01])).is_err());
        assert!(parse_domain_path(Bytes::from_static(&[
            0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x02
        ]))
        .is_err());
    }

    #[test]
    fn test_parse_domain_path_rejects_zero_length_segment() {
        // Passes the minimum-length check, but a segment of zero domains is
        // malformed per RFC 10039 §4 (MUST be >= 1).
        let input = Bytes::from_static(&[
            0x00, //
            0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, 0x80,
        ]);
        assert!(matches!(
            parse_domain_path(input),
            Err(ParserError::ParseError(_))
        ));
    }

    #[test]
    fn test_encode_domain_path_rejects_oversized_segment() {
        // 256 domains cannot be counted by the 1-octet segment length.
        let attr = DomainPathAttribute {
            segments: vec![DomainPathSegment {
                domains: (0..256)
                    .map(|i| DomainPathDomain {
                        global_admin: i as u32,
                        local_admin: 0,
                        isf_safi_type: 0,
                    })
                    .collect(),
            }],
        };
        let mut buf = BytesMut::new();
        let err = encode_domain_path(&attr, &mut buf).unwrap_err();
        assert_eq!(
            err,
            EncodingError::ValueTooLarge {
                field: "BGP Domain Path segment domain count",
                actual: 256,
                max: 255,
            }
        );
    }

    #[test]
    fn test_encode_domain_path_rejects_empty_path_or_segment() {
        // Zero segments (a sub-8-octet value) and zero-length segments are
        // both malformed per RFC 10039 §4; the encoder refuses to emit them.
        let attr = DomainPathAttribute { segments: vec![] };
        let mut buf = BytesMut::new();
        assert!(matches!(
            encode_domain_path(&attr, &mut buf),
            Err(EncodingError::Unencodable { .. })
        ));

        let attr = DomainPathAttribute {
            segments: vec![DomainPathSegment { domains: vec![] }],
        };
        let mut buf = BytesMut::new();
        assert!(matches!(
            encode_domain_path(&attr, &mut buf),
            Err(EncodingError::Unencodable { .. })
        ));
    }

    #[test]
    fn test_malformed_domain_path_falls_back_to_raw() {
        // A declared length below one domain segment is malformed; through
        // parse_attributes the bytes must be retained raw with an RFC 7606
        // warning instead of being dropped.
        let wire = vec![0xc0, 0x24, 0x02, 0x00, 0x00];
        let attributes = super::super::parse_attributes(
            Bytes::from(wire.clone()),
            &AsnLength::Bits16,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(attributes.inner.len(), 1);
        match &attributes.inner[0].value {
            AttributeValue::Raw(raw) => {
                assert_eq!(raw.code, 36);
                assert_eq!(raw.bytes, Bytes::from_static(&[0x00, 0x00]));
            }
            value => panic!("expected Raw fallback, got {value:?}"),
        }
        assert!(attributes.validation_warnings().iter().any(|w| matches!(
            w,
            BgpValidationWarning::OptionalAttributeError { attr_type, .. }
                if *attr_type == AttrType::BGP_DOMAIN_PATH
        )));
        assert_eq!(
            attributes.encode(AsnLength::Bits16).unwrap(),
            Bytes::from(wire)
        );
    }

    /// A well-formed D-PATH: one segment, one domain (ASN 65000, local 1, EVPN).
    const DPATH: [u8; 11] = [
        0xc0, 0x24, 0x08, // optional transitive, type 36, length 8
        0x01, // domain segment length: 1 domain
        0x00, 0x00, 0xFD, 0xE8, // Global Administrator: ASN 65000
        0x00, 0x01, // Local Administrator: 1
        0x46, // ISF_SAFI_TYPE: 70 (EVPN)
    ];

    /// A BGP UPDATE body carrying the given attribute bytes, announced NLRI, and withdrawn NLRI.
    fn update_bytes(attributes: &[u8], announced: &[u8], withdrawn: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        wire.extend_from_slice(withdrawn);
        wire.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        wire.extend_from_slice(attributes);
        wire.extend_from_slice(announced);
        wire
    }

    /// An MP_REACH_NLRI attribute carrying the given value bytes.
    fn mp_reach(value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80, 0x0e, value.len() as u8];
        bytes.extend_from_slice(value);
        bytes
    }

    /// An MP_UNREACH_NLRI attribute carrying the given value bytes.
    fn mp_unreach(value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80, 0x0f, value.len() as u8];
        bytes.extend_from_slice(value);
        bytes
    }

    /// IPv4 next hop, no NLRI: an IPVPN (AFI 1, SAFI 128) MP_REACH value.
    const IPVPN_REACH: [u8; 9] = [0x00, 0x01, 0x80, 0x04, 0xc0, 0x00, 0x02, 0x01, 0x00];

    fn family_warning(attributes: &Attributes) -> Option<String> {
        attributes
            .validation_warnings()
            .iter()
            .find_map(|warning| match warning {
                BgpValidationWarning::OptionalAttributeError { attr_type, reason }
                    if *attr_type == AttrType::BGP_DOMAIN_PATH
                        && reason.contains("treat-as-withdraw") =>
                {
                    Some(reason.clone())
                }
                _ => None,
            })
    }

    #[test]
    fn test_domain_path_without_family_context_is_not_flagged() {
        // an attribute set on its own does not reveal the family: IPv4 unicast NLRI are parsed
        // after the attributes, and the UPDATE parser reports them once it has seen them
        let attributes = super::super::parse_attributes(
            Bytes::from(DPATH.to_vec()),
            &AsnLength::Bits16,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(family_warning(&attributes).is_none());
    }

    #[test]
    fn test_domain_path_with_unicast_mp_reach_is_flagged() {
        // an IPv4 unicast MP_REACH is decoded, so the family is known and not IPVPN/EVPN
        let mut wire = DPATH.to_vec();
        wire.extend(mp_reach(&[
            0x00, 0x01, // AFI: IPv4
            0x01, // SAFI: unicast
            0x04, // next hop length
            0xc0, 0x00, 0x02, 0x01, // next hop: 192.0.2.1
            0x00, // reserved
            0x18, 0xc0, 0x00, 0x02, // NLRI: 192.0.2.0/24
        ]));
        let attributes = super::super::parse_attributes(
            Bytes::from(wire),
            &AsnLength::Bits16,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(family_warning(&attributes).is_some());
    }

    #[test]
    fn test_domain_path_on_ipvpn_is_allowed() {
        let attributes = super::super::parse_attributes(
            Bytes::from(DPATH.to_vec()),
            &AsnLength::Bits16,
            false,
            Some(Afi::Ipv4),
            Some(Safi::MplsVpn),
            None,
        )
        .unwrap();

        assert!(family_warning(&attributes).is_none());
    }

    #[test]
    fn test_domain_path_with_evpn_mp_reach_is_not_flagged() {
        // EVPN is AFI 25 with SAFI 70: the NLRI do not decode yet, but the header still
        // identifies a family D-PATH is allowed on
        let mut wire = DPATH.to_vec();
        wire.extend(mp_reach(&[
            0x00, 0x19, // AFI: L2VPN (25)
            0x46, // SAFI: EVPN (70)
            0x10, // next hop length: 16
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, // reserved
        ]));
        let attributes = super::super::parse_attributes(
            Bytes::from(wire),
            &AsnLength::Bits16,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(family_warning(&attributes).is_none());
    }

    #[test]
    fn test_domain_path_with_mismatched_evpn_safi_is_flagged() {
        // SAFI 70 is EVPN only together with AFI 25, so this combination stays unsupported
        // even though the MP_REACH attribute itself does not decode
        let mut wire = DPATH.to_vec();
        wire.extend(mp_reach(&[
            0x00, 0x02, // AFI: IPv6
            0x46, // SAFI: EVPN (70)
            0x10, // next hop length: 16
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, // reserved
        ]));
        let attributes = super::super::parse_attributes(
            Bytes::from(wire),
            &AsnLength::Bits16,
            false,
            None,
            None,
            None,
        )
        .unwrap();

        let reason = family_warning(&attributes).expect("a mismatched EVPN SAFI must be reported");
        assert!(reason.contains("SAFI 70"), "{reason}");
    }

    #[test]
    fn test_domain_path_with_mpls_vpn_on_a_non_ip_afi_is_flagged() {
        // IPVPN is IPv4/IPv6 with SAFI 128; the same SAFI under another AFI is not IPVPN
        let attributes = super::super::parse_attributes(
            Bytes::from(DPATH.to_vec()),
            &AsnLength::Bits16,
            false,
            Some(Afi::LinkState),
            Some(Safi::MplsVpn),
            None,
        )
        .unwrap();

        assert!(family_warning(&attributes).is_some());
    }

    #[test]
    fn test_domain_path_with_isf_announcement_and_unicast_withdrawal_is_not_flagged() {
        // the announced family decides: a unicast withdrawal next to an IPVPN announcement
        // must not produce a finding, in either attribute order
        let reach = mp_reach(&IPVPN_REACH);
        let unreach = mp_unreach(&[0x00, 0x01, 0x01]); // AFI IPv4, SAFI unicast

        for (first, second) in [(&reach, &unreach), (&unreach, &reach)] {
            let mut wire = DPATH.to_vec();
            wire.extend_from_slice(first);
            wire.extend_from_slice(second);
            let attributes = super::super::parse_attributes(
                Bytes::from(wire),
                &AsnLength::Bits16,
                false,
                None,
                None,
                None,
            )
            .unwrap();

            assert!(
                attributes
                    .inner
                    .iter()
                    .any(|a| matches!(a.value, AttributeValue::MpReachNlri(_))),
                "the IPVPN MP_REACH must decode for this test to mean anything"
            );
            assert!(family_warning(&attributes).is_none());
        }
    }

    #[test]
    fn test_domain_path_with_classic_nlri_beside_ipvpn_announcement_is_flagged() {
        // an UPDATE may announce IPVPN routes through MP_REACH and classic IPv4 unicast NLRI,
        // which the attribute-level check cannot see
        let mut attributes = DPATH.to_vec();
        attributes.extend(mp_reach(&IPVPN_REACH));

        let update = crate::parser::bgp::messages::parse_bgp_update_message(
            Bytes::from(update_bytes(&attributes, &[0x18, 0xc0, 0x00, 0x02], &[])),
            false,
            &AsnLength::Bits16,
        )
        .unwrap();

        assert_eq!(update.announced_prefixes.len(), 1);
        assert!(family_warning(&update.attributes).is_some());
    }

    #[test]
    fn test_domain_path_with_classic_announcement_is_flagged() {
        let update = crate::parser::bgp::messages::parse_bgp_update_message(
            Bytes::from(update_bytes(&DPATH, &[0x18, 0xc0, 0x00, 0x02], &[])),
            false,
            &AsnLength::Bits16,
        )
        .unwrap();

        assert_eq!(update.announced_prefixes.len(), 1);
        assert!(family_warning(&update.attributes).is_some());
    }

    #[test]
    fn test_domain_path_with_classic_withdrawal_only_is_not_flagged() {
        // withdrawals carry no attributes of the routes they remove, so a D-PATH next to them
        // is not evidence of a non-ISF announcement
        let update = crate::parser::bgp::messages::parse_bgp_update_message(
            Bytes::from(update_bytes(&DPATH, &[], &[0x18, 0xc0, 0x00, 0x02])),
            false,
            &AsnLength::Bits16,
        )
        .unwrap();

        assert_eq!(update.withdrawn_prefixes.len(), 1);
        assert!(family_warning(&update.attributes).is_none());
    }
}
