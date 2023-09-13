use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, Bytes};
use log::warn;

/// Parse aggregator attribute.
///
/// https://www.rfc-editor.org/rfc/rfc4271.html#section-5.1.7
///
/// ```text
///    AGGREGATOR is an optional transitive attribute, which MAY be included
///    in updates that are formed by aggregation (see Section 9.2.2.2).  A
///    BGP speaker that performs route aggregation MAY add the AGGREGATOR
///    attribute, which SHALL contain its own AS number and IP address.  The
///    IP address SHOULD be the same as the BGP Identifier of the speaker.`
/// ```
pub fn parse_aggregator(
    mut input: Bytes,
    asn_len: &AsnLength,
) -> Result<(Asn, BgpIdentifier), ParserError> {
    let asn_len_found = match input.remaining() {
        8 => AsnLength::Bits32,
        6 => AsnLength::Bits16,
        _ => {
            return Err(ParserError::ParseError(format!(
                "Aggregator attribute length is invalid: found {}, should 6 or 8",
                input.remaining()
            )))
        }
    };
    if asn_len_found != *asn_len {
        warn!(
            "Aggregator attribute with ASN length set to {:?} but found {:?}",
            asn_len, asn_len_found
        );
    }
    let asn = input.read_asn(asn_len_found)?;

    // the BGP identifier is always 4 bytes or IPv4 address
    let identifier = input.read_ipv4_address()?;
    Ok((asn, identifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_parse_aggregator() {
        let identifier = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let mut data = vec![];
        data.extend([1u8, 2]);
        data.extend(identifier.octets());
        let bytes = Bytes::from(data);

        if let Ok((asn, n)) = parse_aggregator(bytes, &AsnLength::Bits16) {
            assert_eq!(n, identifier);
            assert_eq!(asn, Asn::new_16bit(258))
        } else {
            panic!()
        }

        let mut data = vec![];
        data.extend([0u8, 0, 1, 2]);
        data.extend(identifier.octets());
        let bytes = Bytes::from(data);

        if let Ok((asn, n)) = parse_aggregator(bytes, &AsnLength::Bits32) {
            assert_eq!(n, identifier);
            assert_eq!(asn, Asn::new_16bit(258))
        } else {
            panic!()
        }
    }
}
