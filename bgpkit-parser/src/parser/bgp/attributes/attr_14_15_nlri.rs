use crate::parser::{parse_nlri_list, ReadUtils};
use crate::ParserError;
use bgp_models::prelude::*;
use log::warn;
use std::io::Cursor;

///
/// <https://datatracker.ietf.org/doc/html/rfc4760#section-3>
/// The attribute is encoded as shown below:
/// +---------------------------------------------------------+
/// | Address Family Identifier (2 octets)                    |
/// +---------------------------------------------------------+
/// | Subsequent Address Family Identifier (1 octet)          |
/// +---------------------------------------------------------+
/// | Length of Next Hop Network Address (1 octet)            |
/// +---------------------------------------------------------+
/// | Network Address of Next Hop (variable)                  |
/// +---------------------------------------------------------+
/// | Reserved (1 octet)                                      |
/// +---------------------------------------------------------+
/// | Network Layer Reachability Information (variable)       |
/// +---------------------------------------------------------+
pub fn parse_nlri(
    input: &mut Cursor<&[u8]>,
    afi: &Option<Afi>,
    safi: &Option<Safi>,
    prefixes: &Option<&[NetworkPrefix]>,
    reachable: bool,
    additional_paths: bool,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    let first_byte_zero = input.get_ref()[input.position() as usize] == 0;
    let pos_end = input.position() + total_bytes as u64;

    // read address family
    let afi = match afi {
        Some(afi) => {
            if first_byte_zero {
                input.read_afi()?
            } else {
                afi.to_owned()
            }
        }
        None => input.read_afi()?,
    };
    let safi = match safi {
        Some(safi) => {
            if first_byte_zero {
                input.read_safi()?
            } else {
                safi.to_owned()
            }
        }
        None => input.read_safi()?,
    };

    let mut next_hop = None;
    if reachable {
        let next_hop_length = input.read_8b()?;
        next_hop = match parse_mp_next_hop(next_hop_length, input) {
            Ok(x) => x,
            Err(e) => return Err(e),
        };
    }

    let mut bytes_left = pos_end - input.position();

    let prefixes = match prefixes {
        Some(pfxs) => {
            // skip parsing prefixes: https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.4
            if first_byte_zero {
                if reachable {
                    // skip reserved byte for reachable NRLI
                    if input.read_8b()? != 0 {
                        warn!("NRLI reserved byte not 0");
                    }
                    bytes_left -= 1;
                }
                parse_nlri_list(input, additional_paths, &afi, bytes_left)?
            } else {
                pfxs.to_vec()
            }
        }
        None => {
            if reachable {
                // skip reserved byte for reachable NRLI
                if input.read_8b()? != 0 {
                    warn!("NRLI reserved byte not 0");
                }
                bytes_left -= 1;
            }
            parse_nlri_list(input, additional_paths, &afi, bytes_left)?
        }
    };

    // Reserved field, should ignore
    match reachable {
        true => Ok(AttributeValue::MpReachNlri(Nlri {
            afi,
            safi,
            next_hop,
            prefixes,
        })),
        false => Ok(AttributeValue::MpUnreachNlri(Nlri {
            afi,
            safi,
            next_hop,
            prefixes,
        })),
    }
}

fn parse_mp_next_hop(
    next_hop_length: u8,
    input: &mut Cursor<&[u8]>,
) -> Result<Option<NextHopAddress>, ParserError> {
    let output = match next_hop_length {
        0 => None,
        4 => Some(input.read_ipv4_address().map(NextHopAddress::Ipv4)?),
        16 => Some(input.read_ipv6_address().map(NextHopAddress::Ipv6)?),
        32 => Some(NextHopAddress::Ipv6LinkLocal(
            input.read_ipv6_address()?,
            input.read_ipv6_address()?,
        )),
        v => {
            return Err(ParserError::ParseError(format!(
                "Invalid next hop length found: {}",
                v
            )));
        }
    };
    Ok(output)
}
