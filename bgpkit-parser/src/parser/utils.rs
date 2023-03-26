/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
*/
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::io::{Cursor, Seek, SeekFrom};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use bgp_models::prelude::*;
use byteorder::{ReadBytesExt, BE};
use log::debug;
use num_traits::FromPrimitive;
use std::net::IpAddr;

use crate::error::ParserError;

// Allow reading IPs from Reads
pub trait ReadUtils: io::Read {
    fn read_8b(&mut self) -> io::Result<u8> {
        self.read_u8()
    }

    fn read_16b(&mut self) -> io::Result<u16> {
        self.read_u16::<BE>()
    }

    fn read_32b(&mut self) -> io::Result<u32> {
        self.read_u32::<BE>()
    }

    fn read_64b(&mut self) -> io::Result<u64> {
        self.read_u64::<BE>()
    }

    fn read_128b(&mut self) -> io::Result<u128> {
        self.read_u128::<BE>()
    }

    fn read_address(&mut self, afi: &Afi) -> io::Result<IpAddr> {
        match afi {
            Afi::Ipv4 => match self.read_ipv4_address() {
                Ok(ip) => Ok(IpAddr::V4(ip)),
                _ => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Cannot parse IPv4 address".to_string(),
                )),
            },
            Afi::Ipv6 => match self.read_ipv6_address() {
                Ok(ip) => Ok(IpAddr::V6(ip)),
                _ => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Cannot parse IPv6 address".to_string(),
                )),
            },
        }
    }

    fn read_ipv4_address(&mut self) -> Result<Ipv4Addr, ParserError> {
        let addr = self.read_32b()?;
        Ok(Ipv4Addr::from(addr))
    }

    fn read_ipv6_address(&mut self) -> Result<Ipv6Addr, ParserError> {
        let buf = self.read_u128::<BE>()?;
        Ok(Ipv6Addr::from(buf))
    }

    fn read_ipv4_prefix(&mut self) -> Result<Ipv4Net, ParserError> {
        let addr = self.read_ipv4_address()?;
        let mask = self.read_8b()?;
        match Ipv4Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    fn read_ipv6_prefix(&mut self) -> Result<Ipv6Net, ParserError> {
        let addr = self.read_ipv6_address()?;
        let mask = self.read_8b()?;
        match Ipv6Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    fn read_asn(&mut self, as_length: &AsnLength) -> Result<Asn, ParserError> {
        match as_length {
            AsnLength::Bits16 => {
                let asn = self.read_16b()? as u32;
                Ok(Asn {
                    asn,
                    len: AsnLength::Bits16,
                })
            }
            AsnLength::Bits32 => {
                let asn = self.read_32b()?;
                Ok(Asn {
                    asn,
                    len: AsnLength::Bits32,
                })
            }
        }
    }

    fn read_asns(&mut self, as_length: &AsnLength, count: usize) -> Result<Vec<Asn>, ParserError> {
        let mut path = [0; 255];
        Ok(match as_length {
            AsnLength::Bits16 => {
                for i in 0..count {
                    path[i] = self.read_u16::<BE>()? as u32;
                }
                path[..count]
                    .iter()
                    .map(|asn| Asn {
                        asn: *asn,
                        len: *as_length,
                    })
                    .collect::<Vec<Asn>>()
            }
            AsnLength::Bits32 => {
                for i in 0..count {
                    path[i] = self.read_32b()?;
                }
                path[..count]
                    .iter()
                    .map(|asn| Asn {
                        asn: *asn,
                        len: *as_length,
                    })
                    .collect::<Vec<Asn>>()
            }
        })
    }

    fn read_afi(&mut self) -> Result<Afi, ParserError> {
        let afi = self.read_u16::<BE>()?;
        match Afi::from_i16(afi as i16) {
            Some(afi) => Ok(afi),
            None => Err(crate::error::ParserError::Unsupported(format!(
                "Unknown AFI type: {}",
                afi
            ))),
        }
    }

    fn read_safi(&mut self) -> Result<Safi, ParserError> {
        let safi = self.read_8b()?;
        match Safi::from_u8(safi) {
            Some(safi) => Ok(safi),
            None => Err(crate::error::ParserError::Unsupported(format!(
                "Unknown SAFI type: {}",
                safi
            ))),
        }
    }

    /// Read announced/withdrawn prefix.
    ///
    /// The length in bits is 1 byte, and then based on the IP version it reads different number of bytes.
    /// If the `add_path` is true, it will also first read a 4-byte path id first; otherwise, a path-id of 0
    /// is automatically set.
    fn read_nlri_prefix(
        &mut self,
        afi: &Afi,
        add_path: bool,
    ) -> Result<NetworkPrefix, ParserError> {
        let path_id = if add_path { self.read_32b()? } else { 0 };

        // Length in bits
        let bit_len = self.read_8b()?;

        // Convert to bytes
        let byte_len: usize = (bit_len as usize + 7) / 8;
        let addr: IpAddr = match afi {
            Afi::Ipv4 => {
                // 4 bytes -- u32
                if byte_len > 4 {
                    return Err(ParserError::ParseError(format!(
                        "Invalid byte length for IPv4 prefix. byte_len: {}, bit_len: {}",
                        byte_len, bit_len
                    )));
                }
                let mut buff = [0; 4];
                for i in 0..byte_len {
                    buff[i] = self.read_8b()?
                }
                IpAddr::V4(Ipv4Addr::from(buff))
            }
            Afi::Ipv6 => {
                // 16 bytes
                if byte_len > 16 {
                    return Err(ParserError::ParseError(format!(
                        "Invalid byte length for IPv6 prefix. byte_len: {}, bit_len: {}",
                        byte_len, bit_len
                    )));
                }
                let mut buff = [0; 16];
                for i in 0..byte_len {
                    buff[i] = self.read_8b()?
                }
                IpAddr::V6(Ipv6Addr::from(buff))
            }
        };
        let prefix = match IpNet::new(addr, bit_len) {
            Ok(p) => p,
            Err(_) => {
                return Err(ParserError::ParseError(format!(
                    "Invalid network prefix length: {}",
                    bit_len
                )))
            }
        };

        Ok(NetworkPrefix::new(prefix, path_id))
    }

    fn read_n_bytes(&mut self, n_bytes: usize) -> Result<Vec<u8>, ParserError> {
        // TODO: fix the checking
        // if self.total - self.pos < n_bytes {
        //     return Err(ParserError::IoNotEnoughBytes())
        // }
        let mut bytes = vec![];
        for _ in 0..n_bytes {
            bytes.push(self.read_8b()?);
        }
        Ok(bytes)
    }

    fn read_n_bytes_to_string(&mut self, n_bytes: usize) -> Result<String, ParserError> {
        let buffer = self.read_n_bytes(n_bytes)?;
        Ok(buffer
            .into_iter()
            .map(|x: u8| x as char)
            .collect::<String>())
    }
}

pub fn parse_nlri_list(
    input: &mut Cursor<&[u8]>,
    add_path: bool,
    afi: &Afi,
    total_bytes: u64,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    let pos_end = input.position() + total_bytes;

    let mut is_add_path = add_path;
    let mut prefixes = vec![];

    let mut retry = false;
    let mut guessed = false;

    let pos_save = input.position();

    while input.position() < pos_end {
        if !is_add_path && input.get_ref()[input.position() as usize] == 0 {
            // it's likely that this is a add-path wrongfully wrapped in non-add-path msg
            debug!("not add-path but with NLRI size to be 0, likely add-path msg in wrong msg type, treat as add-path now");
            is_add_path = true;
            guessed = true;
        }
        let prefix = match input.read_nlri_prefix(afi, is_add_path) {
            Ok(p) => p,
            Err(e) => {
                if guessed {
                    retry = true;
                    break;
                } else {
                    return Err(e);
                }
            }
        };
        prefixes.push(prefix);
    }

    if retry {
        prefixes.clear();
        // try again without attempt to guess add-path
        input.seek(SeekFrom::Start(pos_save))?;
        while input.position() < pos_end {
            let prefix = input.read_nlri_prefix(afi, add_path)?;
            prefixes.push(prefix);
        }
    }

    Ok(prefixes)
}

// All types that implement Read can now read prefixes
impl<R: io::Read> ReadUtils for R {}

/// A CRC32 implementation that converts a string to a hex string.
///
/// CRC32 is a checksum algorithm that is used to verify the integrity of data. It is short in
/// length and sufficient for generating unique file names based on remote URLs.
pub fn crc32(input: &str) -> String {
    let input_bytes = input.as_bytes();
    let mut table = [0u32; 256];
    let polynomial = 0xedb88320u32;

    for i in 0..256 {
        let mut crc = i as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }

    let mut crc = !0u32;
    for byte in input_bytes.iter() {
        let index = ((crc ^ (*byte as u32)) & 0xff) as usize;
        crc = (crc >> 8) ^ table[index];
    }

    format!("{:08x}", !crc)
}
