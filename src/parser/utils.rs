/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
*/
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::models::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::debug;
use num_traits::FromPrimitive;
use std::net::IpAddr;

use crate::error::ParserError;
use crate::ParserError::IoNotEnoughBytes;

impl ReadUtils for Bytes {}

// Allow reading IPs from Reads
pub trait ReadUtils: Buf {
    #[inline]
    fn has_n_remaining(&self, n: usize) -> Result<(), ParserError> {
        if self.remaining() < n {
            Err(IoNotEnoughBytes())
        } else {
            Ok(())
        }
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, ParserError> {
        self.has_n_remaining(1)?;
        Ok(self.get_u8())
    }

    #[inline]
    fn read_u16(&mut self) -> Result<u16, ParserError> {
        self.has_n_remaining(2)?;
        Ok(self.get_u16())
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32, ParserError> {
        self.has_n_remaining(4)?;
        Ok(self.get_u32())
    }

    #[inline]
    fn read_u64(&mut self) -> Result<u64, ParserError> {
        self.has_n_remaining(8)?;
        Ok(self.get_u64())
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
        let addr = self.read_u32()?;
        Ok(Ipv4Addr::from(addr))
    }

    fn read_ipv6_address(&mut self) -> Result<Ipv6Addr, ParserError> {
        self.has_n_remaining(16)?;
        let buf = self.get_u128();
        Ok(Ipv6Addr::from(buf))
    }

    fn read_ipv4_prefix(&mut self) -> Result<Ipv4Net, ParserError> {
        let addr = self.read_ipv4_address()?;
        let mask = self.read_u8()?;
        match Ipv4Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    fn read_ipv6_prefix(&mut self) -> Result<Ipv6Net, ParserError> {
        let addr = self.read_ipv6_address()?;
        let mask = self.read_u8()?;
        match Ipv6Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    fn read_asn(&mut self, as_length: &AsnLength) -> Result<Asn, ParserError> {
        match as_length {
            AsnLength::Bits16 => {
                let asn = self.read_u16()? as u32;
                Ok(Asn {
                    asn,
                    len: AsnLength::Bits16,
                })
            }
            AsnLength::Bits32 => {
                let asn = self.read_u32()?;
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
                self.has_n_remaining(count * 2)?; // 2 bytes for 16-bit ASN
                for i in 0..count {
                    path[i] = self.get_u16() as u32;
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
                self.has_n_remaining(count * 4)?; // 4 bytes for 32-bit ASN
                for i in 0..count {
                    path[i] = self.get_u32();
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
        let afi = self.read_u16()?;
        match Afi::from_i16(afi as i16) {
            Some(afi) => Ok(afi),
            None => Err(crate::error::ParserError::Unsupported(format!(
                "Unknown AFI type: {}",
                afi
            ))),
        }
    }

    fn read_safi(&mut self) -> Result<Safi, ParserError> {
        let safi = self.read_u8()?;
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
        let path_id = if add_path { self.read_u32()? } else { 0 };

        // Length in bits
        let bit_len = self.read_u8()?;

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
                self.has_n_remaining(byte_len)?;
                for i in 0..byte_len {
                    buff[i] = self.get_u8();
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
                self.has_n_remaining(byte_len)?;
                let mut buff = [0; 16];
                for i in 0..byte_len {
                    buff[i] = self.get_u8();
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
        self.has_n_remaining(n_bytes)?;
        Ok(self.copy_to_bytes(n_bytes).into())
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
    mut input: Bytes,
    add_path: bool,
    afi: &Afi,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    let mut is_add_path = add_path;
    let mut prefixes = vec![];

    let mut retry = false;
    let mut guessed = false;

    let mut input_copy = None;

    while input.remaining() > 0 {
        if !is_add_path && input[0] == 0 {
            // it's likely that this is a add-path wrongfully wrapped in non-add-path msg
            debug!("not add-path but with NLRI size to be 0, likely add-path msg in wrong msg type, treat as add-path now");
            // cloning the data bytes
            is_add_path = true;
            guessed = true;
            input_copy = Some(input.clone());
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
        // if we reach here (retry==true), input_copy must be Some
        let mut input_2 = input_copy.unwrap();
        while input_2.remaining() > 0 {
            let prefix = input_2.read_nlri_prefix(afi, add_path)?;
            prefixes.push(prefix);
        }
    }

    Ok(prefixes)
}

pub fn encode_asn(asn: &Asn, asn_len: &AsnLength) -> Bytes {
    let mut bytes = BytesMut::new();
    match asn_len {
        AsnLength::Bits16 => {
            bytes.put_u16(asn.asn as u16);
        }
        AsnLength::Bits32 => {
            bytes.put_u32(asn.asn);
        }
    }
    bytes.freeze()
}

pub fn encode_ipaddr(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    }
}

pub fn encode_nlri_prefixes(prefixes: &[NetworkPrefix], add_path: bool) -> Bytes {
    let mut bytes = BytesMut::new();
    for prefix in prefixes {
        bytes.extend(encode_nlri_prefix(prefix, add_path));
    }
    bytes.freeze()
}

pub fn encode_nlri_prefix(prefix: &NetworkPrefix, add_path: bool) -> Bytes {
    let mut bytes = BytesMut::new();
    if add_path {
        // encode path identifier
        bytes.put_u32(prefix.path_id);
    }
    // encode prefix

    let bit_len = prefix.prefix.prefix_len();
    let byte_len = ((bit_len + 7) / 8) as usize;
    bytes.put_u8(bit_len);

    match prefix.prefix {
        IpNet::V4(prefix) => {
            bytes.put_slice(&prefix.addr().octets()[0..byte_len]);
        }
        IpNet::V6(prefix) => {
            bytes.put_slice(&prefix.addr().octets()[0..byte_len]);
        }
    };
    bytes.freeze()
}

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
