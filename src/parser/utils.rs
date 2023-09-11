/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
*/
use ipnet::{IpNet, Ipv4Net, Ipv6Net, PrefixLenError};
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::models::*;
use std::net::IpAddr;

use crate::error::ParserError;

#[cold]
fn eof(name: &'static str, expected: usize, found: usize) -> ParserError {
    ParserError::InconsistentFieldLength {
        name,
        expected,
        found,
    }
}

impl ReadUtils for &'_ [u8] {
    #[inline]
    fn remaining(&self) -> usize {
        self.len()
    }

    #[inline]
    fn advance(&mut self, x: usize) -> Result<(), ParserError> {
        if self.len() >= x {
            *self = &self[x..];
            return Ok(());
        }

        Err(eof("advance", x, self.len()))
    }

    #[inline]
    fn split_to(&mut self, n: usize) -> Result<Self, ParserError> {
        if self.len() >= n {
            let (a, b) = self.split_at(n);
            *self = b;
            return Ok(a);
        }

        Err(eof("split_to", n, self.len()))
    }

    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8, ParserError> {
        if !self.is_empty() {
            let value = self[0];
            *self = &self[1..];
            return Ok(value);
        }

        Err(eof("read_u8", 1, 0))
    }

    #[inline(always)]
    fn read_u16(&mut self) -> Result<u16, ParserError> {
        if self.len() >= 2 {
            let (bytes, remaining) = self.split_at(2);
            *self = remaining;
            return Ok(u16::from_be_bytes(bytes.try_into().unwrap()));
        }

        Err(eof("read_u16", 2, self.len()))
    }

    #[inline(always)]
    fn read_u32(&mut self) -> Result<u32, ParserError> {
        if self.len() >= 4 {
            let (bytes, remaining) = self.split_at(4);
            *self = remaining;
            return Ok(u32::from_be_bytes(bytes.try_into().unwrap()));
        }

        Err(eof("read_u32", 4, self.len()))
    }

    #[inline(always)]
    fn read_u64(&mut self) -> Result<u64, ParserError> {
        if self.len() >= 8 {
            let (bytes, remaining) = self.split_at(8);
            *self = remaining;
            return Ok(u64::from_be_bytes(bytes.try_into().unwrap()));
        }

        Err(eof("read_u64", 8, self.len()))
    }

    #[inline]
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ParserError> {
        match std::io::Read::read_exact(self, buffer) {
            Ok(_) => Ok(()),
            Err(_) => Err(eof("read_exact", buffer.len(), self.len())),
        }
    }
}

// Allow reading IPs from Reads
pub trait ReadUtils: Sized {
    fn remaining(&self) -> usize;
    fn advance(&mut self, x: usize) -> Result<(), ParserError>;
    fn split_to(&mut self, n: usize) -> Result<Self, ParserError>;
    fn read_u8(&mut self) -> Result<u8, ParserError>;
    fn read_u16(&mut self) -> Result<u16, ParserError>;
    fn read_u32(&mut self) -> Result<u32, ParserError>;
    fn read_u64(&mut self) -> Result<u64, ParserError>;
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ParserError>;

    /// Check that the buffer has at least n bytes remaining. This can help the compiler optimize
    /// away bounds checks.
    #[inline(always)]
    fn require_n_remaining(&self, n: usize, target: &'static str) -> Result<(), ParserError> {
        if self.remaining() >= n {
            return Ok(());
        }

        Err(eof(target, n, self.remaining()))
    }

    #[inline(always)]
    fn expect_remaining_eq(&self, n: usize, target: &'static str) -> Result<(), ParserError> {
        if self.remaining() == n {
            return Ok(());
        }

        Err(ParserError::InconsistentFieldLength {
            name: target,
            expected: n,
            found: self.remaining(),
        })
    }

    fn read_address(&mut self, afi: &Afi) -> Result<IpAddr, ParserError> {
        match afi {
            Afi::Ipv4 => self.read_ipv4_address().map(IpAddr::V4),
            Afi::Ipv6 => self.read_ipv6_address().map(IpAddr::V6),
        }
    }

    fn read_ipv4_address(&mut self) -> Result<Ipv4Addr, ParserError> {
        self.require_n_remaining(4, "IPv4 Address")?;
        let addr = self.read_u32()?;
        Ok(Ipv4Addr::from(addr))
    }

    fn read_ipv6_address(&mut self) -> Result<Ipv6Addr, ParserError> {
        self.require_n_remaining(16, "IPv6 Address")?;
        let mut buffer = [0; 16];
        self.read_exact(&mut buffer)?;
        Ok(Ipv6Addr::from(buffer))
    }

    fn read_ipv4_prefix(&mut self) -> Result<Ipv4Net, ParserError> {
        self.require_n_remaining(5, "IPv4 Prefix")?;
        let addr = self.read_ipv4_address()?;
        let mask = self.read_u8()?;
        Ipv4Net::new(addr, mask).map_err(ParserError::from)
    }

    fn read_ipv6_prefix(&mut self) -> Result<Ipv6Net, ParserError> {
        self.require_n_remaining(17, "IPv6 Prefix")?;
        let addr = self.read_ipv6_address()?;
        let mask = self.read_u8()?;
        Ipv6Net::new(addr, mask).map_err(ParserError::from)
    }

    #[inline]
    fn read_asn(&mut self, as_length: AsnLength) -> Result<Asn, ParserError> {
        match as_length {
            AsnLength::Bits16 => self.read_u16().map(Asn::new_16bit),
            AsnLength::Bits32 => self.read_u32().map(Asn::new_32bit),
        }
    }

    fn read_asns(&mut self, as_length: AsnLength, count: usize) -> Result<Vec<Asn>, ParserError> {
        let mut path = Vec::with_capacity(count);

        match as_length {
            AsnLength::Bits16 => {
                self.require_n_remaining(count * 2, "16bit ASNs")?; // 2 bytes for 16-bit ASN
                for _ in 0..count {
                    path.push(Asn::new_16bit(self.read_u16()?));
                }
            }
            AsnLength::Bits32 => {
                self.require_n_remaining(count * 4, "32bit ASNs")?; // 4 bytes for 32-bit ASN
                for _ in 0..count {
                    path.push(Asn::new_32bit(self.read_u32()?));
                }
            }
        }

        Ok(path)
    }

    #[inline(always)]
    fn read_afi(&mut self) -> Result<Afi, ParserError> {
        Afi::try_from(self.read_u16()?).map_err(ParserError::from)
    }

    #[inline(always)]
    fn read_safi(&mut self) -> Result<Safi, ParserError> {
        Safi::try_from(self.read_u8()?).map_err(ParserError::from)
    }

    /// An alternative to [ReadUtils::read_nlri_prefix] which is easier for the compiler to
    /// optimize. Calling `x.read_v4_nlri_prefix()` is functionally equivalent to
    /// `x.read_nlri_prefix(&Afi::Ipv4, false)`.
    #[inline(always)]
    fn read_v4_nlri_prefix(&mut self) -> Result<NetworkPrefix, ParserError> {
        // Length in bits and bytes
        let bit_len = self.read_u8()?;

        if bit_len > 32 {
            return Err(ParserError::InvalidPrefixLength(PrefixLenError));
        }

        let byte_len: usize = (bit_len as usize + 7) / 8;

        let mut buff = [0; 4];
        self.read_exact(&mut buff[..byte_len])?;

        let prefix = match Ipv4Net::new(Ipv4Addr::from(buff), bit_len) {
            Ok(v) => IpNet::V4(v),
            Err(_) => unreachable!("Bit length has already been checked"),
        };

        Ok(NetworkPrefix { prefix, path_id: 0 })
    }

    /// An alternative to [ReadUtils::read_nlri_prefix] which is easier for the compiler to
    /// optimize. Calling `x.read_v6_nlri_prefix()` is functionally equivalent to
    /// `x.read_nlri_prefix(&Afi::Ipv6, false)`.
    #[inline(always)]
    fn read_v6_nlri_prefix(&mut self) -> Result<NetworkPrefix, ParserError> {
        // Length in bits and bytes
        let bit_len = self.read_u8()?;

        // 16 bytes
        if bit_len > 128 {
            return Err(ParserError::InvalidPrefixLength(PrefixLenError));
        }
        let byte_len: usize = (bit_len as usize + 7) / 8;

        let mut buff = [0; 16];
        self.read_exact(&mut buff[..byte_len])?;

        let prefix = match Ipv6Net::new(Ipv6Addr::from(buff), bit_len) {
            Ok(v) => IpNet::V6(v),
            Err(_) => unreachable!("Bit length has already been checked"),
        };

        Ok(NetworkPrefix { prefix, path_id: 0 })
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

        // Length in bits and bytes
        let bit_len = self.read_u8()?;
        let byte_len: usize = (bit_len as usize + 7) / 8;

        let prefix = match afi {
            Afi::Ipv4 => {
                // 4 bytes
                if bit_len > 32 {
                    return Err(ParserError::InvalidPrefixLength(PrefixLenError));
                }

                let mut buff = [0; 4];
                self.read_exact(&mut buff[..byte_len])?;

                match Ipv4Net::new(Ipv4Addr::from(buff), bit_len) {
                    Ok(v) => IpNet::V4(v),
                    Err(_) => unreachable!("Bit length has already been checked"),
                }
            }
            Afi::Ipv6 => {
                // 16 bytes
                if bit_len > 128 {
                    return Err(ParserError::InvalidPrefixLength(PrefixLenError));
                }

                let mut buff = [0; 16];
                self.read_exact(&mut buff[..byte_len])?;

                match Ipv6Net::new(Ipv6Addr::from(buff), bit_len) {
                    Ok(v) => IpNet::V6(v),
                    Err(_) => unreachable!("Bit length has already been checked"),
                }
            }
        };

        Ok(NetworkPrefix::new(prefix, path_id))
    }

    fn read_n_bytes(&mut self, n_bytes: usize) -> Result<Vec<u8>, ParserError> {
        self.require_n_remaining(n_bytes, "raw bytes")?;
        let mut buffer = vec![0; n_bytes];
        self.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn read_n_bytes_to_string(&mut self, n_bytes: usize) -> Result<String, ParserError> {
        let buffer = self.read_n_bytes(n_bytes)?;
        Ok(buffer
            .into_iter()
            .map(|x: u8| x as char)
            .collect::<String>())
    }
}

#[cold]
#[inline(never)]
fn parse_nlri_list_fallback(
    mut input: &[u8],
    afi: Afi,
    add_path: bool,
) -> Result<PrefixList, ParserError> {
    let mut prefixes = PrefixList::with_capacity(input.len() / 4);
    while !input.is_empty() {
        prefixes.push((&mut input).read_nlri_prefix(&afi, add_path)?);
    }

    Ok(prefixes)
}

fn parse_nlri_list_v4(mut input: &[u8]) -> Result<PrefixList, ParserError> {
    let retry_input = input;
    let mut prefixes = PrefixList::with_capacity(input.len() / 3);

    while !input.is_empty() {
        if input[0] == 0 {
            return match parse_nlri_list_fallback(retry_input, Afi::Ipv4, true) {
                Ok(v) => Ok(v),
                Err(_) => parse_nlri_list_fallback(retry_input, Afi::Ipv4, false),
            };
        }

        prefixes.push((&mut input).read_v4_nlri_prefix()?);
    }

    Ok(prefixes)
}

fn parse_nlri_list_v6(mut input: &[u8]) -> Result<PrefixList, ParserError> {
    let retry_input = input;
    let mut prefixes = PrefixList::with_capacity(input.len() / 5);

    while !input.is_empty() {
        if input[0] == 0 {
            return match parse_nlri_list_fallback(retry_input, Afi::Ipv6, true) {
                Ok(v) => Ok(v),
                Err(_) => parse_nlri_list_fallback(retry_input, Afi::Ipv6, false),
            };
        }

        prefixes.push((&mut input).read_v6_nlri_prefix()?);
    }

    Ok(prefixes)
}

pub fn parse_nlri_list(input: &[u8], add_path: bool, afi: Afi) -> Result<PrefixList, ParserError> {
    if add_path {
        return parse_nlri_list_fallback(input, afi, true);
    }

    match afi {
        Afi::Ipv4 => parse_nlri_list_v4(input),
        Afi::Ipv6 => parse_nlri_list_v6(input),
    }
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
