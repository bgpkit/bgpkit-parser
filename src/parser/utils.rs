/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
*/
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::convert::TryFrom;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::error::ParserError;
use crate::models::*;
use crate::ParserError::TruncatedMsg;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::debug;
use regex::Regex;
use std::net::IpAddr;

impl ReadUtils for Bytes {}

// Allow reading IPs from Reads
pub trait ReadUtils: Buf {
    #[inline]
    fn has_n_remaining(&self, n: usize) -> Result<(), ParserError> {
        let remaining = self.remaining();
        if remaining < n {
            Err(TruncatedMsg(format!(
                "not enough bytes to read. remaining: {remaining}, required: {n}"
            )))
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

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ParserError> {
        self.has_n_remaining(buf.len())?;
        self.copy_to_slice(buf);
        Ok(())
    }

    fn read_address(&mut self, afi: &Afi) -> io::Result<IpAddr> {
        match afi {
            Afi::Ipv4 => match self.read_ipv4_address() {
                Ok(ip) => Ok(IpAddr::V4(ip)),
                _ => Err(io::Error::other("Cannot parse IPv4 address")),
            },
            Afi::Ipv6 => match self.read_ipv6_address() {
                Ok(ip) => Ok(IpAddr::V6(ip)),
                _ => Err(io::Error::other("Cannot parse IPv6 address")),
            },
            Afi::LinkState | Afi::L2vpn => {
                // Neither Link-State nor EVPN uses a traditional IP next hop in
                // this path; use the IPv4 zero address as a placeholder.
                Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
            }
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
            Err(_) => Err(io::Error::other("Invalid prefix mask").into()),
        }
    }

    fn read_ipv6_prefix(&mut self) -> Result<Ipv6Net, ParserError> {
        let addr = self.read_ipv6_address()?;
        let mask = self.read_u8()?;
        match Ipv6Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::other("Invalid prefix mask").into()),
        }
    }

    #[inline]
    fn read_asn(&mut self, as_length: AsnLength) -> Result<Asn, ParserError> {
        match as_length {
            AsnLength::Bits16 => self.read_u16().map(Asn::new_16bit),
            AsnLength::Bits32 => self.read_u32().map(Asn::new_32bit),
        }
    }

    fn read_asns(&mut self, as_length: &AsnLength, count: usize) -> Result<Vec<Asn>, ParserError> {
        // Verify the bytes are actually present before allocating, so a large
        // `count` cannot pre-allocate memory the buffer could never fill.
        // `checked_mul` guards against overflow of `count * width` on 32-bit
        // targets.
        let width = match as_length {
            AsnLength::Bits16 => 2,
            AsnLength::Bits32 => 4,
        };
        let needed = count
            .checked_mul(width)
            .ok_or_else(|| TruncatedMsg("ASN count overflows buffer length".to_string()))?;
        self.has_n_remaining(needed)?;

        let mut path = Vec::with_capacity(count);
        match as_length {
            AsnLength::Bits16 => {
                for _ in 0..count {
                    path.push(Asn::new_16bit(self.read_u16()?));
                }
            }
            AsnLength::Bits32 => {
                for _ in 0..count {
                    path.push(Asn::new_32bit(self.read_u32()?));
                }
            }
        }

        Ok(path)
    }

    fn read_afi(&mut self) -> Result<Afi, ParserError> {
        Afi::try_from(self.read_u16()?).map_err(ParserError::from)
    }

    fn read_safi(&mut self) -> Result<Safi, ParserError> {
        Safi::try_from(self.read_u8()?).map_err(ParserError::from)
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
        // Use try_parse_prefix on remaining bytes, then advance
        let data = self.chunk();
        let (prefix, consumed) = try_parse_prefix(data, afi, add_path)?;
        self.advance(consumed);
        Ok(prefix)
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

/// Parse NLRI prefix from byte slice without consuming bytes.
/// Returns (prefix, bytes_consumed) on success.
fn try_parse_prefix(
    data: &[u8],
    afi: &Afi,
    add_path: bool,
) -> Result<(NetworkPrefix, usize), ParserError> {
    let mut pos = 0;

    // Read path_id if add_path
    let path_id = if add_path {
        if data.len() < pos + 4 {
            return Err(ParserError::TruncatedMsg("truncated path_id".to_string()));
        }
        let id = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        Some(id)
    } else {
        None
    };

    // Read prefix length
    if data.len() < pos + 1 {
        return Err(ParserError::TruncatedMsg(
            "truncated prefix length".to_string(),
        ));
    }
    let bit_len = data[pos];
    pos += 1;

    // Validate prefix length
    let max_bit_len: u8 = match afi {
        Afi::Ipv4 => 32,
        Afi::Ipv6 => 128,
        // EVPN NLRI are decoded by their own parser; a bit-length prefix does
        // not apply to either family here.
        Afi::LinkState | Afi::L2vpn => 0,
    };

    if bit_len > max_bit_len {
        return Err(ParserError::ParseError(format!(
            "Invalid prefix length: {bit_len} (max {max_bit_len} for {afi:?})"
        )));
    }

    // Calculate bytes needed
    let byte_len = (bit_len as usize).div_ceil(8);

    // Parse address
    let addr: IpAddr = match afi {
        Afi::Ipv4 => {
            if byte_len > 4 {
                return Err(ParserError::ParseError(
                    "Invalid byte length for IPv4".to_string(),
                ));
            }
            if data.len() < pos + byte_len {
                return Err(ParserError::TruncatedMsg(
                    "truncated IPv4 prefix".to_string(),
                ));
            }
            let mut buff = [0u8; 4];
            buff[..byte_len].copy_from_slice(&data[pos..pos + byte_len]);
            pos += byte_len;
            IpAddr::V4(Ipv4Addr::from(buff))
        }
        Afi::Ipv6 => {
            if byte_len > 16 {
                return Err(ParserError::ParseError(
                    "Invalid byte length for IPv6".to_string(),
                ));
            }
            if data.len() < pos + byte_len {
                return Err(ParserError::TruncatedMsg(
                    "truncated IPv6 prefix".to_string(),
                ));
            }
            let mut buff = [0u8; 16];
            buff[..byte_len].copy_from_slice(&data[pos..pos + byte_len]);
            pos += byte_len;
            IpAddr::V6(Ipv6Addr::from(buff))
        }
        // Neither Link-State nor EVPN carries a traditional prefix here.
        Afi::LinkState | Afi::L2vpn => {
            pos += byte_len;
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        }
    };

    let prefix = IpNet::new(addr, bit_len).map_err(|_| {
        ParserError::ParseError(format!("Invalid network prefix length: {bit_len}"))
    })?;

    Ok((NetworkPrefix::new(prefix, path_id), pos))
}

/// Decode an NLRI block with a known ADD-PATH setting.
///
/// Every entry is decoded the same way, and an error discards the whole block: partially decoded
/// prefixes must not escape to the caller.
fn parse_nlri_list_exact(
    mut input: Bytes,
    add_path: bool,
    afi: &Afi,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    let mut prefixes = Vec::new();
    while input.remaining() > 0 {
        let (prefix, consumed) = try_parse_prefix(input.as_ref(), afi, add_path)?;
        input.advance(consumed);
        prefixes.push(prefix);
    }
    Ok(prefixes)
}

/// Parse an NLRI block, resolving a leading `0x00` byte that the ADD-PATH flag cannot explain.
///
/// A block starting with `0x00` is ambiguous. RFC 4271 §4.3 reads it as a prefix length of 0, the
/// default route. Some producers instead wrap an ADD-PATH message in a non-ADD-PATH record, where
/// the same byte is the first octet of a path identifier (issue #31), and guessing matters there:
/// without it almost three quarters of the elements of such a file disappear.
///
/// The guess is made over the whole block, and a block the ADD-PATH reading cannot consume falls
/// back to the flag. Retrying at the failure position, the previous behaviour, kept the prefixes
/// already decoded out of path-id bytes and dropped the real ones, which emptied or corrupted
/// withdrawal lists that begin with the default route (#360).
///
/// A plain block whose bytes also happen to frame exactly as ADD-PATH is still read as ADD-PATH:
/// the bytes carry nothing that decides between them, and on the data that motivated the guess the
/// ADD-PATH reading is the correct one (see `test_parse_nlri_list_ambiguous_block_prefers_add_path`).
/// A short block of that shape, `0.0.0.0/0` followed by one prefix, is still misread.
pub fn parse_nlri_list(
    input: Bytes,
    add_path: bool,
    afi: &Afi,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    if add_path {
        return parse_nlri_list_exact(input, true, afi);
    }
    if input.first() == Some(&0) {
        debug!("NLRI: block starts with 0x00, trying the ADD-PATH framing");
        if let Ok(prefixes) = parse_nlri_list_exact(input.clone(), true, afi) {
            return Ok(prefixes);
        }
        debug!("NLRI: the ADD-PATH framing does not consume the block, decoding with the flag");
    }
    parse_nlri_list_exact(input, false, afi)
}

pub fn encode_asn(asn: &Asn, asn_len: &AsnLength) -> Bytes {
    let mut bytes = BytesMut::new();
    match asn_len {
        AsnLength::Bits16 => bytes.put_u16(asn.into()),
        AsnLength::Bits32 => {
            bytes.put_u32(asn.into());
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

pub fn encode_nlri_prefixes(prefixes: &[NetworkPrefix]) -> Bytes {
    let mut bytes = BytesMut::new();
    for prefix in prefixes {
        bytes.extend(prefix.encode());
    }
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

/// Convert a f64 timestamp into u32 seconds and u32 microseconds.
///
/// # Arguments
///
/// * `timestamp` - The timestamp to convert.
///
/// # Returns
///
/// A tuple containing the converted seconds and microseconds.
///
/// # Example
///
/// ```rust
/// use bgpkit_parser::utils::convert_timestamp;
///
/// let timestamp = 1609459200.123456;
/// let (seconds, microseconds) = convert_timestamp(timestamp);
/// assert_eq!(seconds, 1609459200);
/// assert_eq!(microseconds, 123456);
/// ```
// convert f64 timestamp into u32 seconds and u32 microseconds
pub fn convert_timestamp(timestamp: f64) -> (u32, u32) {
    let seconds = timestamp as u32;
    let microseconds = ((timestamp - seconds as f64) * 1_000_000.0) as u32;
    (seconds, microseconds)
}

#[derive(Debug, Clone)]
pub struct ComparableRegex {
    pattern: String,
    regex: Regex,
}

impl PartialEq for ComparableRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl ComparableRegex {
    pub fn new(pattern: &str) -> Result<Self, ParserError> {
        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => {
                return Err(ParserError::FilterError(format!(
                    "Invalid regex pattern: {pattern}"
                )))
            }
        };
        Ok(ComparableRegex {
            pattern: pattern.to_string(),
            regex,
        })
    }

    pub fn is_match<S: AsRef<str>>(&self, text: S) -> bool {
        self.regex.is_match(text.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_read_u8() {
        let mut buf = Bytes::from_static(&[0x12]);
        assert_eq!(buf.read_u8().unwrap(), 0x12);
    }

    #[test]
    fn test_read_u16() {
        let mut buf = Bytes::from_static(&[0x12, 0x34]);
        assert_eq!(buf.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32() {
        let mut buf = Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(buf.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u64() {
        let mut buf = Bytes::from_static(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(buf.read_u64().unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_read_ipv4_address() {
        let mut buf = Bytes::from_static(&[0xC0, 0xA8, 0x01, 0x01]);
        assert_eq!(
            buf.read_ipv4_address().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
    }

    #[test]
    fn test_read_ipv6_address() {
        let mut buf = Bytes::from_static(&[
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70,
            0x73, 0x34,
        ]);
        assert_eq!(
            buf.read_ipv6_address().unwrap(),
            Ipv6Addr::new(0x2001, 0x0DB8, 0x85A3, 0x0000, 0x0000, 0x8A2E, 0x0370, 0x7334)
        );
    }

    #[test]
    fn test_read_address() {
        let mut buf = Bytes::from_static(&[0xC0, 0xA8, 0x01, 0x01]);
        assert_eq!(
            buf.read_address(&Afi::Ipv4).unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        let mut buf = Bytes::from_static(&[
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70,
            0x73, 0x34,
        ]);
        assert_eq!(
            buf.read_address(&Afi::Ipv6).unwrap(),
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0DB8, 0x85A3, 0x0000, 0x0000, 0x8A2E, 0x0370, 0x7334
            ))
        );

        let mut buf = Bytes::from_static(&[0xC0, 0xA8, 0x01]);
        assert!(buf.read_address(&Afi::Ipv4).is_err());

        let mut buf = Bytes::from_static(&[
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70,
            0x73,
        ]);
        assert!(buf.read_address(&Afi::Ipv6).is_err());
    }

    #[test]
    fn test_read_asn() {
        let mut buf = Bytes::from_static(&[0x00, 0x01]);
        assert_eq!(buf.read_asn(AsnLength::Bits16).unwrap(), Asn::new_16bit(1));

        let mut buf = Bytes::from_static(&[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(
            buf.read_asn(AsnLength::Bits32).unwrap(),
            Asn::new_32bit(256)
        );
    }

    #[test]
    fn read_asns() {
        let mut buf = Bytes::from_static(&[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            buf.read_asns(&AsnLength::Bits16, 2).unwrap(),
            vec![Asn::new_16bit(1), Asn::new_16bit(0)]
        );
    }

    #[test]
    fn test_read_afi() {
        let mut buf = Bytes::from_static(&[0x00, 0x01]);
        assert_eq!(buf.read_afi().unwrap(), Afi::Ipv4);

        let mut buf = Bytes::from_static(&[0x00, 0x02]);
        assert_eq!(buf.read_afi().unwrap(), Afi::Ipv6);
    }

    #[test]
    fn test_read_safi() {
        let mut buf = Bytes::from_static(&[0x01]);
        assert_eq!(buf.read_safi().unwrap(), Safi::Unicast);

        let mut buf = Bytes::from_static(&[0x02]);
        assert_eq!(buf.read_safi().unwrap(), Safi::Multicast);

        // RFC 8950 VPN SAFI values
        let mut buf = Bytes::from_static(&[0x80]); // 128 in hex
        assert_eq!(buf.read_safi().unwrap(), Safi::MplsVpn);

        let mut buf = Bytes::from_static(&[0x81]); // 129 in hex
        assert_eq!(buf.read_safi().unwrap(), Safi::MulticastVpn);
    }

    #[test]
    fn test_has_n_remaining() {
        let mut buf = Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]);
        assert!(buf.has_n_remaining(4).is_ok());
        assert!(buf.has_n_remaining(5).is_err());

        let _ = buf.read_u8().unwrap();
        assert!(buf.has_n_remaining(3).is_ok());
        assert!(buf.has_n_remaining(4).is_err());
    }

    #[test]
    fn test_read_ipv4_prefix() {
        let mut buf = Bytes::from_static(&[0xC0, 0xA8, 0x01, 0x01, 0x18]);
        assert_eq!(
            buf.read_ipv4_prefix().unwrap(),
            Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()
        );

        // Test with invalid IPv4 prefix mask, /33
        let mut buf = Bytes::from_static(&[0xC0, 0xA8, 0x01, 0x01, 0x21]);
        assert!(buf.read_ipv4_prefix().is_err());
    }

    #[test]
    fn test_read_ipv6_prefix() {
        let mut buf = Bytes::from_static(&[
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70,
            0x73, 0x34, 0x40,
        ]);
        assert_eq!(
            buf.read_ipv6_prefix().unwrap(),
            Ipv6Net::new(
                Ipv6Addr::new(0x2001, 0x0DB8, 0x85A3, 0x0000, 0x0000, 0x8A2E, 0x0370, 0x7334),
                64
            )
            .unwrap()
        );

        // Test with invalid IPv6 prefix mask, /129
        let mut buf = Bytes::from_static(&[
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70,
            0x73, 0x34, 0x81,
        ]);
        assert!(buf.read_ipv6_prefix().is_err());
    }

    #[test]
    fn test_read_n_bytes() {
        let mut buf = Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(buf.read_n_bytes(4).unwrap(), vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_read_n_bytes_to_string() {
        let mut buf = Bytes::from_static(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello" in ASCII
        assert_eq!(buf.read_n_bytes_to_string(5).unwrap(), "Hello");
    }

    #[test]
    fn test_crc32() {
        assert_eq!(crc32("Hello, World!"), "ec4ac3d0");
    }

    #[test]
    fn test_read_nlri_prefix() {
        let mut buf = Bytes::from_static(&[0x18, 0xC0, 0xA8, 0x01]);
        let expected = NetworkPrefix::new(
            IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
            None,
        );
        assert_eq!(buf.read_nlri_prefix(&Afi::Ipv4, false).unwrap(), expected);

        let mut buf = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0x18, 0xC0, 0xA8, 0x01]);
        let expected = NetworkPrefix::new(
            IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
            Some(1),
        );
        assert_eq!(buf.read_nlri_prefix(&Afi::Ipv4, true).unwrap(), expected);
    }

    #[test]
    fn test_read_nlri_prefix_length_validation() {
        // Test IPv4 prefix length > 32 (e.g., 33, 255) is rejected
        for invalid_len in [33u8, 255] {
            let mut buf = Bytes::from(vec![invalid_len, 0xC0, 0xA8, 0x01]);
            let result = buf.read_nlri_prefix(&Afi::Ipv4, false);
            assert!(
                result.is_err(),
                "IPv4 prefix length {} should be rejected",
                invalid_len
            );
            if let Err(ParserError::ParseError(msg)) = result {
                assert!(msg.contains("Invalid prefix length"));
            }
        }

        // Test IPv6 prefix length > 128 (e.g., 129, 255) is rejected
        for invalid_len in [129u8, 255] {
            let mut buf = Bytes::from(vec![invalid_len, 0x20, 0x01, 0x0D, 0xB8]);
            let result = buf.read_nlri_prefix(&Afi::Ipv6, false);
            assert!(
                result.is_err(),
                "IPv6 prefix length {} should be rejected",
                invalid_len
            );
            if let Err(ParserError::ParseError(msg)) = result {
                assert!(msg.contains("Invalid prefix length"));
            }
        }

        // Test valid IPv4 prefix lengths pass (0-32)
        for valid_len in [0u8, 1, 32] {
            // Provide enough bytes for any byte_len calculation
            let mut buf = Bytes::from(vec![valid_len, 0x00, 0x00, 0x00, 0x00]);
            let result = buf.read_nlri_prefix(&Afi::Ipv4, false);
            assert!(
                result.is_ok(),
                "IPv4 prefix length {} should be valid",
                valid_len
            );
        }

        // Test valid IPv6 prefix lengths pass (0-128)
        for valid_len in [0u8, 1, 64, 128] {
            // Provide enough bytes for any byte_len calculation (max 16 bytes)
            let buf_data: Vec<u8> = std::iter::once(valid_len)
                .chain(std::iter::repeat_n(0x00, 16))
                .collect();
            let mut buf = Bytes::from(buf_data);
            let result = buf.read_nlri_prefix(&Afi::Ipv6, false);
            assert!(
                result.is_ok(),
                "IPv6 prefix length {} should be valid",
                valid_len
            );
        }
    }

    #[test]
    fn test_encode_asn() {
        let asn = Asn::new_32bit(1);
        let asn_len = AsnLength::Bits32;
        let expected = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(encode_asn(&asn, &asn_len), expected);

        let asn = Asn::new_16bit(1);
        let asn_len = AsnLength::Bits16;
        let expected = Bytes::from_static(&[0x00, 0x01]);
        assert_eq!(encode_asn(&asn, &asn_len), expected);
    }

    #[test]
    fn test_encode_ipaddr() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let expected = vec![192, 168, 1, 1];
        assert_eq!(encode_ipaddr(&addr), expected);

        let addr = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0DB8, 0x85A3, 0x0000, 0x0000, 0x8A2E, 0x0370, 0x7334,
        ));
        let expected = vec![
            0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70,
            0x73, 0x34,
        ];
        assert_eq!(encode_ipaddr(&addr), expected);
    }

    #[test]
    fn test_encode_nlri_prefixes() {
        let prefixes = vec![
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
                None,
            ),
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 2, 0), 24).unwrap()),
                None,
            ),
        ];
        let expected = Bytes::from_static(&[0x18, 0xC0, 0xA8, 0x01, 0x18, 0xC0, 0xA8, 0x02]);
        assert_eq!(encode_nlri_prefixes(&prefixes), expected);

        let prefixes = vec![
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
                Some(1),
            ),
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 2, 0), 24).unwrap()),
                Some(1),
            ),
        ];
        let expected = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x01, 0x18, 0xC0, 0xA8, 0x01, 0x00, 0x00, 0x00, 0x01, 0x18, 0xC0,
            0xA8, 0x02,
        ]);
        assert_eq!(encode_nlri_prefixes(&prefixes), expected);
    }

    #[test]
    fn test_comparable_regex_functionality() {
        // Test valid pattern creation
        let regex1 = ComparableRegex::new(r"\d+").unwrap();
        let regex2 = ComparableRegex::new(r"\d+").unwrap();
        let regex3 = ComparableRegex::new(r"\w+").unwrap();

        // Verify pattern storage
        assert_eq!(regex1.pattern, r"\d+");
        assert_eq!(regex3.pattern, r"\w+");

        // Verify equality with same pattern
        assert_eq!(regex1, regex2);

        // Verify inequality with different patterns
        assert_ne!(regex1, regex3);

        // Verify regex matching functionality
        assert!(regex1.regex.is_match("123"));
        assert!(!regex1.regex.is_match("abc"));
    }

    #[test]
    #[should_panic(expected = "Invalid regex pattern")]
    fn test_comparable_regex_invalid_pattern_panic() {
        // Test invalid pattern creation
        ComparableRegex::new(r"(\d+").unwrap(); // Unclosed parenthesis should panic
    }

    #[test]
    fn test_parse_nlri_list() {
        // Test normal case with add_path=false
        let input = Bytes::from_static(&[0x18, 0xC0, 0xA8, 0x01, 0x18, 0xC0, 0xA8, 0x02]);
        let expected = vec![
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
                None,
            ),
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 2, 0), 24).unwrap()),
                None,
            ),
        ];
        assert_eq!(parse_nlri_list(input, false, &Afi::Ipv4).unwrap(), expected);

        // Test normal case with add_path=true
        let input = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x01, 0x18, 0xC0, 0xA8, 0x01, 0x00, 0x00, 0x00, 0x02, 0x18, 0xC0,
            0xA8, 0x02,
        ]);
        let expected = vec![
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
                Some(1),
            ),
            NetworkPrefix::new(
                IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 2, 0), 24).unwrap()),
                Some(2),
            ),
        ];
        assert_eq!(parse_nlri_list(input, true, &Afi::Ipv4).unwrap(), expected);

        // Test the auto-detection of add_path when first byte is 0
        let input = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0x18, 0xC0, 0xA8, 0x01]);
        let expected = vec![NetworkPrefix::new(
            IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()),
            Some(1),
        )];
        assert_eq!(parse_nlri_list(input, false, &Afi::Ipv4).unwrap(), expected);
    }

    #[test]
    fn test_convert_timestamp() {
        // Test integer timestamp
        let (seconds, microseconds) = convert_timestamp(1609459200.0);
        assert_eq!(seconds, 1609459200);
        assert_eq!(microseconds, 0);

        // Test fractional timestamp
        let (seconds, microseconds) = convert_timestamp(1609459200.123456);
        assert_eq!(seconds, 1609459200);
        assert_eq!(microseconds, 123456);

        // Test rounding
        let (seconds, microseconds) = convert_timestamp(1609459200.1234567);
        assert_eq!(seconds, 1609459200);
        assert_eq!(microseconds, 123456); // Should round to microseconds
    }

    #[test]
    fn test_parse_nlri_list_add_path_heuristic() {
        // Test the Add-Path heuristic: first byte is 0 suggests path_id = 0
        // This tests the memory-optimized lazy clone behavior

        // Valid Add-Path NLRI with path_id = 0: [0x00, 0x00, 0x00, 0x00, prefix_len, prefix_bytes...]
        let input = Bytes::from(vec![
            0x00, 0x00, 0x00, 0x00, // path_id = 0
            0x18, // prefix_len = 24 bits
            0xC0, 0xA8, 0x01, // 192.168.1 prefix
        ]);

        // With add_path=false, the heuristic should trigger (first byte is 0)
        // and parse successfully with Add-Path format
        let result = parse_nlri_list(input, false, &Afi::Ipv4);
        assert!(
            result.is_ok(),
            "Add-Path heuristic should parse successfully"
        );

        let prefixes = result.unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(
            prefixes[0].prefix.addr(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))
        );
        assert_eq!(prefixes[0].prefix.prefix_len(), 24);
        assert_eq!(prefixes[0].path_id, Some(0));
    }

    #[test]
    fn test_parse_nlri_list_non_addpath_with_zero_prefix() {
        // Edge case: Non-Add-Path NLRI where the first prefix byte happens to be 0
        // This could trigger a false positive in the heuristic
        // Example: /0 default route would start with byte 0

        // Non-Add-Path NLRI for 0.0.0.0/0 (default route)
        // Format: [prefix_len, prefix_bytes...]
        let input = Bytes::from(vec![
            0x00, // prefix_len = 0 (default route)
                 // No prefix bytes needed for /0
        ]);

        // This might trigger the heuristic (first byte is 0)
        // The optimized code should handle the retry correctly
        let result = parse_nlri_list(input, false, &Afi::Ipv4);

        // Should either parse successfully or return an error
        // The key point is it shouldn't panic
        match result {
            Ok(prefixes) => {
                // If parsed, should be the default route
                if !prefixes.is_empty() {
                    assert_eq!(prefixes[0].prefix.prefix_len(), 0);
                }
            }
            Err(_) => {
                // Error is acceptable - the heuristic might fail on this edge case
                // The important thing is we don't panic
            }
        }
    }

    #[test]
    fn test_parse_nlri_list_multiple_prefixes_with_addpath() {
        // Test multiple prefixes with Add-Path enabled
        // This would have caught the bug where we dropped the clone after first prefix

        // Two prefixes with path_id = 0:
        // [path_id=0, len=24, 192.168.1] [path_id=0, len=24, 192.168.2]
        let input = Bytes::from(vec![
            // First prefix
            0x00, 0x00, 0x00, 0x00, // path_id = 0
            0x18, // prefix_len = 24 bits
            0xC0, 0xA8, 0x01, // 192.168.1
            // Second prefix
            0x00, 0x00, 0x00, 0x00, // path_id = 0
            0x18, // prefix_len = 24 bits
            0xC0, 0xA8, 0x02, // 192.168.2
        ]);

        // With add_path=false, heuristic should trigger and parse both
        let result = parse_nlri_list(input, false, &Afi::Ipv4);
        assert!(result.is_ok(), "Should parse multiple Add-Path prefixes");

        let prefixes = result.unwrap();
        assert_eq!(prefixes.len(), 2, "Should have 2 prefixes");

        // First prefix
        assert_eq!(
            prefixes[0].prefix.addr(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))
        );
        assert_eq!(prefixes[0].prefix.prefix_len(), 24);
        assert_eq!(prefixes[0].path_id, Some(0));

        // Second prefix
        assert_eq!(
            prefixes[1].prefix.addr(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 0))
        );
        assert_eq!(prefixes[1].prefix.prefix_len(), 24);
        assert_eq!(prefixes[1].path_id, Some(0));
    }

    #[test]
    fn test_parse_nlri_list_ipv6_addpath() {
        // Test IPv6 NLRI with Add-Path
        let input = Bytes::from(vec![
            // path_id = 1
            0x00, 0x00, 0x00, 0x01, // prefix_len = 64 bits
            0x40, // 2001:db8::/64 (first 8 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        ]);

        let result = parse_nlri_list(input, true, &Afi::Ipv6);
        assert!(result.is_ok(), "Should parse IPv6 Add-Path prefix");

        let prefixes = result.unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix.prefix_len(), 64);
        assert_eq!(prefixes[0].path_id, Some(1));
    }

    #[test]
    fn test_parse_nlri_list_explicit_addpath_nonzero_path_id() {
        // Test with explicit add_path=true and non-zero path_id
        let input = Bytes::from(vec![
            0x00, 0x00, 0x00, 0xFF, // path_id = 255
            0x18, // prefix_len = 24 bits
            0xC0, 0xA8, 0x01, // 192.168.1
        ]);

        let result = parse_nlri_list(input, true, &Afi::Ipv4);
        assert!(result.is_ok());

        let prefixes = result.unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].path_id, Some(255));
    }

    #[test]
    fn test_parse_nlri_list_empty() {
        // Empty input should return empty vec
        let input = Bytes::from(vec![]);
        let result = parse_nlri_list(input, false, &Afi::Ipv4);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_nlri_list_truncated_data() {
        // Truncated data should return error, not panic
        let input = Bytes::from(vec![
            0x18, // prefix_len = 24 bits (claims 3 bytes)
            0xC0, // but only 1 byte provided
        ]);

        let result = parse_nlri_list(input, false, &Afi::Ipv4);
        assert!(result.is_err(), "Should error on truncated data");
    }

    #[test]
    fn test_parse_nlri_list_single_default_route() {
        // A lone 0x00 is a prefix length of 0 with no address octets: the default route.
        let prefixes = parse_nlri_list(Bytes::from_static(&[0x00]), false, &Afi::Ipv4).unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix.to_string(), "0.0.0.0/0");
        assert_eq!(prefixes[0].path_id, None);
    }

    // A block whose first prefix is the default route is not an ADD-PATH block. Reading the 0x00 as
    // a path identifier shifted the decode and dropped or invented withdrawals (#360).
    fn assert_ipv4_block(block: &'static [u8], expected: &[&str]) {
        let prefixes = parse_nlri_list(Bytes::from_static(block), false, &Afi::Ipv4).unwrap();
        let got: Vec<String> = prefixes.iter().map(|p| p.prefix.to_string()).collect();
        assert_eq!(got, expected);
        assert!(
            prefixes.iter().all(|p| p.path_id.is_none()),
            "non-ADD-PATH block must not produce path ids"
        );
    }

    #[test]
    fn test_parse_nlri_list_non_addpath_default_route_at_head() {
        assert_ipv4_block(
            &[
                0x00, // 0.0.0.0/0
                0x18, 0x01, 0x00, 0x00, // 1.0.0.0/24
                0x18, 0x01, 0x00, 0x04, // 1.0.4.0/24
                0x18, 0x01, 0x00, 0x05, // 1.0.5.0/24
                0x18, 0x01, 0x00, 0x06, // 1.0.6.0/24
            ],
            &[
                "0.0.0.0/0",
                "1.0.0.0/24",
                "1.0.4.0/24",
                "1.0.5.0/24",
                "1.0.6.0/24",
            ],
        );
    }

    #[test]
    fn test_parse_nlri_list_non_addpath_default_route_in_middle() {
        assert_ipv4_block(
            &[
                0x18, 0x01, 0x00, 0x00, // 1.0.0.0/24
                0x00, // 0.0.0.0/0
                0x18, 0x01, 0x00, 0x04, // 1.0.4.0/24
            ],
            &["1.0.0.0/24", "0.0.0.0/0", "1.0.4.0/24"],
        );
    }

    #[test]
    fn test_parse_nlri_list_non_addpath_default_route_at_tail() {
        assert_ipv4_block(
            &[
                0x18, 0x01, 0x00, 0x00, // 1.0.0.0/24
                0x18, 0x01, 0x00, 0x04, // 1.0.4.0/24
                0x00, // 0.0.0.0/0
            ],
            &["1.0.0.0/24", "1.0.4.0/24", "0.0.0.0/0"],
        );
    }

    #[test]
    fn test_parse_nlri_list_non_addpath_ipv6_default_route_at_head() {
        let block = &[
            0x00, // ::/0
            0x30, 0x2a, 0x0a, 0x02, 0xc0, 0x00, 0x1a, // 2a0a:2c0:1a::/48
            0x2a, 0x26, 0x20, 0x01, 0x29, 0x20, 0x00, // 2620:129:2000::/42
            0x20, 0x28, 0x04, 0x50, 0x5c, // 2804:505c::/32
        ];
        let prefixes = parse_nlri_list(Bytes::from_static(block), false, &Afi::Ipv6).unwrap();
        let got: Vec<String> = prefixes.iter().map(|p| p.prefix.to_string()).collect();
        assert_eq!(
            got,
            vec![
                "::/0",
                "2a0a:2c0:1a::/48",
                "2620:129:2000::/42",
                "2804:505c::/32"
            ]
        );
        assert!(prefixes.iter().all(|p| p.path_id.is_none()));
    }

    #[test]
    fn test_parse_nlri_list_ambiguous_block_prefers_add_path() {
        // Bytes from route-views.amsix 2020-06-17 18:30 UTC: ADD-PATH data under a non-ADD-PATH
        // subtype, one entry. Framing it without path ids yields a run of /0 prefixes, framing it
        // with them yields the real route. Both readings consume the block, and this is the reading
        // the data requires, so the guess stays on ties.
        let block = &[0x00, 0x00, 0x01, 0xe2, 0x18, 0x8a, 0x61, 0x16];
        // Both readings have to consume the block for this to be the tie the wrapper resolves.
        let framed = parse_nlri_list_exact(Bytes::from_static(block), false, &Afi::Ipv4).unwrap();
        assert_eq!(framed.len(), 4);
        assert!(framed.iter().all(|p| p.path_id.is_none()));
        let plain = parse_nlri_list(Bytes::from_static(block), false, &Afi::Ipv4).unwrap();
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].prefix.to_string(), "138.97.22.0/24");
        assert_eq!(plain[0].path_id, Some(482));
    }

    #[test]
    fn test_parse_nlri_list_short_ambiguous_block_is_read_as_add_path() {
        // 0.0.0.0/0 followed by one /24 also frames exactly as a single ADD-PATH entry, so the
        // guess stays on and the /24 is lost. The bytes decide nothing here; the limitation is
        // deliberate and recorded in the CHANGELOG.
        let block = &[0x00, 0x18, 0x01, 0x00, 0x00];
        let prefixes = parse_nlri_list(Bytes::from_static(block), false, &Afi::Ipv4).unwrap();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(prefixes[0].prefix.to_string(), "0.0.0.0/0");
        assert!(prefixes[0].path_id.is_some());
    }

    #[test]
    fn test_parse_nlri_list_wrapped_addpath_block_keeps_path_ids() {
        // ADD-PATH data under a non-ADD-PATH flag still has to decode with its path ids (#31).
        let block = &[
            0x00, 0x00, 0x00, 0x01, 0x18, 0xc0, 0xa8, 0x01, // path_id 1, 192.168.1.0/24
            0x00, 0x00, 0x00, 0x02, 0x18, 0xc0, 0xa8, 0x02, // path_id 2, 192.168.2.0/24
        ];
        let prefixes = parse_nlri_list(Bytes::from_static(block), false, &Afi::Ipv4).unwrap();
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].prefix.to_string(), "192.168.1.0/24");
        assert_eq!(prefixes[1].prefix.to_string(), "192.168.2.0/24");
        assert_eq!(prefixes[0].path_id, Some(1));
        assert_eq!(prefixes[1].path_id, Some(2));
    }
}
