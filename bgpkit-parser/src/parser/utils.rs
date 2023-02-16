/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
*/
use ipnet::{Ipv4Net, Ipv6Net, IpNet};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
use std::convert::TryInto;

use num_traits::FromPrimitive;
use std::net::IpAddr;
use bgp_models::network::{Afi, Asn, AsnLength, NetworkPrefix, Safi};
use log::debug;

use crate::error::ParserError;

pub struct DataBytes<'input> {
    pub bytes: &'input [u8],
    pub pos: usize,
    pub total: usize,
}

// Allow reading IPs from Reads
impl  DataBytes <'_>{

    pub fn new(data: &Vec<u8>) -> DataBytes{
        DataBytes{
            bytes: data.as_slice(),
            pos: 0,
            total: data.len(),
        }
    }

    #[inline]
    pub fn bytes_left(&self) -> usize {
        self.total - self.pos
    }

    #[inline]
    pub fn read_128b(&mut self) -> Result<u128, ParserError> {
        let len = 16;
        if self.total - self.pos < len {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos += len;
        Ok( u128::from_be_bytes(self.bytes[self.pos-len..self.pos].try_into().unwrap()) )
    }

    #[inline]
    pub fn read_64b(&mut self) -> Result<u64, ParserError> {
        let len = 8;
        if self.total - self.pos < len {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos += len;
        Ok( u64::from_be_bytes(self.bytes[self.pos-len..self.pos].try_into().unwrap()) )
    }

    #[inline]
    pub fn read_32b(&mut self) -> Result<u32, ParserError> {
        let len = 4;
        if self.total - self.pos < len {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos += len;
        Ok( u32::from_be_bytes(self.bytes[self.pos-len..self.pos].try_into().unwrap()) )
    }

    #[inline]
    pub fn read_16b(&mut self) -> Result<u16, ParserError> {
        let len = 2;
        if self.total - self.pos < len {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos += len;
        Ok( u16::from_be_bytes(self.bytes[self.pos-len..self.pos].try_into().unwrap()) )
    }

    #[inline]
    pub fn read_8b(&mut self) -> Result<u8, ParserError> {
        let len = 1;
        if self.total - self.pos < len {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos += len;
        Ok( self.bytes[self.pos-len] )
    }

    pub fn read_n_bytes(&mut self, n_bytes: usize) -> Result<Vec<u8>, ParserError>{
        if self.total - self.pos < n_bytes {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos += n_bytes;
        Ok(self.bytes[self.pos-n_bytes..self.pos].to_vec())
    }

    pub fn read_n_bytes_to_string(&mut self, n_bytes: usize) -> Result<String, ParserError>{
        let buffer = self.read_n_bytes(n_bytes)?;
        Ok(buffer.into_iter().map(|x:u8| x as char).collect::<String>())
    }

    pub fn read_and_drop_n_bytes(&mut self, n_bytes: usize) -> Result<(), ParserError>{
        if self.total - self.pos < n_bytes {
            return Err(ParserError::IoNotEnoughBytes())
        }
        self.pos+=n_bytes;
        Ok(())
    }

    pub fn fast_forward(&mut self, to: usize) {
        self.pos = to;
    }

    /// Read announced/withdrawn prefix.
    ///
    /// The length in bits is 1 byte, and then based on the IP version it reads different number of bytes.
    /// If the `add_path` is true, it will also first read a 4-byte path id first; otherwise, a path-id of 0
    /// is automatically set.
    pub fn read_nlri_prefix(&mut self, afi: &Afi, add_path: bool) -> Result<NetworkPrefix, ParserError> {

        let path_id = if add_path {
            self.read_32b()?
        } else {
            0
        };

        // Length in bits
        let bit_len = self.read_8b()?;

        // Convert to bytes
        let byte_len: usize = (bit_len as usize + 7) / 8;
        let addr:IpAddr = match afi {
            Afi::Ipv4 => {

                // 4 bytes -- u32
                if byte_len>4 {
                    return Err(ParserError::ParseError(format!("Invalid byte length for IPv4 prefix. byte_len: {}, bit_len: {}", byte_len, bit_len)))
                }
                let mut buff = [0; 4];
                for i in 0..byte_len {
                    buff[i] = self.read_8b()?
                }
                IpAddr::V4(Ipv4Addr::from(buff))
            }
            Afi::Ipv6 => {
                // 16 bytes
                if byte_len>16 {
                    return Err(ParserError::ParseError(format!("Invalid byte length for IPv6 prefix. byte_len: {}, bit_len: {}", byte_len, bit_len)))
                }
                let mut buff = [0; 16];
                for i in 0..byte_len {
                    buff[i] = self.read_8b()?
                }
                IpAddr::V6(Ipv6Addr::from(buff))
            }
        };
        let prefix = match IpNet::new(addr, bit_len) {
            Ok(p) => {p}
            Err(_) => {
                return Err(ParserError::ParseError(format!("Invalid network prefix length: {}", bit_len)))
            }
        };

        Ok(NetworkPrefix::new(prefix, path_id))
    }

    pub fn read_address(&mut self, afi: &Afi) -> io::Result<IpAddr> {
        match afi {
            Afi::Ipv4 => {
                match self.read_ipv4_address(){
                    Ok(ip) => Ok(IpAddr::V4(ip)),
                    _ => Err(io::Error::new(io::ErrorKind::Other, "Cannot parse IPv4 address".to_string()))
                }
            },
            Afi::Ipv6 => {
                match self.read_ipv6_address(){
                    Ok(ip) => Ok(IpAddr::V6(ip)),
                    _ => Err(io::Error::new(io::ErrorKind::Other, "Cannot parse IPv6 address".to_string()))
                }
            },
        }
    }

    pub fn read_ipv4_address(&mut self) -> Result<Ipv4Addr, ParserError> {
        let addr = self.read_32b()?;
        Ok(Ipv4Addr::from(addr))
    }

    pub fn read_ipv6_address(&mut self) -> Result<Ipv6Addr, ParserError> {
        let buf = self.read_128b()?;
        Ok(Ipv6Addr::from(buf))
    }

    pub fn read_ipv4_prefix(&mut self) -> Result<Ipv4Net, ParserError> {
        let addr = self.read_ipv4_address()?;
        let mask = self.read_8b()?;
        match Ipv4Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    pub fn read_ipv6_prefix(&mut self) -> Result<Ipv6Net, ParserError> {
        let addr = self.read_ipv6_address()?;
        let mask = self.read_8b()?;
        match Ipv6Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    pub fn read_asn(&mut self, as_length: &AsnLength) -> Result<Asn, ParserError> {
        match as_length {
            AsnLength::Bits16 => {
                let asn = self.read_16b()? as u32;
                Ok(
                    Asn{
                        asn,
                        len: AsnLength::Bits16
                    }
                )
            },
            AsnLength::Bits32 => {
                let asn = self.read_32b()? as u32;
                Ok(
                    Asn{
                        asn,
                        len: AsnLength::Bits32
                    }
                )
            },
        }
    }

    pub fn read_asns(&mut self, as_length: &AsnLength, count: usize) -> Result<Vec<Asn>, ParserError> {
        let mut path  = [0;255];
        Ok(
            match as_length {
                AsnLength::Bits16 => {
                    for i in 0..count {
                        path[i] = self.read_16b()? as u32;
                        // path.push();
                    }
                    path[..count].iter().map(|asn| Asn{asn:*asn, len: *as_length}).collect::<Vec<Asn>>()
                }
                AsnLength::Bits32 => {
                    for i in 0..count {
                        // path.push(Asn{asn: self.read_32b()? as i32, len: *as_length});
                        path[i] = self.read_32b()? as u32;
                    }
                    path[..count].iter().map(|asn| Asn{asn:*asn, len: *as_length}).collect::<Vec<Asn>>()
                }
            }
        )
    }

    pub fn read_afi(&mut self) -> Result<Afi, ParserError> {
        let afi = self.read_16b()?;
        match Afi::from_i16(afi as i16) {
            Some(afi) => Ok(afi),
            None => {
                Err(crate::error::ParserError::Unsupported(format!("Unknown AFI type: {}", afi)))
            },
        }
    }

    pub fn read_safi(&mut self) -> Result<Safi, ParserError> {
        let safi = self.read_8b()?;
        match Safi::from_u8(safi) {
            Some(safi) => Ok(safi),
            None => Err(crate::error::ParserError::Unsupported(format!("Unknown SAFI type: {}", safi)))
        }
    }

    pub fn parse_nlri_list(
        &mut self,
        add_path: bool,
        afi: &Afi,
        total_bytes: usize,
    ) -> Result<Vec<NetworkPrefix>, ParserError> {
        let pos_end = self.pos + total_bytes;

        let mut is_add_path = add_path;
        let mut prefixes = vec![];

        let mut retry = false;
        let mut guessed = false;

        let pos_save = self.pos;

        while self.pos < pos_end {
            if !is_add_path && self.bytes[self.pos]==0 {
                // it's likely that this is a add-path wrongfully wrapped in non-add-path msg
                debug!("not add-path but with NLRI size to be 0, likely add-path msg in wrong msg type, treat as add-path now");
                is_add_path = true;
                guessed = true;
            }
            let prefix = match self.read_nlri_prefix(afi, is_add_path){
                Ok(p) => {p}
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
            self.pos = pos_save;
            while self.pos < pos_end {
                let prefix = self.read_nlri_prefix(afi, add_path)?;
                prefixes.push(prefix);
            }
        }

        Ok(prefixes)
    }
}
// Allow reading IPs from Reads
pub trait ReadUtils: io::Read {
    #[inline]
    fn read_32b(&mut self) -> io::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    #[inline]
    fn read_16b(&mut self) -> io::Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
}

// All types that implement Read can now read prefixes
impl<R: io::Read> ReadUtils for R {}
