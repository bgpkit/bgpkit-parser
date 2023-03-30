use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use std::io::{Cursor, Seek, SeekFrom};
use std::net::IpAddr;

///
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                   Magic Number (0x4F424D50)                   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |   Major Ver.  |   Minor Ver.  |         Header Length         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                        Message Length                         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     Flags     |   Obj. Type   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                   Coll. Timestamp (seconds)                   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                 Coll. Timestamp (microseconds)                |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                   Collector Hash (16 bytes)                   |
///  ~                                                               ~
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     Coll. Admin ID Length     |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                   Coll. Admin ID (variable)                   |
///  ~                                                               ~
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    Router Hash (16 bytes)                     |
///  ~                                                               ~
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     Router IP (16 bytes)                      |
///  ~                                                               ~
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |      Router Group Length      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    Router Group (variable)                    |
///  ~                                                               ~
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                           Row Count                           |
///  +---------------------------------------------------------------+
/// ```
#[derive(Debug)]
pub struct OpenBmpHeader {
    pub major_version: u8,
    pub minor_version: u8,
    /// Total number of bytes in the header (including version and header length fields)
    pub header_len: u16,
    /// Number of "data" bytes following the header
    pub msg_len: u32,
    pub object_type: u8,
    pub timestamp: f64,
    pub admin_id: String,
    pub router_ip: IpAddr,
    pub router_group: Option<String>,
}

pub fn parse_openbmp_header(reader: &mut Cursor<&[u8]>) -> Result<OpenBmpHeader, ParserBmpError> {
    // read magic number
    let magic_number = reader.read_n_bytes_to_string(4)?;
    if magic_number != "OBMP" {
        return Err(ParserBmpError::InvalidOpenBmpHeader);
    }

    // read version numbers
    let version_major = reader.read_8b()?;
    let version_minor = reader.read_8b()?;
    if (version_major, version_minor) != (1, 7) {
        return Err(ParserBmpError::InvalidOpenBmpHeader);
    }

    // read msg lengths
    let header_len = reader.read_16b()?;
    let msg_len = reader.read_32b()?;

    // read flags
    let flags = reader.read_8b()?;
    let (is_router_msg, is_router_ipv6) = (flags & 0x80 != 0, flags & 0x40 != 0);
    if !is_router_msg {
        return Err(ParserBmpError::UnsupportedOpenBmpMessage);
    }

    // read object type
    let object_type = reader.read_8b()?;
    if object_type != 12 {
        return Err(ParserBmpError::UnsupportedOpenBmpMessage);
    }

    // read_timestamp
    let t_sec = reader.read_32b()?;
    let t_usec = reader.read_32b()?;
    let timestamp = t_sec as f64 + (t_usec as f64) / 1_000_000.0;

    // read admin-id
    reader.seek(SeekFrom::Current(16))?;
    let mut name_len = reader.read_16b()?;
    if name_len > 255 {
        name_len = 255;
    }
    let admin_id = reader.read_n_bytes_to_string(name_len as usize)?;

    // read router IP
    reader.seek(SeekFrom::Current(16))?;
    let ip: IpAddr = if is_router_ipv6 {
        reader.read_ipv6_address()?.into()
    } else {
        let ip = reader.read_ipv4_address()?;
        reader.seek(SeekFrom::Current(12))?;
        ip.into()
    };

    // read router group
    let group = match reader.read_16b()? {
        0 => "".to_string(),
        n => reader.read_n_bytes_to_string(n as usize)?,
    };

    // read msg count
    let row_count = reader.read_32b()?;
    if row_count != 1 {
        return Err(ParserBmpError::InvalidOpenBmpHeader);
    }

    Ok(OpenBmpHeader {
        major_version: version_major,
        minor_version: version_minor,
        header_len,
        msg_len,
        object_type,
        timestamp,
        admin_id,
        router_ip: ip,
        router_group: Some(group),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_bmp_header() {
        let input = "4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000000000000000003fda060e00000da30000000061523c36000c0e1c0200000a";
        let decoded = hex::decode(input).unwrap();
        let mut reader = Cursor::new(decoded.as_slice());
        let _header = parse_openbmp_header(&mut reader).unwrap();
    }
}
