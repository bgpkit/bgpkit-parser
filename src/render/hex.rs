//! Hex encoding of record bytes.
//!
//! One record, one lowercase hex string — the paste format for
//! byte-level tools (e.g. wirescope's hex input). Encoding operates on
//! the record's *original* bytes (see
//! [`BgpkitParser::into_filtered_raw_record_iter`](crate::BgpkitParser::into_filtered_raw_record_iter)), never on a
//! re-encoding of the parsed model, so attribute ordering quirks (e.g.
//! BGP-LS hash-map iteration order) cannot alter the output.

/// Encode bytes as a single lowercase hex string (no separators).
///
/// Writes the two digits directly into the output buffer; no
/// per-byte allocations.
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_golden_values() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(encode(&[0xff, 0x10, 0x0a]), "ff100a");
    }

    #[test]
    fn encodes_all_byte_values_lowercase() {
        let all: Vec<u8> = (0..=255u8).collect();
        let hex = encode(&all);
        assert_eq!(hex.len(), 512);
        assert!(!hex.contains(|c: char| c.is_uppercase()));
        // spot checks across the range
        assert_eq!(&hex[0..2], "00");
        assert_eq!(&hex[9 * 2..10 * 2], "09");
        assert_eq!(&hex[10 * 2..12 * 2], "0a0b");
        assert_eq!(&hex[510..512], "ff");
    }
}
