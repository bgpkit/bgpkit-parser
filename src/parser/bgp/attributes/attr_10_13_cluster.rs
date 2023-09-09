use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;

/// <https://tools.ietf.org/html/rfc4456>
pub fn parse_clusters(mut input: &[u8]) -> Result<AttributeValue, ParserError> {
    let mut clusters = Vec::with_capacity(input.remaining() / 4);
    while input.remaining() > 0 {
        clusters.push(input.read_u32()?);
    }
    Ok(AttributeValue::Clusters(clusters))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clusters() {
        if let Ok(AttributeValue::Clusters(n)) =
            parse_clusters(&[0xC0, 0x00, 0x02, 0x01, 0xC0, 0x00, 0x02, 0x02])
        {
            assert_eq!(n.len(), 2);
            assert_eq!(n[0], 0xC0000201);
            assert_eq!(n[1], 0xC0000202);
        } else {
            panic!()
        }
    }
}
