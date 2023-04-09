use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;

pub fn parse_med(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    Ok(AttributeValue::MultiExitDiscriminator(input.read_u32()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_med() {
        if let Ok(AttributeValue::MultiExitDiscriminator(123)) =
            parse_med(Bytes::from(vec![0, 0, 0, 123]))
        {
        } else {
            panic!()
        }
    }
}
