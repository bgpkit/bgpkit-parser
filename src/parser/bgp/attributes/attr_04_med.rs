use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;

pub fn parse_med(mut input: &[u8]) -> Result<AttributeValue, ParserError> {
    input.expect_remaining_eq(4, "MULTI_EXIT_DISCRIMINATOR")?;
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
