use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

pub fn parse_med(input: &mut Cursor<&[u8]>) -> Result<AttributeValue, ParserError> {
    match input.read_32b() {
        Ok(v) => Ok(AttributeValue::MultiExitDiscriminator(v)),
        Err(err) => Err(ParserError::from(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_med() {
        if let Ok(AttributeValue::MultiExitDiscriminator(123)) =
            parse_med(&mut Cursor::new(&[0, 0, 0, 123]))
        {
        } else {
            panic!()
        }
    }
}
