use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

pub fn parse_local_pref(input: &mut Cursor<&[u8]>) -> Result<AttributeValue, ParserError> {
    match input.read_32b() {
        Ok(v) => Ok(AttributeValue::LocalPreference(v)),
        Err(err) => Err(ParserError::from(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_med() {
        if let Ok(AttributeValue::LocalPreference(123)) =
            parse_local_pref(&mut Cursor::new(&[0, 0, 0, 123]))
        {
        } else {
            panic!()
        }
    }
}
