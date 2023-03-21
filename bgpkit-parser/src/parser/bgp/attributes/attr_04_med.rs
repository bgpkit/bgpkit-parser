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
