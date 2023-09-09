use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::Bytes;

pub fn parse_local_pref(mut input: Bytes) -> Result<AttributeValue, ParserError> {
    input.expect_remaining_eq(4, "LOCAL_PREFERENCE")?;
    Ok(AttributeValue::LocalPreference(input.read_u32()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_med() {
        if let Ok(AttributeValue::LocalPreference(123)) =
            parse_local_pref(Bytes::from(vec![0, 0, 0, 123]))
        {
        } else {
            panic!()
        }
    }
}
