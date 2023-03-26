use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::{AttributeValue, Origin};
use num_traits::FromPrimitive;
use std::io::Cursor;

pub fn parse_origin(input: &mut Cursor<&[u8]>) -> Result<AttributeValue, ParserError> {
    let origin = input.read_8b()?;
    match Origin::from_u8(origin) {
        Some(v) => Ok(AttributeValue::Origin(v)),
        None => Err(ParserError::UnknownAttr(
            "Failed to parse attribute type: origin".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test parse origin
    /// ```text
    /// ORIGIN is a well-known mandatory attribute that defines the
    ///        origin of the path information.  The data octet can assume
    ///        the following values:
    ///
    ///           Value      Meaning
    ///
    ///           0         IGP - Network Layer Reachability Information
    ///                        is interior to the originating AS
    ///
    ///           1         EGP - Network Layer Reachability Information
    ///                        learned via the EGP protocol [RFC904]
    ///
    ///           2         INCOMPLETE - Network Layer Reachability
    ///                        Information learned by some other means
    ///
    /// Usage of this attribute is defined in 5.1.1.
    /// ```
    #[test]
    fn test_parse_origin() {
        assert_eq!(
            AttributeValue::Origin(Origin::IGP),
            parse_origin(&mut Cursor::new(&[0u8])).unwrap()
        );
        assert_eq!(
            AttributeValue::Origin(Origin::EGP),
            parse_origin(&mut Cursor::new(&[1u8])).unwrap()
        );
        assert_eq!(
            AttributeValue::Origin(Origin::INCOMPLETE),
            parse_origin(&mut Cursor::new(&[2u8])).unwrap()
        );
        assert!(matches!(
            parse_origin(&mut Cursor::new(&[3u8])).unwrap_err(),
            ParserError::UnknownAttr(_)
        ));
    }
}
