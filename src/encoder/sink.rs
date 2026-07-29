//! Sink-style encoding helpers.
//!
//! All "write a length prefix, then the payload" logic in the crate funnels
//! through these helpers. They write a placeholder length, encode the payload
//! into the same buffer, then back-patch the measured length — checking it
//! against the field's capacity. If the payload encoder fails, or the measured
//! length overflows, the buffer is rolled back to its pre-call state so a
//! failed encode never leaves dirty bytes behind.

use crate::error::EncodingError;
use bytes::{BufMut, BytesMut};

/// Check that `n` fits within `max`, returning [`EncodingError::ValueTooLarge`]
/// otherwise. Use for element counts and non-power-of-two byte bounds that are
/// written at a known position (not back-patched).
pub(crate) fn check_max(field: &'static str, n: usize, max: usize) -> Result<usize, EncodingError> {
    if n > max {
        Err(EncodingError::too_large(field, n, max))
    } else {
        Ok(n)
    }
}

/// Encode `f`'s payload with a 1-octet length prefix, back-patched after
/// encoding. Errors if the payload exceeds 255 bytes or `f` fails; in both
/// cases `buf` is rolled back to its pre-call length.
pub(crate) fn with_u8_len(
    buf: &mut BytesMut,
    field: &'static str,
    f: impl FnOnce(&mut BytesMut) -> Result<(), EncodingError>,
) -> Result<(), EncodingError> {
    let at = buf.len();
    buf.put_u8(0); // placeholder
    if let Err(e) = f(buf) {
        buf.truncate(at);
        return Err(e);
    }
    let len = buf.len() - at - 1;
    let Ok(len) = u8::try_from(len) else {
        let actual = buf.len() - at - 1;
        buf.truncate(at);
        return Err(EncodingError::too_large(field, actual, u8::MAX as usize));
    };
    buf[at] = len;
    Ok(())
}

/// Encode `f`'s payload with a 2-octet length prefix, back-patched after
/// encoding. Errors if the payload exceeds 65535 bytes or `f` fails; in both
/// cases `buf` is rolled back to its pre-call length.
pub(crate) fn with_u16_len(
    buf: &mut BytesMut,
    field: &'static str,
    f: impl FnOnce(&mut BytesMut) -> Result<(), EncodingError>,
) -> Result<(), EncodingError> {
    let at = buf.len();
    buf.put_u16(0); // placeholder
    if let Err(e) = f(buf) {
        buf.truncate(at);
        return Err(e);
    }
    let len = buf.len() - at - 2;
    let Ok(len) = u16::try_from(len) else {
        let actual = buf.len() - at - 2;
        buf.truncate(at);
        return Err(EncodingError::too_large(field, actual, u16::MAX as usize));
    };
    buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_with_u8_len_roundtrip() {
        let mut buf = BytesMut::new();
        with_u8_len(&mut buf, "test", |b| {
            b.extend_from_slice(&[1, 2, 3]);
            Ok(())
        })
        .unwrap();
        assert_eq!(buf.freeze(), Bytes::from_static(&[3, 1, 2, 3]));
    }

    #[test]
    fn test_with_u8_len_boundary() {
        let mut buf = BytesMut::new();
        // 255 bytes fits exactly
        with_u8_len(&mut buf, "test", |b| {
            b.extend_from_slice(&[0u8; 255]);
            Ok(())
        })
        .unwrap();
        assert_eq!(buf[0], 255);

        // 256 bytes overflows and rolls back
        let before = buf.len();
        let err = with_u8_len(&mut buf, "test", |b| {
            b.extend_from_slice(&[0u8; 256]);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, EncodingError::ValueTooLarge { .. }));
        assert_eq!(buf.len(), before, "buffer must roll back on overflow");
    }

    #[test]
    fn test_with_u16_len_boundary() {
        let mut buf = BytesMut::new();
        with_u16_len(&mut buf, "test", |b| {
            b.extend_from_slice(&[0u8; 65535]);
            Ok(())
        })
        .unwrap();
        assert_eq!(&buf[..2], &[0xFF, 0xFF]);

        let before = buf.len();
        let err = with_u16_len(&mut buf, "test", |b| {
            b.extend_from_slice(&[0u8; 65536]);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, EncodingError::ValueTooLarge { .. }));
        assert_eq!(buf.len(), before);
    }

    #[test]
    fn test_child_error_rolls_back() {
        let mut buf = BytesMut::from(&b"prefix"[..]);
        let err = with_u16_len(&mut buf, "test", |b| {
            b.extend_from_slice(&[1, 2, 3]);
            Err(EncodingError::unencodable("test", "boom"))
        })
        .unwrap_err();
        assert!(matches!(err, EncodingError::Unencodable { .. }));
        assert_eq!(&buf[..], b"prefix", "buffer must roll back on child error");
    }

    #[test]
    fn test_nested_prefixes() {
        let mut buf = BytesMut::new();
        with_u8_len(&mut buf, "outer", |b| {
            b.put_u8(0xAA);
            with_u8_len(b, "inner", |b2| {
                b2.extend_from_slice(&[1, 2]);
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(buf.freeze(), Bytes::from_static(&[4, 0xAA, 2, 1, 2]));
    }

    #[test]
    fn test_check_max() {
        assert_eq!(check_max("count", 10, 255).unwrap(), 10);
        assert_eq!(check_max("count", 255, 255).unwrap(), 255);
        assert!(check_max("count", 256, 255).is_err());
        assert!(check_max("FlowSpec length", 4096, 0x0FFF).is_err());
    }
}
