/*!
Back-patching helpers for length-prefixed wire fields.

All "write a length, then the payload" encoding in this crate goes through
these helpers: a placeholder length is written, the payload is encoded
directly into the shared buffer, and the length is patched in afterwards with
a checked conversion. This centralizes every wire-capacity check and avoids
per-node intermediate buffers.
*/
use crate::error::{check_max, EncodingError};
use bytes::{BufMut, BytesMut};

/// Encode a payload with a 1-byte length prefix.
///
/// Runs `f` to append the payload to `buf`, then back-patches the length.
/// Returns `EncodingError::ValueTooLarge` (naming `field`) if the payload
/// exceeds 255 bytes.
pub(crate) fn with_u8_len(
    buf: &mut BytesMut,
    field: &'static str,
    f: impl FnOnce(&mut BytesMut) -> Result<(), EncodingError>,
) -> Result<(), EncodingError> {
    let at = buf.len();
    buf.put_u8(0);
    f(buf)?;
    let len = buf.len() - at - 1;
    check_max(field, len, u8::MAX as usize)?;
    buf[at] = len as u8;
    Ok(())
}

/// Encode a payload with a 2-byte big-endian length prefix.
///
/// Runs `f` to append the payload to `buf`, then back-patches the length.
/// Returns `EncodingError::ValueTooLarge` (naming `field`) if the payload
/// exceeds 65535 bytes.
pub(crate) fn with_u16_len(
    buf: &mut BytesMut,
    field: &'static str,
    f: impl FnOnce(&mut BytesMut) -> Result<(), EncodingError>,
) -> Result<(), EncodingError> {
    let at = buf.len();
    buf.put_u16(0);
    f(buf)?;
    let len = buf.len() - at - 2;
    check_max(field, len, u16::MAX as usize)?;
    buf[at..at + 2].copy_from_slice(&(len as u16).to_be_bytes());
    Ok(())
}

/// Write `slice` preceded by its length as 1 byte.
///
/// Returns `EncodingError::ValueTooLarge` (naming `field`) if the slice
/// exceeds 255 bytes; `buf` is not modified in that case.
pub(crate) fn put_u8_len_slice(
    buf: &mut BytesMut,
    field: &'static str,
    slice: &[u8],
) -> Result<(), EncodingError> {
    check_max(field, slice.len(), u8::MAX as usize)?;
    buf.put_u8(slice.len() as u8);
    buf.put_slice(slice);
    Ok(())
}

/// Write `slice` preceded by its length as 2 big-endian bytes.
///
/// Returns `EncodingError::ValueTooLarge` (naming `field`) if the slice
/// exceeds 65535 bytes; `buf` is not modified in that case.
pub(crate) fn put_u16_len_slice(
    buf: &mut BytesMut,
    field: &'static str,
    slice: &[u8],
) -> Result<(), EncodingError> {
    check_max(field, slice.len(), u16::MAX as usize)?;
    buf.put_u16(slice.len() as u16);
    buf.put_slice(slice);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::check_max;

    #[test]
    fn test_with_u8_len_basic() {
        let mut buf = BytesMut::new();
        with_u8_len(&mut buf, "test", |b| {
            b.put_slice(&[1, 2, 3]);
            Ok(())
        })
        .unwrap();
        assert_eq!(&buf[..], &[3, 1, 2, 3]);
    }

    #[test]
    fn test_with_u8_len_empty() {
        let mut buf = BytesMut::new();
        with_u8_len(&mut buf, "test", |_| Ok(())).unwrap();
        assert_eq!(&buf[..], &[0]);
    }

    #[test]
    fn test_with_u8_len_at_max() {
        let mut buf = BytesMut::new();
        with_u8_len(&mut buf, "test", |b| {
            b.put_slice(&[0xAA; 255]);
            Ok(())
        })
        .unwrap();
        assert_eq!(buf[0], 255);
        assert_eq!(buf.len(), 256);
    }

    #[test]
    fn test_with_u8_len_overflow() {
        let mut buf = BytesMut::new();
        let err = with_u8_len(&mut buf, "test field", |b| {
            b.put_slice(&[0xAA; 256]);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(
            err,
            EncodingError::ValueTooLarge {
                field: "test field",
                actual: 256,
                max: 255
            }
        );
    }

    #[test]
    fn test_with_u16_len_basic() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xFF); // pre-existing content must be preserved
        with_u16_len(&mut buf, "test", |b| {
            b.put_slice(&[1, 2, 3]);
            Ok(())
        })
        .unwrap();
        assert_eq!(&buf[..], &[0xFF, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_with_u16_len_overflow() {
        let mut buf = BytesMut::new();
        let err = with_u16_len(&mut buf, "test field", |b| {
            b.put_slice(&vec![0xAA; 65536]);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(
            err,
            EncodingError::ValueTooLarge {
                field: "test field",
                actual: 65536,
                max: 65535
            }
        );
    }

    #[test]
    fn test_nested_prefixes() {
        let mut buf = BytesMut::new();
        with_u16_len(&mut buf, "outer", |b| {
            with_u8_len(b, "inner", |b| {
                b.put_slice(&[7, 8]);
                Ok(())
            })
        })
        .unwrap();
        // outer len = 3 (inner prefix byte + 2 payload bytes)
        assert_eq!(&buf[..], &[0, 3, 2, 7, 8]);
    }

    #[test]
    fn test_inner_error_propagates() {
        let mut buf = BytesMut::new();
        let err = with_u16_len(&mut buf, "outer", |_| {
            Err(EncodingError::too_large("inner", 1, 0))
        })
        .unwrap_err();
        assert_eq!(
            err,
            EncodingError::ValueTooLarge {
                field: "inner",
                actual: 1,
                max: 0
            }
        );
    }

    #[test]
    fn test_check_max_custom_bound() {
        assert_eq!(check_max("f", 4095, 0x0FFF), Ok(4095));
        assert!(check_max("f", 4096, 0x0FFF).is_err());
    }
}
