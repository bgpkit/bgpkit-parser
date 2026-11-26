//! One framing path for every MRT consumer.
//!
//! Every reader of an MRT stream needs the same three steps: read the common header, read the
//! declared body, and decide what the record is. This module owns those steps and hands out a
//! [`Frame`] whose body is borrowed from a caller-owned buffer, so no path allocates per record.
//!
//! The body buffer is lent by the consumer rather than owned here: it lets the consumer keep its
//! own buffer alive across records (the high-water trick) and keeps the returned frame borrowing
//! only that buffer, so the consumer can still mutate other state while the frame is live.
//!
//! The peer index table is deliberately *not* part of a [`Frame`]: `PEER_INDEX_TABLE` records
//! replace it mid-stream, so binding it into a frame would either alias that mutation or force a
//! per-record snapshot. Consumers that resolve `peer_index` values take `&[Peer]` explicitly.

use crate::error::ParserError;
use crate::models::{CommonHeader, EntryType};
use crate::parser::mrt::mrt_header::{frame_common_header_captured, HeaderBuf};
use std::io::Read;

/// Upper bound on the MRT body length the parser will read into memory.
pub(crate) const MAX_MRT_MESSAGE_LEN: u32 = 16 * 1024 * 1024; // 16 MiB

/// Buffer growth allowed before switching to `read_to_end`, which keeps a single outlier record
/// from pinning the reusable buffer at its size for the rest of the stream.
const MAX_EAGER_GROWTH: usize = 64 * 1024;

/// A framing failure with the bytes needed to report it.
pub(crate) struct FrameError {
    pub(crate) error: ParserError,
    pub(crate) bytes: Option<Vec<u8>>,
}

/// A framed record whose body borrows the consumer's buffer.
pub(crate) struct Frame<'a> {
    pub(crate) header: CommonHeader,
    /// The raw common-header bytes, for error and core-dump reporting.
    pub(crate) raw_header: HeaderBuf,
    pub(crate) body: &'a [u8],
}

/// Reads consecutive MRT common headers, and the body into the consumer's buffer.
#[derive(Default)]
pub(crate) struct Framer {
    header: HeaderBuf,
    parsed_header: Option<Result<CommonHeader, ParserError>>,
}

impl Framer {
    /// Frame the next record into `body`, borrowing it for the frame's lifetime.
    ///
    /// `body.len()` is treated as the high-water mark across records: a shorter record reuses the
    /// already-initialised prefix and never zeroes the tail.
    pub(crate) fn next<'a>(
        &mut self,
        input: &mut impl Read,
        body: &'a mut Vec<u8>,
    ) -> Result<Frame<'a>, FrameError> {
        let body_len = self.read_body(input, body)?;
        let header = self.take_header(body)?;
        Ok(Frame {
            header,
            raw_header: self.header,
            body: &body[..body_len],
        })
    }

    /// Read the declared body into `body` and return its length.
    fn read_body(
        &mut self,
        input: &mut impl Read,
        body: &mut Vec<u8>,
    ) -> Result<usize, FrameError> {
        let framed = match frame_common_header_captured(input, &mut self.header) {
            Ok(framed) => framed,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::UnexpectedEof
                    && self.header.as_slice().is_empty()
                {
                    return Err(FrameError {
                        error: ParserError::EofExpected,
                        bytes: None,
                    });
                }
                return Err(FrameError {
                    error: error.into(),
                    bytes: Some(self.header.as_slice().to_vec()),
                });
            }
        };

        self.parsed_header = Some(framed.header);

        if framed.body_length > MAX_MRT_MESSAGE_LEN {
            return Err(FrameError {
                error: ParserError::OversizedRecord {
                    length: framed.body_length,
                },
                bytes: Some(framed.raw_bytes.to_vec()),
            });
        }

        let body_len = framed.body_length as usize;
        if body_len <= body.len() {
            let filled = fill(input, body, body_len, self.header)?;
            if filled != body_len {
                return Err(truncated_body(self.header, body, body_len, filled));
            }
        } else if body_len - body.len() <= MAX_EAGER_GROWTH {
            body.resize(body_len, 0);
            let filled = fill(input, body, body_len, self.header)?;
            if filled != body_len {
                return Err(truncated_body(self.header, body, body_len, filled));
            }
        } else {
            body.clear();
            if let Err(err) = input.take(body_len as u64).read_to_end(body) {
                return Err(FrameError {
                    error: ParserError::IoError(err),
                    bytes: Some(assemble_error_bytes(self.header.as_slice(), body)),
                });
            }
            if body.len() != body_len {
                let filled = body.len();
                return Err(truncated_body(self.header, body, body_len, filled));
            }
        }

        self.apply_legacy_length_correction(input, body, body_len)
    }

    /// Preserve stream alignment across historical TABLE_DUMP v1 records that under-declared their
    /// body length by 4 bytes.
    fn apply_legacy_length_correction(
        &mut self,
        input: &mut impl Read,
        body: &mut Vec<u8>,
        body_len: usize,
    ) -> Result<usize, FrameError> {
        let Some(Ok(common_header)) = self.parsed_header.as_ref() else {
            return Ok(body_len);
        };
        let common_header = *common_header;
        if common_header.entry_type != EntryType::TABLE_DUMP
            || !crate::parser::mrt::messages::table_dump::needs_legacy_length_correction(
                common_header.entry_subtype,
                &body[..body_len],
            )
        {
            return Ok(body_len);
        }

        let needed = body_len + 4;
        if body.len() < needed {
            body.resize(needed, 0);
        }
        match read_slice_full(input, &mut body[body_len..needed]) {
            Ok(4) => {
                log::debug!(
                    "recovered historical TABLE_DUMP record whose declared length was four bytes short (timestamp={}, subtype={}, declared_length={})",
                    common_header.timestamp,
                    common_header.entry_subtype,
                    common_header.length
                );
                Ok(needed)
            }
            Ok(read) => Err(FrameError {
                error: ParserError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated historical TABLE_DUMP length correction",
                )),
                bytes: Some(assemble_error_bytes(
                    self.header.as_slice(),
                    &body[..body_len + read],
                )),
            }),
            Err((err, read)) => Err(FrameError {
                error: ParserError::IoError(err),
                bytes: Some(assemble_error_bytes(
                    self.header.as_slice(),
                    &body[..body_len + read],
                )),
            }),
        }
    }

    fn take_header(&mut self, body: &[u8]) -> Result<CommonHeader, FrameError> {
        match self.parsed_header.take() {
            Some(Ok(header)) => Ok(header),
            Some(Err(error)) => Err(FrameError {
                error,
                bytes: Some(assemble_error_bytes(self.header.as_slice(), body)),
            }),
            None => Err(FrameError {
                error: ParserError::EofExpected,
                bytes: None,
            }),
        }
    }
}

fn fill(
    input: &mut impl Read,
    body: &mut [u8],
    body_len: usize,
    header: HeaderBuf,
) -> Result<usize, FrameError> {
    match read_slice_full(input, &mut body[..body_len]) {
        Ok(filled) => Ok(filled),
        Err((err, filled)) => Err(FrameError {
            error: ParserError::IoError(err),
            bytes: Some(assemble_error_bytes(header.as_slice(), &body[..filled])),
        }),
    }
}

fn truncated_body(header: HeaderBuf, body: &[u8], expected: usize, read: usize) -> FrameError {
    FrameError {
        error: ParserError::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("truncated MRT body: expected {expected} bytes, read {read}"),
        )),
        bytes: Some(assemble_error_bytes(
            header.as_slice(),
            &body[..read.min(body.len())],
        )),
    }
}

/// Read up to `buf.len()` bytes, retrying `Interrupted` and preserving the count read on error.
fn read_slice_full(
    input: &mut impl Read,
    buf: &mut [u8],
) -> Result<usize, (std::io::Error, usize)> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err((e, filled)),
        }
    }
    Ok(filled)
}

pub(crate) fn assemble_error_bytes(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    out
}
