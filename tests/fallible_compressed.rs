//! Regression tests for issue #349: fallible iterators must terminate after a
//! fatal reader error instead of re-yielding the same error forever.
//!
//! Each fixture is an in-memory compressed MRT stream (32 identical TABLE_DUMP
//! v1 records, 52 bytes each) whose codec state is damaged mid-stream, then fed
//! through the real `BgpkitParser::new` path so oneio's suffix-based bz2/gz
//! decompression is exercised end to end. The damaged stream must yield the
//! intact records that precede the damage, then one error, then end.
#![cfg(all(feature = "parser", feature = "oneio"))]

use bgpkit_parser::{BgpkitParser, ParserError, ParserErrorWithBytes};
use bzip2::write::BzEncoder;
use flate2::write::GzEncoder;
use std::cell::Cell;
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::rc::Rc;
use tempfile::NamedTempFile;

const RECORDS: usize = 32;

/// `Codec::compress` splits the stream at `input.len() / 2 + 5`, i.e. inside
/// record 17 (byte 837 = 16 whole 52-byte records plus 5 bytes), so a stream
/// damaged at the split boundary only after the first block must produce this
/// many intact items before the decompression error surfaces.
const RECORDS_BEFORE_FAILURE: usize = 16;

type Parser = BgpkitParser<Box<dyn Read + Send>>;
type FallibleItems = Box<dyn Iterator<Item = Result<(), ParserErrorWithBytes>>>;

#[derive(Clone, Copy, Debug)]
enum Codec {
    Bzip2,
    Gzip,
}

impl Codec {
    fn suffix(self) -> &'static str {
        match self {
            Self::Bzip2 => ".bz2",
            Self::Gzip => ".gz",
        }
    }

    /// Compress `input` with a flush inside a record, and return
    /// `(compressed, corrupt_offset, truncate_at)` where:
    /// - `corrupt_offset` is a byte whose flip corrupts the stream mid-way
    ///   (the first block CRC for bzip2, the second stored-block header for
    ///   gzip),
    /// - `truncate_at` is a length that cuts the second compressed block in
    ///   half, so truncation ends inside decompressed data rather than at a
    ///   block boundary.
    fn compress(self, input: &[u8]) -> (Vec<u8>, usize, usize) {
        // Split inside a record so truncation exercises a partial MRT header/body, not clean EOF.
        let split = input.len() / 2 + 5;
        match self {
            Self::Bzip2 => {
                let mut encoder = BzEncoder::new(Vec::new(), bzip2::Compression::best());
                encoder.write_all(&input[..split]).unwrap();
                encoder.flush().unwrap();
                let flushed = encoder.get_ref().len();
                encoder.write_all(&input[split..]).unwrap();
                let bytes = encoder.finish().unwrap();
                assert_eq!(&bytes[4..10], b"1AY&SY");
                let truncate_at = flushed + (bytes.len() - flushed) / 2;
                // The first block CRC is in the compressed payload, not the file header.
                (bytes, 10, truncate_at)
            }
            Self::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::none());
                encoder.write_all(&input[..split]).unwrap();
                encoder.flush().unwrap();
                // A sync flush leaves a byte-aligned boundary for the next stored block.
                let block_start = encoder.get_ref().len();
                encoder.write_all(&input[split..]).unwrap();
                let bytes = encoder.finish().unwrap();
                assert_eq!(bytes[block_start] & 0x06, 0);
                let truncate_at = block_start + (bytes.len() - block_start) / 2;
                (bytes, block_start, truncate_at)
            }
        }
    }

    fn parser(self, bytes: &[u8]) -> (NamedTempFile, Parser) {
        let mut file = tempfile::Builder::new()
            .suffix(self.suffix())
            .tempfile()
            .unwrap();
        file.write_all(bytes).unwrap();
        let parser = BgpkitParser::new(file.path().to_str().unwrap()).unwrap();
        (file, parser)
    }
}

#[derive(Clone, Copy, Debug)]
enum IterKind {
    Elem,
    Record,
    Update,
    Route,
}

const ITER_KINDS: [IterKind; 4] = [
    IterKind::Elem,
    IterKind::Record,
    IterKind::Update,
    IterKind::Route,
];

fn items<R: Read + 'static>(parser: BgpkitParser<R>, kind: IterKind) -> FallibleItems {
    match kind {
        IterKind::Elem => Box::new(parser.into_fallible_elem_iter().map(|r| r.map(|_| ()))),
        IterKind::Record => Box::new(parser.into_fallible_record_iter().map(|r| r.map(|_| ()))),
        IterKind::Update => Box::new(parser.into_fallible_update_iter().map(|r| r.map(|_| ()))),
        IterKind::Route => Box::new(parser.into_fallible_route_iter().map(|r| r.map(|_| ()))),
    }
}

fn valid_record() -> Vec<u8> {
    // TABLE_DUMP v1, IPv4 192.0.2.0/24, peer AS64512, with all mandatory attributes.
    let body = [
        0, 0, 0, 1, // view and sequence
        192, 0, 2, 0, 24, 1, // network and status
        0, 0, 0, 1, // originated time
        198, 51, 100, 1, 0xfc, 0, // peer IP and ASN
        0, 18, // attribute length
        0x40, 1, 1, 0, // ORIGIN: IGP
        0x40, 2, 4, 2, 1, 0xfc, 0, // AS_PATH: AS64512
        0x40, 3, 4, 198, 51, 100, 1, // NEXT_HOP
    ];
    let mut record = vec![0, 0, 0, 1, 0, 12, 0, 1];
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

/// Pull items until the first fatal stream error, then require EOF.
///
/// `expected_ok` pins the number of intact items that must precede the error
/// (`None` when the fixture does not promise an exact count). The loop is
/// bounded by `RECORDS + 1` pulls, so a stream that keeps re-yielding the same
/// error fails the test instead of hanging it — on a correct iterator the
/// error appears well before the bound and is followed by `None`.
fn assert_error_then_end(mut iter: FallibleItems, context: &str, expected_ok: Option<usize>) {
    let mut successes = 0;
    for _ in 0..=RECORDS {
        match iter.next() {
            Some(Ok(())) => successes += 1,
            Some(Err(error)) => {
                assert!(
                    matches!(
                        error.error,
                        ParserError::IoError(_) | ParserError::EofError(_)
                    ),
                    "{context}: expected an IoError or EofError, got {:?}",
                    error.error
                );
                if let Some(expected) = expected_ok {
                    assert_eq!(
                        successes, expected,
                        "{context}: intact items must parse before the fatal error"
                    );
                }
                assert!(
                    iter.next().is_none(),
                    "{context}: a fatal stream error must be followed by EOF, not another item"
                );
                assert!(
                    iter.next().is_none(),
                    "{context}: the failed stream must stay stopped"
                );
                return;
            }
            None => panic!("{context}: expected a decompression error, not clean EOF"),
        }
    }
    panic!("{context}: no terminal error within {} pulls", RECORDS + 1);
}

fn check_corruption(codec: Codec) {
    let (mut compressed, corrupt_offset, _) = codec.compress(&valid_record().repeat(RECORDS));
    match codec {
        Codec::Bzip2 => compressed[corrupt_offset] ^= 1,
        // Flip BTYPE from stored (00) to reserved (11), leaving the stream untruncated.
        Codec::Gzip => compressed[corrupt_offset] ^= 0x06,
    }
    for kind in ITER_KINDS {
        let (_file, parser) = codec.parser(&compressed);
        assert_error_then_end(
            items(parser, kind),
            &format!("{codec:?}/{kind:?} corruption"),
            Some(RECORDS_BEFORE_FAILURE),
        );
    }
}

#[test]
fn corrupt_bzip2_terminates() {
    check_corruption(Codec::Bzip2);
}

#[test]
fn corrupt_gzip_terminates() {
    check_corruption(Codec::Gzip);
}

#[test]
fn clean_compressed_streams_reach_eof() {
    for codec in [Codec::Bzip2, Codec::Gzip] {
        let (compressed, _, _) = codec.compress(&valid_record().repeat(RECORDS));
        for kind in ITER_KINDS {
            let (_file, parser) = codec.parser(&compressed);
            let mut iter = items(parser, kind);
            for _ in 0..RECORDS {
                assert!(matches!(iter.next(), Some(Ok(()))), "{codec:?} {kind:?}");
            }
            assert!(iter.next().is_none());
            assert!(iter.next().is_none());
        }
    }
}

#[test]
fn truncated_compressed_streams_error_once() {
    for codec in [Codec::Bzip2, Codec::Gzip] {
        let (mut compressed, _, truncate_at) = codec.compress(&valid_record().repeat(RECORDS));
        // Cut inside the second compressed block, not at the whole-file midpoint.
        compressed.truncate(truncate_at);
        for kind in ITER_KINDS {
            let (_file, parser) = codec.parser(&compressed);
            assert_error_then_end(
                items(parser, kind),
                &format!("{codec:?}/{kind:?} truncation"),
                None,
            );
        }
    }
}

#[test]
fn malformed_record_io_error_is_skippable() {
    let valid = valid_record();
    let mut bad = valid.clone();
    bad[20] = 33; // Invalid IPv4 mask: body parsing returns IoError, not a reader failure.
    let stream = [valid.as_slice(), bad.as_slice(), valid.as_slice()].concat();
    for codec in [Codec::Bzip2, Codec::Gzip] {
        let (compressed, _, _) = codec.compress(&stream);
        for kind in ITER_KINDS {
            let (_file, parser) = codec.parser(&compressed);
            let mut iter = items(parser, kind);
            assert!(matches!(iter.next(), Some(Ok(()))));
            assert!(matches!(
                iter.next(),
                Some(Err(ParserErrorWithBytes {
                    error: ParserError::IoError(_),
                    ..
                }))
            ));
            assert!(matches!(iter.next(), Some(Ok(()))));
            assert!(iter.next().is_none());
        }
    }
}

#[test]
fn malformed_header_is_skippable() {
    let mut stream = vec![0, 0, 0, 1, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
    stream.extend_from_slice(&valid_record());
    for kind in ITER_KINDS {
        let mut iter = items(BgpkitParser::from_reader(Cursor::new(stream.clone())), kind);
        assert!(matches!(
            iter.next(),
            Some(Err(ParserErrorWithBytes {
                error: ParserError::ParseError(_),
                ..
            }))
        ));
        assert!(matches!(iter.next(), Some(Ok(()))));
        assert!(iter.next().is_none());
    }
}

struct FailedReader {
    kind: ErrorKind,
    reads: Rc<Cell<usize>>,
}

impl Read for FailedReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        Err(io::Error::new(self.kind, "stream failure"))
    }
}

#[test]
fn stream_errors_stop_without_reading_again() {
    let valid = valid_record();
    for error_kind in [
        ErrorKind::InvalidInput,
        ErrorKind::InvalidData,
        ErrorKind::Other,
    ] {
        // Exercise failure before a header, midway through a header, and midway through a body.
        for partial_len in [0, 5, 17] {
            let prefix = [valid.as_slice(), &valid[..partial_len]].concat();
            for kind in ITER_KINDS {
                let reads = Rc::new(Cell::new(0));
                let reader = Cursor::new(prefix.clone()).chain(FailedReader {
                    kind: error_kind,
                    reads: reads.clone(),
                });
                let mut iter = items(BgpkitParser::from_reader(reader), kind);
                assert!(matches!(iter.next(), Some(Ok(()))));
                let Some(Err(error)) = iter.next() else {
                    panic!("expected a stream failure");
                };
                assert_eq!(error.bytes.as_deref(), Some(&valid[..partial_len]));
                let reads_at_error = reads.get();
                assert!(
                    iter.next().is_none(),
                    "fatal {error_kind:?} error must be followed by EOF: partial_len={partial_len} {kind:?}"
                );
                assert!(iter.next().is_none());
                assert_eq!(reads.get(), reads_at_error, "must not poll a dead reader");
            }
        }
    }
}

struct TransientReader {
    kind: Option<ErrorKind>,
    inner: Cursor<Vec<u8>>,
}

impl Read for TransientReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(kind) = self.kind.take() {
            return Err(io::Error::new(kind, "retryable read failure"));
        }
        self.inner.read(buffer)
    }
}

#[test]
fn retryable_reader_errors_do_not_end_iteration() {
    for error_kind in [ErrorKind::Interrupted, ErrorKind::WouldBlock] {
        for kind in ITER_KINDS {
            let reader = TransientReader {
                kind: Some(error_kind),
                inner: Cursor::new(valid_record()),
            };
            let mut iter = items(BgpkitParser::from_reader(reader), kind);
            if error_kind == ErrorKind::WouldBlock {
                assert!(matches!(iter.next(), Some(Err(_))));
            }
            assert!(matches!(iter.next(), Some(Ok(()))));
            assert!(iter.next().is_none());
        }
    }
}

#[test]
fn uncompressed_truncation_and_empty_eof_are_unchanged() {
    let valid = valid_record();
    for partial_len in [5, 17] {
        let stream = [valid.as_slice(), &valid[..partial_len]].concat();
        for kind in ITER_KINDS {
            let iter = items(BgpkitParser::from_reader(Cursor::new(stream.clone())), kind);
            assert_error_then_end(iter, &format!("uncompressed/{kind:?} truncation"), Some(1));
        }
    }
    for kind in ITER_KINDS {
        let mut iter = items(BgpkitParser::from_reader(io::empty()), kind);
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }
}
