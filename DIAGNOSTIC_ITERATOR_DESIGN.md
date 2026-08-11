# Diagnostic Iterator Design

## 1. Overview

Issue [#303](https://github.com/bgpkit/bgpkit-parser/issues/303) needs an opt-in,
MRT-record-oriented iterator for applications that investigate malformed BGP data. The
iterator will classify every framed MRT record as a clean parsed record, a parsed record
with RFC 7606 validation findings, or a parse error, while retaining original wire data
where it is useful for export. It complements the existing fallible iterators; it does
not change their result types, filtering behavior, or default error-skipping behavior.

## 2. Motivation and Use Cases

- Monocle can display validation findings and fatal errors without parsing an input twice.
- A collector-quality job can count malformed UPDATEs and export their original MRT records.
- A bug report or regression test can retain the exact bytes that produced a finding.
- A normal parser pipeline can continue to use the smaller record, update, element, or route
  iterators without incurring raw-byte retention for successful records.

| Aspect | Existing fallible iterators | Diagnostic iterator |
| --- | --- | --- |
| Goal | Return a chosen parsed projection or an error | Classify each framed MRT record for investigation |
| Unit | Record, update, element, or route | Physical MRT record |
| Recoverable RFC 7606 warning | Nested inside `Attributes` on an `Ok` value | First-class `Validation` event |
| Raw bytes for a clean parsed record | Not retained | Not retained |
| Raw bytes for a validation finding | Not available from the iterator | Retained as `RawMrtRecord` |
| Fatal error context | `ParserErrorWithBytes` | Error, optional common header, and consumed bytes |

## 3. Design Decisions

**Add one diagnostic iterator, not diagnostic variants of every existing iterator.** The
feature is for record-level forensics. An element-level event would duplicate a record's
diagnostic once per prefix and would still not preserve a meaningful raw-record boundary.
`into_fallible_elem_iter`, `into_fallible_update_iter`, and `into_fallible_route_iter`
remain the appropriate APIs for typed processing pipelines.

**Use an enum of events rather than `Result<MrtRecord, _>`.** `Result` can represent a
fatal parse failure but cannot distinguish a clean record from a recoverably parsed record
with RFC 7606 findings. The enum makes the three states explicit without requiring each
consumer to know every location where an `Attributes` value can occur.

**Make `Validation` own a `RawMrtRecord`.** `RawMrtRecord` holds the original header and
body as `Bytes` and exposes `raw_bytes()` for export. Keeping that structure avoids
re-encoding the parsed model and avoids allocating a concatenated byte vector unless the
caller requests one. Clean `Record` events deliberately discard raw bytes after parsing.

**Expose copied warnings in deterministic record traversal order.** A warning is already
`Clone`; `Validation` returns `Vec<BgpValidationWarning>`. For BGP4MP and legacy BGP this
is the UPDATE's attribute order. For TABLE_DUMP batches and TABLE_DUMP_V2 RIBs it is entry
order followed by the order in each entry's `Attributes`. The record itself remains in the
event, so callers that need more context can inspect its message and entries.

**Keep diagnostics unfiltered.** `add_filter` and `with_filters` are element-oriented and
cannot reliably decide whether an unparseable record or a partially recovered UPDATE
matches. `into_diagnostic_iter()` therefore ignores configured parser filters and emits
every framed MRT record. Consumers can filter `DiagnosticEvent`s after classification.

**Support MRT only in the first release.** Text dumps have neither an MRT common header
nor original MRT bytes, and their current streaming parser returns `BgpElem` rather than
structured validation/error events. As with record-based iterators today, a text-dump
parser produces no diagnostic events.

**Continue only after body parse errors.** If the common header and declared body were fully
consumed, a body parse error is followed by the next MRT record. A malformed or truncated
header/body cannot always be resynchronized, so the iterator emits one `ParseError` and then
terminates. This prevents it from reinterpreting a partial record as a new MRT header or
looping on a persistent reader error.

**Do not change `ParserErrorWithBytes`.** Adding a field to its public struct would break
external struct literals. Instead, the raw-record reader gets an internal contextual error
type used only by the diagnostic iterator; existing parser and fallible APIs keep their
current signatures.

Alternatives rejected:

- Replacing fallible iterators: this would force record-oriented raw handling on normal
  pipelines and discard useful typed projections.
- Adding a `warnings()` method to `MrtRecord`: helpful in isolation, but it still does not
  join the warnings to original raw bytes or fatal parse errors.
- Returning `Vec<u8>` in every event: clean records would pay a copy/allocation cost for a
  debugging-only capability.

## 4. Data Structures

Add `src/parser/iters/diagnostic.rs` and re-export the following public types through the
existing `parser::iters` and `parser` re-export chain:

```rust
use crate::error::{BgpValidationWarning, ParserError};
use crate::models::{CommonHeader, MrtRecord};
use crate::parser::mrt::RawMrtRecord;

/// A record-level parsing outcome for malformed-data investigation.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiagnosticEvent {
    /// A fully parsed record with no RFC 7606 validation findings.
    Record(MrtRecord),
    /// A parsed record with one or more recoverable validation findings.
    Validation {
        record: MrtRecord,
        warnings: Vec<BgpValidationWarning>,
        raw_record: RawMrtRecord,
    },
    /// A record that could not be fully parsed.
    ParseError {
        error: ParserError,
        common_header: Option<CommonHeader>,
        raw_bytes: Option<Vec<u8>>,
    },
}

/// MRT-record diagnostic iterator created by `into_diagnostic_iter`.
pub struct DiagnosticIterator<R> {
    parser: BgpkitParser<R>,
}
```

`DiagnosticEvent` is `#[non_exhaustive]` because more record-level findings may be added
later. It intentionally does not derive `Clone` or `Eq`: `ParserError` has neither trait,
and duplicating captured raw data is not an expected event-stream operation.

Add an internal error used at the raw-framing boundary:

```rust
pub(crate) struct RawMrtRecordError {
    pub(crate) error: ParserError,
    pub(crate) common_header: Option<CommonHeader>,
    pub(crate) bytes: Option<Vec<u8>>,
}
```

`chunk_mrt_record_with_context` returns this error, while the existing
`chunk_mrt_record` maps it back to `ParserErrorWithBytes`. `common_header` is `Some` after
header parsing succeeded, including a partial-body read; it is `None` for an incomplete or
invalid header.

## 5. Algorithm

`DiagnosticIterator::next` has no pending element/update state; exactly one call attempts
to classify the next physical MRT record.

```text
fn next():
  1. If this is a text-dump parser, return None.
  2. Call chunk_mrt_record_with_context(reader).
  3. If the error is EofExpected, return None.
  4. If framing failed, mark the iterator terminated and return ParseError {
       error, common_header, raw_bytes: bytes,
     }.
  5. Retain the successful RawMrtRecord and call raw_record.clone().parse().
  6. If body parsing failed, return ParseError {
       error, common_header: Some(raw_record.common_header),
       raw_bytes: Some(raw_record.raw_bytes().to_vec()),
     }.
  7. Collect cloned warnings from every Attributes value in the MrtRecord.
  8. If no warnings exist, return Record(record); RawMrtRecord drops here.
  9. Otherwise return Validation { record, warnings, raw_record }.
```

The warning collector traverses only locations that own `Attributes`:

```rust
fn record_validation_warnings(record: &MrtRecord) -> Vec<BgpValidationWarning> {
    match &record.message {
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message)) => {
            update_warnings(&message.bgp_message)
        }
        MrtMessage::LegacyBgp(LegacyBgp::Message(message)) => {
            update_warnings(&message.bgp_message)
        }
        MrtMessage::TableDumpMessage(message) => {
            message.attributes.validation_warnings().to_vec()
        }
        MrtMessage::TableDumpMessageBatch(messages) => messages
            .iter()
            .flat_map(|message| message.attributes.validation_warnings().iter().cloned())
            .collect(),
        MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)) => rib
            .rib_entries
            .iter()
            .flat_map(|entry| entry.attributes.validation_warnings().iter().cloned())
            .collect(),
        _ => Vec::new(),
    }
}

fn update_warnings(message: &BgpMessage) -> Vec<BgpValidationWarning> {
    match message {
        BgpMessage::Update(update) => update.attributes.validation_warnings().to_vec(),
        _ => Vec::new(),
    }
}
```

Unlike `FallibleRecordIterator`, this algorithm intentionally does not apply
`parser.filters`. Unlike `RawRecordIterator`, it does not log, write a core dump, skip an
error, or use the `enable_core_dump` flag to stop iteration; the event is the diagnostic
output.

Worked sequence:

```text
[clean BGP4MP UPDATE][malformed NLRI UPDATE][invalid TABLE_DUMP body][clean UPDATE]
      -> Record
      -> Validation { warnings: [MalformedNlri { .. }], raw_record }
      -> ParseError { common_header: Some(..), raw_bytes: Some(..) }
      -> Record
```

## 6. Output Format

This is a Rust API, not a persisted output format. Applications decide whether and how to
serialize events. A consumer can emit a concise JSONL representation without re-parsing or
re-encoding the source:

```json
{"kind":"validation","timestamp":1710000000,"warnings":["MalformedNlri"],"raw_record_len":91}
{"kind":"parse_error","error":"truncated MRT body: expected 64 bytes, read 12","mrt_type":12,"raw_bytes_len":24}
```

Exporting an original validation record is direct:

```rust
if let DiagnosticEvent::Validation { raw_record, .. } = event {
    raw_record.write_raw_bytes("malformed-record.mrt")?;
}
```

The library does not add a CLI report mode or a serde representation in this change.

## 7. Changes to Existing Files

**`src/parser/iters/mod.rs`**

```rust
mod diagnostic;

pub use diagnostic::{DiagnosticEvent, DiagnosticIterator};

impl<R> BgpkitParser<R> {
    /// Creates an MRT-record diagnostic iterator for malformed-data investigation.
    ///
    /// This iterator ignores parser filters and emits no events for text dumps.
    pub fn into_diagnostic_iter(self) -> DiagnosticIterator<R> {
        DiagnosticIterator::new(self)
    }
}
```

Place the method beside the fallible iterator constructors. The docs must state that it is
MRT-only, unfiltered, event-oriented, and intended for diagnostics rather than the normal
per-element data path.

**`src/parser/mrt/mrt_record.rs`**

Factor the current body of `chunk_mrt_record` into an internal contextual variant. The
public function remains source-compatible:

```rust
pub fn chunk_mrt_record(input: &mut impl Read) -> Result<RawMrtRecord, ParserErrorWithBytes> {
    chunk_mrt_record_with_context(input).map_err(|error| ParserErrorWithBytes {
        error: error.error,
        bytes: error.bytes,
    })
}

pub(crate) fn chunk_mrt_record_with_context(
    input: &mut impl Read,
) -> Result<RawMrtRecord, RawMrtRecordError> {
    // Existing header/body reading logic, retaining `Some(common_header)` once parsed.
}
```

The refactor must preserve existing error strings and bytes exactly. In particular, the
existing oversized-record behavior continues to retain only the header bytes, and a
partial body continues to retain the header plus body bytes read so far.

**`src/parser/mrt/mod.rs`**

Keep the public re-export unchanged. If `diagnostic.rs` imports the contextual function
through `mrt_record`, do not make it public:

```rust
pub use mrt_record::{chunk_mrt_record, parse_mrt_record, RawMrtRecord};
```

**`CHANGELOG.md`**

Add under `## Unreleased` / `### Added`:

```markdown
* **Diagnostic MRT iterator** ([#303](https://github.com/bgpkit/bgpkit-parser/issues/303)): added `into_diagnostic_iter()` for record-level malformed-data investigation. It emits clean records, recoverable RFC 7606 validation findings with original MRT bytes, and fatal parse errors with available header and byte context.
```

No `src/lib.rs` change is needed: `pub use parser::*` already exposes public iterator
re-exports when the `parser` feature is enabled.

## 8. New Files

**`src/parser/iters/diagnostic.rs`** — mirrors the ownership and `Iterator` style of
`src/parser/iters/fallible.rs`, but reads framed records directly like the fallible route
iterator. It contains:

- `DiagnosticEvent` and `DiagnosticIterator` public definitions.
- `DiagnosticIterator::new` as `pub(crate)`.
- The `Iterator for DiagnosticIterator<R>` implementation described above.
- `record_validation_warnings` and `update_warnings` private helpers.
- Unit tests built from encoded `MrtRecord`s and small manually framed invalid records.

The module imports `chunk_mrt_record_with_context` and `RawMrtRecordError` from
`mrt_record`; it must not call `BgpkitParser::next_record`, because that API discards a
successfully framed `RawMrtRecord` after parsing.

## 9. Unit Tests

Add focused tests in `src/parser/iters/diagnostic.rs`; reuse the small builders already
used by iterator and RFC 7606 tests rather than adding binary fixtures.

- Clean BGP4MP UPDATE with valid attributes -> one `Record`, no retained raw record.
- UPDATE with invalid flags -> one `Validation` containing `AttributeFlagsError`; its
  `raw_record.raw_bytes()` equals the original encoded MRT bytes.
- UPDATE with missing ORIGIN/AS_PATH/NEXT_HOP -> one `Validation` containing the three
  mandatory-attribute warnings.
- UPDATE with malformed AS_PATH or typed-attribute length -> one `Validation` whose
  warning and raw bytes are preserved.
- UPDATE with malformed announced and withdrawn NLRI -> one `Validation` containing
  `MalformedNlri` warnings and their existing embedded NLRI raw bytes.
- A fully framed MRT record whose body cannot parse -> `ParseError` with `Some` common
  header and full original MRT bytes.
- An invalid or incomplete MRT header -> `ParseError` with `None` common header and all
  consumed bytes.
- A declared body that ends early -> `ParseError` with `Some` common header and the header
  plus partial body bytes.
- `[bad fully framed body][clean record]` -> `ParseError` followed by `Record`.
- A framing error (for example, an oversized declared body) -> one `ParseError`, then end of
  iteration even if bytes follow it.
- TABLE_DUMP batch and TABLE_DUMP_V2 RIB entries with warnings -> a single `Validation`
  event per physical MRT record; warnings are collected in entry order.
- Parser with a filter configured -> the same diagnostic event sequence as an unfiltered
  parser.
- Text-dump parser -> no events, matching record/fallible-record behavior.

Keep existing tests in `tests/test_rfc7606_error_handling.rs`, `tests/raw_iter.rs`, and
`src/parser/mrt/mrt_record.rs`; extend the raw-record tests only if the contextual
refactor risks their byte-preservation assertions.

## 10. Open Questions

**Question**: Should a validation finding identify its exact nested location, such as RIB
entry index or BGP4MP UPDATE?
**Default**: No. Version one returns the parsed record and warnings in documented traversal
order. Add a `DiagnosticFinding { location, warning }` wrapper only when a consumer needs
machine-readable nested location; changing `warnings` now would make a simple API heavier.

**Question**: Should the diagnostic iterator expose non-UPDATE records?
**Default**: Yes, as `Record`. A physical-record stream must preserve sequence and allow
callers to relate a later parse failure to surrounding state records or peer tables.

**Question**: Should text dumps gain diagnostics later?
**Default**: Not in this issue. That requires a separate text parser event/error contract
and has no raw MRT record to export.

## 11. Implementation Sequence

1. Add `RawMrtRecordError` and `chunk_mrt_record_with_context` in
   `src/parser/mrt/mrt_record.rs`; run its existing raw-byte tests.
2. Add `src/parser/iters/diagnostic.rs` with public event types, framing/body classification,
   and the private validation-warning collector.
3. Re-export the new iterator and add `BgpkitParser::into_diagnostic_iter` in
   `src/parser/iters/mod.rs`.
4. Add unit tests for clean, validation, error, raw-byte, continuation, filter, and text-dump
   behavior.
5. Add the `CHANGELOG.md` entry and API docs/doctest.
6. Run `cargo fmt`, `cargo build --all-features --examples`, `cargo test --all-features`, and
   `cargo clippy --all-targets --all-features -- -D warnings`.

## 12. Notes and Caveats

- This API retains a `RawMrtRecord` only for `Validation`; raw bytes remain unavailable for
  clean records by design.
- A `ParseError` from a malformed header cannot reliably name a `CommonHeader`; that field
  is intentionally optional.
- Event continuation applies only to a body parse error after the reader consumed a known
  record boundary. Framing errors terminate the iterator rather than attempting to
  resynchronize arbitrary corrupted byte streams.
- The existing `enable_core_dump()` option is intentionally irrelevant to this iterator:
  writing files as a side effect would make an application-level event API surprising.
- The iterator should be documented as a debugging and data-quality API. It is not expected
  to replace the parser's normal high-throughput element/update paths.
