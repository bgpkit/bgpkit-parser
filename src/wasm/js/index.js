'use strict';

const wasm = require('./nodejs/bgpkit_parser.js');

/**
 * Parse an OpenBMP-wrapped BMP message (e.g. from the RouteViews Kafka stream).
 *
 * Returns null for non-router OpenBMP frames (collector heartbeats).
 *
 * @param {Uint8Array} data - Raw OpenBMP message bytes
 * @returns {object|null} Parsed BMP message with discriminated `type` field
 */
function parseOpenBmpMessage(data) {
  const json = wasm.parseOpenBmpMessage(data);
  return json ? JSON.parse(json) : null;
}

/**
 * Parse a raw BMP message (no OpenBMP wrapper).
 *
 * @param {Uint8Array} data - Raw BMP message bytes
 * @param {number} timestamp - Collection time in seconds since Unix epoch
 * @returns {object} Parsed BMP message with discriminated `type` field
 */
function parseBmpMessage(data, timestamp) {
  return JSON.parse(wasm.parseBmpMessage(data, timestamp));
}

/**
 * Parse a decompressed MRT file into BGP elements.
 *
 * Handles TABLE_DUMP, TABLE_DUMP_V2, and BGP4MP record types.
 * The caller is responsible for decompressing the file (bzip2/gzip) before
 * passing the raw bytes.
 *
 * @param {Uint8Array} data - Decompressed MRT file bytes
 * @returns {object[]} Array of BgpElem objects
 */
function parseMrtFile(data) {
  return JSON.parse(wasm.parseMrtFile(data));
}

/**
 * Parse a single BGP UPDATE message into BGP elements.
 *
 * Expects a full BGP message including the 16-byte marker, 2-byte length,
 * and 1-byte type header. Assumes 4-byte ASN encoding.
 *
 * The returned elements have timestamp=0 and unspecified peer IP/ASN since
 * those are not part of the BGP message itself.
 *
 * @param {Uint8Array} data - Raw BGP message bytes
 * @returns {object[]} Array of BgpElem objects
 */
function parseBgpUpdate(data) {
  return JSON.parse(wasm.parseBgpUpdate(data));
}

// MRT common header: timestamp(4) + type(2) + subtype(2) + length(4) = 12 bytes.
// Extended timestamp records add 4 more bytes to the header but the length
// field still measures only the message body, so total = 12 + length (or 16 + length
// for extended). We read the basic 12-byte framing to extract one record at a time.
const MRT_HEADER_LEN = 12;

/**
 * Read the MRT record length from a 12-byte header.
 * Returns the total record size (header + body) or -1 if not enough data.
 * @param {Uint8Array} data
 * @param {number} offset
 * @returns {number}
 */
function mrtRecordSize(data, offset) {
  if (offset + MRT_HEADER_LEN > data.length) return -1;
  // length is a big-endian u32 at offset+8
  const bodyLen =
    (data[offset + 8] << 24) |
    (data[offset + 9] << 16) |
    (data[offset + 10] << 8) |
    data[offset + 11];
  return MRT_HEADER_LEN + (bodyLen >>> 0); // >>> 0 to treat as unsigned
}

/**
 * Parse a single MRT record from the start of a buffer.
 *
 * Only sends the bytes of that one record to WASM, so even multi-GB files
 * work without exceeding WASM's 4 GB memory limit.
 *
 * Returns `{ elems: BgpElem[], bytesRead: number }` on success,
 * or `null` when there are no more records.
 *
 * @param {Uint8Array} data - Remaining decompressed MRT bytes
 * @returns {{ elems: object[], bytesRead: number } | null}
 */
function parseMrtRecord(data) {
  const size = mrtRecordSize(data, 0);
  if (size < 0 || size > data.length) return null;
  // Pass only this record's bytes to WASM
  const recordBytes = data.subarray(0, size);
  const json = wasm.parseMrtRecord(recordBytes);
  if (!json) return null;
  const result = JSON.parse(json);
  // Override bytesRead with the framed size (the WASM side always reports
  // bytesRead == recordBytes.length, but we set it here for clarity)
  result.bytesRead = size;
  return result;
}

/**
 * Reset the internal MRT parser state. Call before parsing a new file
 * with `parseMrtRecord` to clear the PeerIndexTable from a previous file.
 */
function resetMrtParser() {
  wasm.resetMrtParser();
}

/**
 * Generator that yields parsed MRT records one at a time.
 *
 * Automatically resets parser state before starting, so the PeerIndexTable
 * from a previous file does not leak. Each iteration sends only one record's
 * bytes to WASM, keeping memory usage constant regardless of total file size.
 *
 * @param {Uint8Array} data - Decompressed MRT file bytes
 * @yields {{ elems: object[], bytesRead: number }}
 */
function* parseMrtRecords(data) {
  wasm.resetMrtParser();
  let offset = 0;
  while (offset < data.length) {
    const size = mrtRecordSize(data, offset);
    if (size < 0 || offset + size > data.length) break;
    const recordBytes = data.subarray(offset, offset + size);
    const json = wasm.parseMrtRecord(recordBytes);
    if (!json) break;
    const result = JSON.parse(json);
    result.bytesRead = size;
    yield result;
    offset += size;
  }
}

module.exports = {
  parseOpenBmpMessage,
  parseBmpMessage,
  parseMrtFile,
  parseMrtRecord,
  parseMrtRecords,
  resetMrtParser,
  parseBgpUpdate,
};
