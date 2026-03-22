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

module.exports = { parseOpenBmpMessage, parseBmpMessage, parseMrtFile, parseBgpUpdate };
