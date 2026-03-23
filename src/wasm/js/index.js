'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const wasm = require('./nodejs/bgpkit_parser.js');

// ── Low-level parsing functions ──────────────────────────────────────

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

// ── Streaming MRT record parsing ─────────────────────────────────────

// MRT common header: timestamp(4) + type(2) + subtype(2) + length(4) = 12 bytes.
const MRT_HEADER_LEN = 12;

/**
 * Read the MRT record length from a 12-byte header.
 * Returns the total record size (header + body) or -1 if not enough data.
 */
function mrtRecordSize(data, offset) {
  if (offset + MRT_HEADER_LEN > data.length) return -1;
  const bodyLen =
    (data[offset + 8] << 24) |
    (data[offset + 9] << 16) |
    (data[offset + 10] << 8) |
    data[offset + 11];
  return MRT_HEADER_LEN + (bodyLen >>> 0);
}

/**
 * Parse a single MRT record from the start of a buffer.
 *
 * Only sends the bytes of that one record to WASM, so even multi-GB files
 * work without exceeding WASM's 4 GB memory limit.
 *
 * @param {Uint8Array} data - Remaining decompressed MRT bytes
 * @returns {{ elems: object[], bytesRead: number } | null}
 */
function parseMrtRecord(data) {
  const size = mrtRecordSize(data, 0);
  if (size < 0 || size > data.length) return null;
  const recordBytes = data.subarray(0, size);
  const json = wasm.parseMrtRecord(recordBytes);
  if (!json) return null;
  const result = JSON.parse(json);
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

// ── I/O helpers (oneio-style transparent source + compression) ───────

/**
 * Try to load an optional bzip2 decompressor.
 * Supports: 'unbzip2-stream' (streaming), 'seek-bzip' (sync), 'bz2' (sync).
 */
let _bz2Module = undefined; // undefined = not checked, null = not available
function getBz2() {
  if (_bz2Module !== undefined) return _bz2Module;
  for (const name of ['unbzip2-stream', 'seek-bzip', 'bz2']) {
    try {
      _bz2Module = { name, mod: require(name) };
      return _bz2Module;
    } catch {}
  }
  _bz2Module = null;
  return null;
}

/**
 * Detect compression type from a file path or URL.
 * @param {string} pathOrUrl
 * @returns {'gz' | 'bz2' | 'xz' | 'none'}
 */
function detectCompression(pathOrUrl) {
  const name = pathOrUrl.split('?')[0].split('#')[0]; // strip query/fragment
  if (name.endsWith('.gz')) return 'gz';
  if (name.endsWith('.bz2')) return 'bz2';
  if (name.endsWith('.xz')) return 'xz';
  return 'none';
}

/**
 * Open an HTTP(S) URL and return a readable stream, following redirects.
 * @param {string} url
 * @returns {Promise<import('stream').Readable>}
 */
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    lib
      .get(url, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          httpGet(res.headers.location).then(resolve, reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        resolve(res);
      })
      .on('error', reject);
  });
}

/**
 * Collect a readable stream into a single Buffer.
 * @param {import('stream').Readable} stream
 * @returns {Promise<Buffer>}
 */
function collectStream(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

/**
 * Decompress a buffer based on the detected compression type.
 * @param {Buffer} buf
 * @param {'gz' | 'bz2' | 'xz' | 'none'} compression
 * @returns {Buffer}
 */
function decompressSync(buf, compression) {
  if (compression === 'gz') {
    return zlib.gunzipSync(buf);
  }
  if (compression === 'bz2') {
    const bz2 = getBz2();
    if (!bz2) {
      throw new Error(
        'bzip2 decompression requires an optional dependency. ' +
          'Install one of: npm install unbzip2-stream, npm install seek-bzip, npm install bz2'
      );
    }
    if (bz2.name === 'seek-bzip') {
      return Buffer.from(bz2.mod.decode(buf));
    }
    if (bz2.name === 'bz2') {
      const decompress = bz2.mod.decompress || bz2.mod;
      return Buffer.from(decompress(buf));
    }
    // unbzip2-stream: streaming, need to pipe through
    throw new Error(
      'unbzip2-stream does not support sync decompression. ' +
        'Use streamMrtFrom() instead, or install seek-bzip or bz2.'
    );
  }
  if (compression === 'xz') {
    throw new Error('xz decompression is not yet supported in the WASM package');
  }
  return buf;
}

/**
 * Create a decompression stream for the given compression type.
 * @param {'gz' | 'bz2' | 'xz' | 'none'} compression
 * @returns {import('stream').Transform | null}
 */
function decompressStream(compression) {
  if (compression === 'gz') {
    return zlib.createGunzip();
  }
  if (compression === 'bz2') {
    const bz2 = getBz2();
    if (!bz2) {
      throw new Error(
        'bzip2 decompression requires an optional dependency. ' +
          'Install one of: npm install unbzip2-stream, npm install seek-bzip, npm install bz2'
      );
    }
    if (bz2.name === 'unbzip2-stream') {
      return bz2.mod();
    }
    // seek-bzip and bz2 don't have streaming APIs; collect and decompress
    return null;
  }
  return null;
}

/**
 * Open an MRT file from a local path or URL, automatically decompressing
 * based on the file extension (.gz, .bz2).
 *
 * This is the JS equivalent of oneio's `get_reader(path)` — it makes the
 * source (local file vs HTTP) and compression format transparent.
 *
 * @param {string} pathOrUrl - Local file path or HTTP(S) URL
 * @returns {Promise<Buffer>} Decompressed MRT file bytes
 */
async function openMrt(pathOrUrl) {
  const compression = detectCompression(pathOrUrl);
  const isUrl =
    pathOrUrl.startsWith('http://') || pathOrUrl.startsWith('https://');

  if (isUrl) {
    const rawStream = await httpGet(pathOrUrl);
    const decomp = decompressStream(compression);
    if (decomp) {
      return collectStream(rawStream.pipe(decomp));
    }
    // No streaming decompressor available — collect then decompress sync
    const raw = await collectStream(rawStream);
    return decompressSync(raw, compression);
  }

  // Local file
  const raw = fs.readFileSync(pathOrUrl);
  return decompressSync(raw, compression);
}

/**
 * Async generator that streams MRT records from a local path or URL.
 *
 * Handles fetching, decompression (gz/bz2), and incremental parsing.
 * Each yield returns one MRT record's elements, keeping WASM memory
 * usage constant regardless of file size.
 *
 * @param {string} pathOrUrl - Local file path or HTTP(S) URL
 * @yields {{ elems: object[], bytesRead: number }}
 *
 * @example
 * for await (const { elems } of streamMrtFrom("https://archive.routeviews.org/.../rib.20250101.0000.bz2")) {
 *   for (const elem of elems) {
 *     console.log(elem.prefix, elem.as_path);
 *   }
 * }
 */
async function* streamMrtFrom(pathOrUrl) {
  const raw = await openMrt(pathOrUrl);
  yield* parseMrtRecords(raw);
}

module.exports = {
  // Low-level byte parsers (all platforms)
  parseOpenBmpMessage,
  parseBmpMessage,
  parseBgpUpdate,
  parseMrtRecords,
  parseMrtRecord,
  resetMrtParser,

  // Node.js I/O helpers
  openMrt,
  streamMrtFrom,
};
