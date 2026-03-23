import * as wasm from './bundler/bgpkit_parser.js';

export function parseOpenBmpMessage(data) {
  const json = wasm.parseOpenBmpMessage(data);
  return json ? JSON.parse(json) : null;
}

export function parseBmpMessage(data, timestamp) {
  return JSON.parse(wasm.parseBmpMessage(data, timestamp));
}

export function parseBgpUpdate(data) {
  return JSON.parse(wasm.parseBgpUpdate(data));
}

// ── Streaming MRT record parsing ─────────────────────────────────────

const MRT_HEADER_LEN = 12;

function mrtRecordSize(data, offset) {
  if (offset + MRT_HEADER_LEN > data.length) return -1;
  const bodyLen =
    (data[offset + 8] << 24) |
    (data[offset + 9] << 16) |
    (data[offset + 10] << 8) |
    data[offset + 11];
  return MRT_HEADER_LEN + (bodyLen >>> 0);
}

export function parseMrtRecord(data) {
  const size = mrtRecordSize(data, 0);
  if (size < 0 || size > data.length) return null;
  const recordBytes = data.subarray(0, size);
  const json = wasm.parseMrtRecord(recordBytes);
  if (!json) return null;
  const result = JSON.parse(json);
  result.bytesRead = size;
  return result;
}

export function resetMrtParser() {
  wasm.resetMrtParser();
}

export function* parseMrtRecords(data) {
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
