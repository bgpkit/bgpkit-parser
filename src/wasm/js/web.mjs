import initWasm from './web/bgpkit_parser.js';
import * as wasm from './web/bgpkit_parser.js';

/**
 * Initialize the WASM module. Must be called (and awaited) before using
 * any parsing functions.
 *
 * @param {RequestInfo | URL | BufferSource} [input] - Optional URL or buffer
 *   of the .wasm file. If omitted, the default path is used.
 */
export async function init(input) {
  await initWasm(input);
}

export function parseOpenBmpMessage(data) {
  const json = wasm.parseOpenBmpMessage(data);
  return json ? JSON.parse(json) : null;
}

export function parseBmpMessage(data, timestamp) {
  return JSON.parse(wasm.parseBmpMessage(data, timestamp));
}

export function parseMrtFile(data) {
  return JSON.parse(wasm.parseMrtFile(data));
}

export function parseBgpUpdate(data) {
  return JSON.parse(wasm.parseBgpUpdate(data));
}
