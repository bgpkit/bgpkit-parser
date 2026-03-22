import * as wasm from './bundler/bgpkit_parser.js';

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
