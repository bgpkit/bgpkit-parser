// TypeScript type definitions for the web target entry point.
// The web target requires calling init() before using any parsing functions.

export {
  BmpParsedMessage,
  BmpRouteMonitoringMessage,
  BmpPeerUpMessage,
  BmpPeerDownMessage,
  BmpInitiationMessage,
  BmpTerminationMessage,
  BmpStatsReportMessage,
  BmpRouteMirroringMessage,
  OpenBmpHeader,
  BmpPeerHeader,
  BgpElem,
  MrtRecordResult,
  RisLiveMeta,
  RisLiveRawFull,
  BgpUpdateFull,
  DissectMrtResult,
  DissectionNode,
  Span,
  SpannedWarning,
  Attribute,
  Attributes,
  BgpValidationWarning,
} from './index';

export {
  parseOpenBmpMessage,
  parseBmpMessage,
  parseBgpUpdate,
  parseBgpUpdateFull,
  dissectBgpMessage,
  parseRisLiveMessageJson,
  parseRisLiveMessageRaw,
  parseMrtRecord,
  dissectMrtRecord,
  resetMrtParser,
  parseMrtRecords,
} from './index';

/**
 * Initialize the WASM module. Must be called (and awaited) before using
 * any parsing functions.
 *
 * @param input - Optional URL, Request, or BufferSource of the .wasm file.
 *   If omitted, the default path is used.
 */
export function init(input?: RequestInfo | URL | BufferSource): Promise<void>;
