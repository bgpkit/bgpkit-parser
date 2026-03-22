// TypeScript type definitions for @bgpkit/parser WebAssembly bindings.
//
// These types describe the JSON output produced by the Rust WASM functions.

// ── Parsing functions ────────────────────────────────────────────────

/**
 * Parse an OpenBMP-wrapped BMP message (e.g. from the RouteViews Kafka stream).
 * Returns null for non-router OpenBMP frames (collector heartbeats).
 */
export function parseOpenBmpMessage(data: Uint8Array): BmpParsedMessage | null;

/**
 * Parse a raw BMP message (no OpenBMP wrapper).
 * @param timestamp Collection time in seconds since Unix epoch.
 */
export function parseBmpMessage(
  data: Uint8Array,
  timestamp: number
): BmpParsedMessage;

/**
 * Parse a decompressed MRT file into BGP elements.
 * Handles TABLE_DUMP, TABLE_DUMP_V2, and BGP4MP record types.
 */
export function parseMrtFile(data: Uint8Array): BgpElem[];

/**
 * Parse a single BGP UPDATE message (with 16-byte marker + 2-byte length
 * + type header) into BGP elements. Assumes 4-byte ASN encoding.
 */
export function parseBgpUpdate(data: Uint8Array): BgpElem[];

/**
 * Parse a single MRT record from the start of a buffer.
 * Returns null when there are no more records.
 *
 * Slice off `bytesRead` bytes before the next call to advance.
 */
export function parseMrtRecord(data: Uint8Array): MrtRecordResult | null;

/**
 * Reset the internal MRT parser state. Call before parsing a new file
 * with `parseMrtRecord` to clear the PeerIndexTable from a previous file.
 * (Called automatically by `parseMrtRecords`.)
 */
export function resetMrtParser(): void;

/**
 * Generator that yields MRT records one at a time, automatically slicing
 * the buffer as it advances. Resets parser state before starting.
 */
export function parseMrtRecords(
  data: Uint8Array
): Generator<MrtRecordResult, void, unknown>;

export interface MrtRecordResult {
  elems: BgpElem[];
  bytesRead: number;
}

// ── BMP message types (discriminated union on `type`) ────────────────

export type BmpParsedMessage =
  | BmpRouteMonitoringMessage
  | BmpPeerUpMessage
  | BmpPeerDownMessage
  | BmpInitiationMessage
  | BmpTerminationMessage
  | BmpStatsReportMessage
  | BmpRouteMirroringMessage;

interface BmpMessageBase {
  openBmpHeader: OpenBmpHeader | null;
  timestamp: number;
}

export interface BmpRouteMonitoringMessage extends BmpMessageBase {
  type: "RouteMonitoring";
  peerHeader: BmpPeerHeader;
  elems: BgpElem[];
}

export interface BmpPeerUpMessage extends BmpMessageBase {
  type: "PeerUpNotification";
  peerHeader: BmpPeerHeader;
  localIp: string;
  localPort: number;
  remotePort: number;
}

export interface BmpPeerDownMessage extends BmpMessageBase {
  type: "PeerDownNotification";
  peerHeader: BmpPeerHeader;
  reason: string;
}

export interface BmpInitiationMessage extends BmpMessageBase {
  type: "InitiationMessage";
  tlvs: Array<{ type: string; value: string }>;
}

export interface BmpTerminationMessage extends BmpMessageBase {
  type: "TerminationMessage";
  tlvs: Array<{ type: string; value: string }>;
}

export interface BmpStatsReportMessage extends BmpMessageBase {
  type: "StatisticsReport";
  peerHeader: BmpPeerHeader;
}

export interface BmpRouteMirroringMessage extends BmpMessageBase {
  type: "RouteMirroringMessage";
  peerHeader: BmpPeerHeader;
}

// ── Shared types ─────────────────────────────────────────────────────

export interface OpenBmpHeader {
  routerIp: string;
  routerGroup: string | null;
  adminId: string;
  timestamp: number;
}

export interface BmpPeerHeader {
  peerIp: string;
  peerAsn: number;
  peerBgpId: string;
  peerType: string;
  isPostPolicy: boolean;
  isAdjRibOut: boolean;
  timestamp: number;
}

export interface BgpElem {
  timestamp: number;
  type: "ANNOUNCE" | "WITHDRAW";
  peer_ip: string;
  peer_asn: number;
  peer_bgp_id: string | null;
  prefix: string;
  next_hop: string | null;
  as_path: AsPath | null;
  origin_asns: number[] | null;
  origin: string | null;
  local_pref: number | null;
  med: number | null;
  communities: MetaCommunity[] | null;
  atomic: boolean;
  aggr_asn: number | null;
  aggr_ip: string | null;
  only_to_customer: number | null;
}

// ── AS path types ────────────────────────────────────────────────────

/**
 * AS path in simplified format: a flat array where numbers are ASNs in
 * AS_SEQUENCE segments and nested arrays are AS_SET members.
 * Example: [6447, 39120, [643, 836], 352]
 *
 * Falls back to verbose format with confederation segments:
 * [{ ty: "AS_CONFED_SEQUENCE", values: [123, 942] }, ...]
 */
export type AsPath = AsPathElement[];
export type AsPathElement = number | number[] | AsPathVerboseSegment;
export interface AsPathVerboseSegment {
  ty: "AS_SET" | "AS_SEQUENCE" | "AS_CONFED_SEQUENCE" | "AS_CONFED_SET";
  values: number[];
}

// ── Community types ──────────────────────────────────────────────────

/** Discriminated union of all BGP community types (serde untagged). */
export type MetaCommunity = PlainCommunity | LargeCommunity | ExtendedCommunity;

export type PlainCommunity =
  | { Custom: [number, number] }
  | "NoExport"
  | "NoAdvertise"
  | "NoExportSubConfed";

export interface LargeCommunity {
  global_admin: number;
  local_data: [number, number];
}

/** Extended community — many variants, treat as opaque JSON object. */
export type ExtendedCommunity = Record<string, unknown>;
