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
 * Parse a single BGP UPDATE message (with 16-byte marker + 2-byte length
 * + type header) into BGP elements. Assumes 4-byte ASN encoding.
 */
export function parseBgpUpdate(data: Uint8Array): BgpElem[];

/**
 * Parse a RIS Live WebSocket message using its JSON-projected UPDATE fields.
 * No `includeRaw` subscription option required, but the JSON projection
 * exposes only a subset of BGP path attributes (path, community, origin, med,
 * aggregator, announcements, withdrawals).
 */
export function parseRisLiveMessageJson(message: string): BgpElem[];

/**
 * Parse a RIS Live WebSocket message from its hex `data.raw` BGP wire bytes.
 * Requires a subscription with `socketOptions.includeRaw = true`.
 *
 * Preserves every path attribute of the UPDATE (large/extended communities,
 * OTC, local pref, originator ID, cluster list, AIGP, ...) plus RFC 7606
 * validation warnings. `elems` use the same `BgpElem` shape as
 * `parseRisLiveMessageJson` but are derived from the wire NLRI, so they can
 * differ from the JSON projection's grouping (e.g. a multi-prefix MP_REACH
 * yields one elem per prefix here, while RIS's projection may group them).
 */
export function parseRisLiveMessageRaw(message: string): RisLiveRawFull;

/**
 * Parse a single BGP UPDATE message (with header) with full attribute
 * fidelity: elements, every path attribute (including the ones the elem
 * projection drops — originator ID, cluster list, AIGP, raw-retained
 * BGPSEC_PATH/ATTR_SET, ...), and RFC 7606 validation warnings.
 */
export function parseBgpUpdateFull(data: Uint8Array): BgpUpdateFull;

/**
 * Dissect a single BGP message into a Wireshark-style field tree.
 *
 * Every node of the returned tree carries its byte range (`offset`/`length`
 * relative to the message start), so a UI can highlight the bytes behind any
 * protocol field and vice versa. Attribute values are dissected one level
 * deep (AS_PATH segments, community entries, MP_REACH structure, fixed u32
 * fields). Best effort: truncated input yields a partial tree, not an error.
 *
 * @param fourByteAsn 4-octet (modern default) vs 2-octet AS number rendering.
 */
export function dissectBgpMessage(
  data: Uint8Array,
  fourByteAsn?: boolean
): DissectionNode;

/**
 * Dissect one MRT record from the start of a buffer into a field tree whose
 * offsets cover the whole record: common header, BGP4MP subheader, and the
 * embedded BGP message. Returns null when no complete record is present.
 *
 * Slice off `bytesRead` bytes before the next call to advance.
 */
export function dissectMrtRecord(
  data: Uint8Array
): DissectMrtResult | null;

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

/** Full-fidelity result of `parseBgpUpdateFull`. */
export interface BgpUpdateFull {
  elems: BgpElem[];
  attributes: Attributes;
  validationWarnings: BgpValidationWarning[];
}

/** Result of `dissectMrtRecord`. */
export interface DissectMrtResult {
  tree: DissectionNode;
  bytesRead: number;
}

// ── High-level I/O helpers (Node.js only) ────────────────────────────

/**
 * Open an MRT file from a local path or URL, automatically decompressing
 * based on the file extension (.gz, .bz2).
 */
export function openMrt(pathOrUrl: string): Promise<Buffer>;

/**
 * Async generator that streams MRT records from a local path or URL.
 * Handles fetching, decompression, and incremental parsing.
 */
export function streamMrtFrom(
  pathOrUrl: string
): AsyncGenerator<MrtRecordResult, void, unknown>;

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
  /** Unknown attributes serialized as `{ code, bytes }` entries. */
  unknown: { code: number; bytes: number[] }[] | null;
  /** Deprecated attributes serialized as `{ code, bytes }` entries. */
  deprecated: { code: number; bytes: number[] }[] | null;
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

// ── RIS Live types ───────────────────────────────────────────────────

/** Envelope metadata carried by every RIS Live `ris_message`. */
export interface RisLiveMeta {
  host: string;
  id: string;
  peer: string;
  peerAsn: number;
  timestamp: number;
}

/**
 * Full-fidelity result of parsing a RIS Live message from `data.raw`.
 * `elems` use the same `BgpElem` shape as `parseRisLiveMessageJson` (derived
 * from the wire NLRI, so grouping may differ); `attributes` additionally
 * keeps attributes that the elem conversion drops (originator ID, cluster
 * list, AIGP, BGPSEC_PATH, ATTR_SET, ...).
 */
export interface RisLiveRawFull {
  meta: RisLiveMeta;
  elems: BgpElem[];
  attributes: Attributes;
  validationWarnings: BgpValidationWarning[];
}

// ── BGP attribute types (generated by ts-rs) ─────────────────────────
//
// The files under ./generated are produced from the Rust model types:
//   TS_RS_EXPORT_DIR=src/wasm/js/generated cargo test --features ts-rs
// Commit the regenerated files whenever the Rust models change; CI verifies
// they are up to date. Types with custom serde impls (AsPath, NetworkPrefix,
// Attributes) stay hand-written here or carry ts(...) overrides in Rust.

export type { DissectionNode } from './generated/DissectionNode';
export type { Span } from './generated/Span';
export type { SpannedWarning } from './generated/SpannedWarning';
export type { Attribute } from './generated/Attribute';
export type { AttributeValue } from './generated/AttributeValue';
export type { AsPathWire } from './generated/AsPathWire';
export type { AttrRaw } from './generated/AttrRaw';
export type { AttrType } from './generated/AttrType';
export type { BgpValidationWarning } from './generated/BgpValidationWarning';
export type { Afi } from './generated/Afi';
export type { Asn } from './generated/Asn';
export type { Community } from './generated/Community';
export type { ExtendedCommunity } from './generated/ExtendedCommunity';
export type { ExtendedCommunityType } from './generated/ExtendedCommunityType';
export type { LargeCommunity } from './generated/LargeCommunity';
export type { NextHopAddress } from './generated/NextHopAddress';
export type { Nlri } from './generated/Nlri';
export type { Origin } from './generated/Origin';
export type { Safi } from './generated/Safi';

/** All path attributes of one BGP UPDATE; serializes as an `Attribute[]`. */
export type Attributes = Attribute[];
