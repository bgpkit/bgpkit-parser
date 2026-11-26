# Lazy record: the internal parsing unit

## 1. Goal

One internal representation of a framed MRT record, from which every public iterator expands only
what it needs, without changing any public type or signature.

Today three places know the MRT layout: `parse_mrt_body` (owned `MrtRecord`), the fast framing path
(`ChunkedRecord` + `parse_chunk_with_zebra_compat`), and the RIB view engine (`elem_ref.rs`,
#368). Each record also allocates its own body `Vec` (2.9 KB average, about 4 GB of allocation and
copying over the 1.43M records of a full RIB), and the raw path allocates a second time for the
header.

This replaces that with one `Frame` per record, borrowed from a reusable buffer.

## 2. Non-goals

No public item changes: `MrtRecord`, `BgpElem`, `RawMrtRecord`, every iterator signature and every
output format stay exactly as they are. A view-typed public iterator is a separate, later decision
(PR #368 stays a parked draft).

## 3. Structs

```rust
/// Reader-owned state, reused across records.
struct ReaderState {
    framer: Framer,                 // common-header state only
    body: Vec<u8>,                  // one buffer, refilled per record
    peers: Option<Vec<Peer>>,       // dense, indexed by wire peer_index (not a HashMap)
}

/// One framed record. Borrows the body buffer; never allocates.
///
/// It deliberately does not carry the peer table: `PEER_INDEX_TABLE` records replace it
/// mid-stream, so a borrowed handle inside the frame would either alias that mutation or force a
/// per-record snapshot. Consumers that resolve `peer_index` take `&[Peer]` explicitly.
struct Frame<'a> {
    header: CommonHeader,   // 16 bytes, Copy
    raw_header: HeaderBuf,  // stack copy for raw/error paths
    body: &'a [u8],         // record bytes after the common header
}

enum FrameBody<'a> {
    PeerIndex(PeerIndexFrame<'a>),   // dump: replaces ReaderState.peer_table
    Rib(RibFrame<'a>),               // dump: one prefix, N peer entries
    Bgp4Mp(Bgp4MpFrame<'a>),         // updates: peer header + one BGP message
    Opaque,                          // legacy TABLE_DUMP v1, legacy BGP, BMP
}

struct RibFrame<'a>   { sequence: u32, prefix: NetworkPrefix, count: u16, entries: &'a [u8] }
struct RibEntry<'a>   { peer_index: u16, originated_time: u32, attrs: Attrs<'a> }

struct Bgp4MpFrame<'a> {
    peer_asn: Asn,
    local_asn: Asn,
    peer_ip: IpAddr,
    local_ip: IpAddr,
    afi: Afi,
    add_path: bool,        // from the entry subtype, as `check_add_path_consistency` does today
    message: &'a [u8],     // the BGP message
}
struct UpdateFrame<'a> { withdrawn: &'a [u8], announced: &'a [u8], attrs: Attrs<'a> }

struct Attrs<'a> { bytes: &'a [u8] }   // TLV walk; find(code) -> Option<&'a [u8]>, iter()
```

## 4. Two file kinds, one frame

- **RIB dumps**: `ReaderState.peer_table` is `Some`. A `PeerIndex` frame replaces it; a `Rib` frame
  resolves `RibEntry::peer_index` through the table the consumer passes in. A `Rib` frame with no
  table is the existing `MissingPeerTable` condition, not a new failure mode.
- **Updates**: there is no peer table and none is consulted. Peer identity comes from the
  `Bgp4MpFrame` header, so `peer_ip` / `peer_asn` filters are decidable at record level here, and
  only here. `add_path` comes from the BGP4MP subtype, preserving the current consistency check.
- **Other entry types**: `Opaque`, consumable only as bytes; every consumer falls back to today's
  behaviour.

## 5. Consumers

| public surface | expansion of the frame |
| --- | --- |
| `into_raw_record_iter` | `RawMrtRecord` (copies header and body into `Bytes`, as its contract requires) |
| `into_record_iter` | `Frame::to_record()` → owned `MrtRecord` |
| `into_elem_iter` | `FrameBody::elems()` → materialise one `BgpElem` per entry, one TLV pass per entry |
| `into_diagnostic_iter` | same `Frame`, findings retained per record |
| filter pass | `FrameBody::may_match(&[Filter])` → `Reject` / `Accept` / `Unknown`, stops at the first match |
| future view iterator | `FrameBody::entries()` → `ElemRef` |

The materialiser is the load-bearing piece: it must fill every `BgpElem` field from **one** pass over
the entry's attribute TLVs. Calling per-field accessors instead would walk the attribute list several
times per entry and make the new default slower than the old one.

## 6. Filter pushdown on top of it

A frame can answer record-level questions before any attribute is parsed:

| filter | RIB | updates | from |
| --- | --- | --- | --- |
| `prefix`, `prefixes` (exact/super/sub) | yes | no | `RibFrame::prefix` |
| `peer_ip`, `peer_asn` | no | yes | `Bgp4MpFrame` header |
| `ip_version` | yes | **no** | RIB subtype; the BGP4MP AFI is the peering transport family, while the filter tests the NLRI prefix (MP-BGP can differ) |
| `ts_start`, `ts_end` | **no** | yes | RIB elem time is the entry's `originated_time`, not the record header |
| `type` (a/w) | yes | needs the NLRI sections, not the attributes | entry type |
| stop at first match | only for the record predicate | only for the record predicate | elem iteration must visit every entry; stopping early loses the remaining peers |
| `origin*`, `as_path`, `community`, `otc`, `next_hop`, `local_pref`, `med`, `atomic`, `aggr_*`, `field present`, `peer_bgp_id` | no | no | attributes / peer table |

Rule: a record is skipped only when **some conjunct is certain to fail for every element it would
yield**. Undecidable means parse, never guess. For the undecidable ones the frame still helps: walking
`entries()` parses one entry at a time and stops at the first match, so an `origin_asn` filter never
builds a `BgpElem` for the rest of the record.

## 7. Invariants

1. No public API change; with no filters, output is byte-identical to today for every iterator.
2. `Frame` borrows the body and cannot outlive the next fill. Internal consumers are push-style;
   public iterators are unaffected because they hand out owned values.
3. One peer table owned by `ReaderState`, replaced when a `PeerIndex` frame is framed, never copied
   per record, and never reachable from a `Frame`.
4. A record skipped by a filter is not parsed, so it produces no attribute warnings and no RFC 7606
   findings. This is a documented behaviour change for filtered runs and goes in the changelog.
5. No `unsafe`; attribute and NLRI reads stay bounds-checked.

## 7.1 What the first two steps measured

- Sharing the framing (header + body read + legacy correction) with the borrowed element engine:
  no cost, net -190 lines.
- Routing the RIB entry walk through the frame's own entry iterator: **+6%** (29.46G vs 27.77G
  instructions on `bview.20261014.0000.gz`). Precomputing the entry offsets in the iterator instead:
  **+9%** (30.36G). The walk has to stay in the consumer's hot loop; the shared piece is the layout
  constants, not an iterator object. Keep this in mind before factoring the element path again.
- Therefore: typed views (`FrameBody`, `RibFrame`, `Bgp4MpFrame`) are proven by tests against parsed
  records for both a RIB dump and an updates file, and their first production consumer was the
  prefix pushdown, not the record path.
- The default element path now runs on the borrowed engine for RIB dumps: 270.6G / 30.7s ->
  173.5G / 17.7s on the uncompressed dump, 314.0G / 34.5s -> 218.0G / 21.3s compressed. Identical
  output on the full fixture, a 20k-line sample of the dump, and a whole updates file.
- Materialising `BgpElem` from a borrowed entry, isolated (both sides reading every field):
  536.6G / 55.9s from `into_elem_iter`, 404.4G / 38.8s from `ElemRef::to_bgp_elem`, so **1.33x**.
  The earlier 6.5x figure compared a four-field view walk against full element construction and was
  not like for like. Attribute decoding dominates both paths; the win comes from dropping the
  intermediate `Attributes` model, not from the element itself.

## 8. Migration, each step shippable and measured

1. DONE: `Framer` (borrowed body) + `Frame::kind()` producing `FrameBody` for `PeerIndex`,
   `Rib`, `Bgp4Mp`, `Opaque`, with parity tests over a RIB dump and an updates file.
2. NOT the record path: `MrtRecord` must own every `Vec<Attribute>` and `Bytes` attribute value, so
   expanding a borrowed frame into a record needs a 4.15 GB copy or a crate-wide `&[u8]` rewrite. The
   record path keeps its owned `Vec` and gains nothing from frames.
3. `into_elem_iter` materialises from `Frame`, one TLV pass per entry. Accept if the unfiltered elem
   path is ≤ 1.0x today's instructions *and* byte-identical output.
4. `into_record_iter` / `into_raw_record_iter` expand the same frames.
5. Prototype first: one standalone `rib_frame_to_elems(body, peers) -> BgpElem` function on a reused
   buffer, measured against `-e` before any iterator is rewired. Gate: parse-only slope and
   allocations per elem, not wall time.
6. Filter pass on `Frame` for the decidable filters above (RIB prefix is the only high-value one);
   accept on byte-identical filtered output plus the measured drop on `-p`.

## 8.1 Measured against BGPStream (same host, same files, output to /dev/null)

| workload | bgpreader | bgpkit-parser |
| --- | --- | --- |
| RIB, all elements | 1158.6G / 94.3s | 218.3G / 21.7s |
| RIB, `-p 8.8.8.0/24` | 117.3G / 8.8s | 46.7G / 4.5s |
| updates, all elements | 47.7G / 3.9s | 10.1G / 1.2s |
| updates, peer ASN 835 | 4.6G / 0.43s | 4.0G / 0.44s |
| RIB, full PSV export | (not compared) | 1304.9G / 155.3s -> 901.0G / 80.7s |

The field sets differ between the two tools, so these are approximate real-usage numbers, not
identical-output comparisons. Filtered scans on compressed input are now bounded by inflate.

## 9. Acceptance numbers

Same file and method as the baseline (`bview.20261014.0000.gz`, `perf stat` instructions, warm cache,
alternating runs):

- unfiltered elem iteration: ≤ 293.9 G / 33.2 s today; target ≤ today, byte-identical stream;
- `-p 8.8.8.0/24` on the gz file: 310.0 G / 35.6 s today, now 46.6 G / 4.52 s (6.7x instructions,
  7.9x wall). On the same stream uncompressed: 265 G / 31 s, now 2.14 G / 0.92 s (124x). The gz
  residual is decompression plus the per-record read, not record parsing; the uncompressed number is
  the ceiling this change reaches.
- `-o <origin_asn>`: 307.4 G today; target below 250 G (saves elem construction, keeps attribute
  parsing) and stops at the first matching entry per record;
- `into_record_iter`: ≤ 184.7 G / 21.1 s today, unchanged output;
- `into_raw_record_iter`: unchanged output, and the per-record header allocation removed.

Anything above those bounds is not an improvement and gets reverted, not explained.


## 10. Review findings (carbon, 2026-11-26) that changed this document

1. `ts_start` / `ts_end` are not decidable on RIB records: elem time is the entry's `originated_time`.
2. `ip_version` is not decidable on updates: `BGP4MP.afi` is the transport family, the filter tests the
   NLRI prefix.
3. Stopping at the first matching entry is valid for the record predicate only; elem iteration must
   visit every entry of the record.
4. The record path cannot consume borrowed frames without an extra 4.15 GB copy; `MrtRecord` owns
   `Bytes` attribute values.
5. The peer table must stay a dense `Vec<Peer>`; a `HashMap` lookup per entry costs 55.8M lookups.
6. `RibGeneric` subtypes must report `Unsupported`, not `Opaque`. `Bgp4MpFrame` also needs `asn_len`,
   `msg_type` and StateChange handling, plus the shortened-Zebra compatibility case.
7. Wall-clock revert gates are noise on this host (up to 18% swing); gate on instructions and
   allocations per elem.
