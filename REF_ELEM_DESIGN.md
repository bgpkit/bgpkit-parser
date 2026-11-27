# Borrowed element views

> **Status.** Shipped as the borrowed element engine: `next_record_elems` / `RecordElems` /
> `ElemRef` are public, and the default element iterator uses the same engine for RIB dumps. The
> numbers in section 1 are from before that work landed; the current figures, the filter pushdown
> and the framing rules are in `LAZY_RECORD_DESIGN.md`, which is the authoritative document for
> this branch.

## 1. What the measurements say

On the rrc00 bview of 2026-10-14 (420 MB gz, 55,786,629 elems), instructions, one thread:

| workload | instructions |
| --- | --- |
| framing only (`into_raw_record_iter`) | 26.0 G |
| full record parse into owned `MrtRecord` | 294.8 G |
| elem iteration (`into_elem_iter`) | 368.8 G |
| CAIDA BGPStream, records | 84.7 G |
| CAIDA BGPStream, elems with fields read | 123.4 G |

Our framing is 3.3x faster than BGPStream's whole records mode. Everything above it is eager
materialisation: `parse_mrt_body` decodes every attribute into owned Rust values (`Attributes`,
`Vec<PathAttribute>`, `AsPath` with per-segment storage, `Vec<MetaCommunity>`) whether or not the
caller reads them, and the elem path then dismantles that structure into `BgpElem`.

So the gap to BGPStream is not "we allocate for elems". It is "we decode eagerly, they decode on
demand". A borrowed view makes the record path collapse back to framing plus the fields actually
read.

## 2. Goal

One record in memory at a time; fields decoded when read; no per-element heap allocation. The
owned `BgpElem` API stays exactly as it is: this is a second, additive way to read the same data.

## 3. API shape

A lending iterator is not expressible with `Iterator` on stable Rust, so the shape is a record
batch that borrows the iterator:

```rust
impl<R: Read> BgpkitParser<R> {
    /// Advance to the next record and return a view over its elements.
    /// The view borrows the iterator; drop it before calling `next_record` again.
    pub fn next_record_elems(&mut self) -> Option<RecordElems<'_>>;
}

pub struct RecordElems<'a> { /* record body, peer table, scratch */ }

impl<'a> RecordElems<'a> {
    pub fn header(&self) -> &CommonHeader;
    pub fn len(&self) -> usize;               // exact, from the RIB entry count
    pub fn iter(&mut self) -> ElemRefIter<'_>; // yields ElemRef<'_>
}

pub struct ElemRef<'a> { /* scalars + slices into the record body */ }

impl<'a> ElemRef<'a> {
    pub fn prefix(&self) -> NetworkPrefix;
    pub fn peer_ip(&self) -> IpAddr;
    pub fn peer_asn(&self) -> Asn;
    pub fn as_path(&self) -> AsPathView<'a>;           // no allocation
    pub fn origin_asns(&self) -> AsnsView<'a>;
    pub fn communities(&self) -> CommunitiesView<'a>; // raw u32 words + typed accessors
    pub fn next_hop(&self) -> Option<IpAddr>;
    pub fn med(&self) -> Option<u32>;
    pub fn local_pref(&self) -> Option<u32>;
    pub fn timestamp(&self) -> f64;
    pub fn elem_type(&self) -> ElemType;
}
```

No callback API is needed if `RecordElems` is the ownership boundary: the caller iterates a
record's elements, then asks for the next record. That composes with existing `for` loops via
`while let Some(mut record) = parser.next_record_elems() { for e in record.iter() { ... } }`.

## 4. Where each field comes from

- `prefix`, `seq`, `entry count`: decoded once per record from the RIB_AFI header, already done.
- `peer_ip`, `peer_asn`: from the peer index table, borrowed for the same `'a` as the record. The
  table lives in the iterator, so one lifetime covers both; a table swap mid-file ends the current
  `RecordElems` borrow first by construction.
- `as_path`: the wire is AS_SEQUENCE / AS_SET segments. Expose `AsPathView<'a>` as a slice of
  segments pointing into the body, with an iterator that expands sets on the fly, and a
  `to_vec()` escape hatch. No arena needed for the common case.
- `origin_asns`: derived from the last segment; a small iterator, no allocation.
- `communities`: words borrowed from the attribute, not `&'a [u32]`. MRT payloads sit at
  1-byte alignment and communities are big-endian, so the slice is `&'a
  [zerocopy::big_endian::U32]` through a length check, with `as_plain()`, `as_extended()`,
  `as_ipv6_extended()` and `as_large()` adapters that interpret in place. A plain `&[u32]`
  needs `unsafe` or a copy; the design was wrong about that.
- `next_hop`, `med`, `local_pref`, `origin`, `atomic_aggregate`, `aggregator`: scalars copied out
  of the attribute slice as they are parsed.
- Unknown, deprecated, malformed attributes: exposed as `raw()` slices, same policy as today.

Scratch space: if a record needs expansion that cannot be a slice (for example AS4 merging of a
2-byte-path plus AS4_PATH), one `Vec` inside `RecordElems` is reused across records, not per elem.

## 5. Invariants

1. `ElemRef<'a>` never outlives its `RecordElems`; enforced by the borrow checker, no `unsafe`
   lifetime extension, no `transmute`.
2. Peak memory is one record body (bounded by 16 MiB) plus one reusable scratch buffer plus the
   peer table. Iterating a 4 GB RIB must not grow RSS with the number of elements.
3. Field values are identical to what `into_elem_iter` produces for every element on the fixtures,
   compared through `BgpElem`'s own accessors.
4. Error, warning and core-dump behaviour is the existing one; a malformed attribute yields a
   missing field plus the same warning the owned path emits.
5. No `unsafe` in the new module. If a slice cast is unavoidable (u32 community words), it is one
   documented helper with a length check and a test.

## 6. Acceptance

- `count` workload on the RIB: within 20% of the raw framing number (26 G on the `.gz`), i.e.
  under ~32 G, against 368.8 G for the owned elem path today.
- "prefix + peer + as_path" workload (what a monocle filter needs): under 150 G on the `.gz`,
  against 368.8 G today and 123.4 G for BGPStream.
- byte-identical field values against `into_elem_iter` on the RIB fixture and the updates fixture;
  RSS stays flat over a 4 GB file (assert < 50 MiB).

## 7. Non-goals

- No change to `BgpElem`, `into_elem_iter`, or any existing iterator.
- No BMP, no text dumps, no filters in the first version.
- No attempt to make `ElemRef` storable: a caller that keeps elements copies them.

## 8. Open questions

- Whether `next_record_elems` should also be offered as `for_each_elem` for callers who want a
  plain loop without the outer `while let`. Decide from the first consumer's ergonomics.
- Whether the peer table borrow forces `RecordElems` to be `!Send`. That is acceptable: the
  parallel iterator is the way to use more cores, and it owns its own records.
- Whether the CLI's `-e` and the PSV/JSON writers move to views. The counting path is where the
  measurement is easy; the writers are mechanical follow-up.
