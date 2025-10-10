# Examples

This directory contains runnable examples for bgpkit-parser. They demonstrate basic usage, filtering, batch processing with BGPKIT Broker, real-time streaming, attribute and metadata inspection, error handling, and more. Each entry below links directly to the source so you can browse it on GitHub.

## Quickstart and Iteration
- [parse-single-file.rs](parse-single-file.rs) — Download and iterate over a single RouteViews updates file, logging each BGP element (BgpElem).
- [display_elems.rs](display_elems.rs) — Print selected fields from each BGP element in a compact, pipe-delimited format.
- [count_elems.rs](count_elems.rs) — Count the total number of BGP elements in a given file.
- [records_iter.rs](records_iter.rs) — Iterate over raw MRT records and inspect/update messages; includes an example of detecting the Only-To-Customer (OTC) attribute.
- [scan_mrt.rs](scan_mrt.rs) — CLI-style scanner that quickly walks an MRT file, counting raw records, parsed records, or elements without processing them.

## Filtering and Policy Examples
- [filters.rs](filters.rs) — Parse an MRT file and filter by a specific prefix (e.g., 211.98.251.0/24), logging matching announcements.
- [filter_export_rib.rs](filter_export_rib.rs) — Filter the content of a RIB by origin ASN and re-encode/export to a new RIB file.
- [find_as_set_messages.rs](find_as_set_messages.rs) — Find announcements containing AS_SET/CONFED_SET segments in AS paths across RIBs retrieved via BGPKIT Broker.

## Batch and Broker Workflows
- [parse-files-from-broker.rs](parse-files-from-broker.rs) — Use BGPKIT Broker to find data files for a time range and parse them, including a simple origin-ASN filter example.
- [parse-files-from-broker-parallel.rs](parse-files-from-broker-parallel.rs) — Query BGPKIT Broker then parse multiple files in parallel using Rayon, reporting the total message count.
- [cache_reading.rs](cache_reading.rs) — Use the parser’s on-disk cache to avoid re-downloading the same remote files when iterating over time ranges.
- [mrt_filter_archiver.rs](mrt_filter_archiver.rs) — Apply filters while reading updates and archive the filtered stream into a new MRT file; re-parse to verify the output.

## Real-time Streams (RIS Live, RouteViews Kafka, BMP)
- [real-time-ris-live-websocket.rs](real-time-ris-live-websocket.rs) — Connect to RIPE RIS Live over WebSocket (tungstenite), subscribe to a collector, parse, and print elements.
- [real-time-ris-live-websocket-async.rs](real-time-ris-live-websocket-async.rs) — Async tokio+tungstenite version of the RIS Live WebSocket subscriber.
- [real-time-routeviews-kafka-openbmp.rs](real-time-routeviews-kafka-openbmp.rs) — Consume RouteViews Kafka topics (OpenBMP format), parse BMP messages, and print derived elements.
- [real-time-routeviews-kafka-to-mrt.rs](real-time-routeviews-kafka-to-mrt.rs) — Consume RouteViews Kafka BMP messages and archive them into an MRT file for later analysis.
- [bmp_listener.rs](bmp_listener.rs) — Minimal TCP BMP listener that parses incoming BMP Route Monitoring messages and logs them.

## Attributes and Metadata
- [extended_communities.rs](extended_communities.rs) — Print BGP elements that carry extended, large, or IPv6-extended communities.
- [deprecated_attributes.rs](deprecated_attributes.rs) — Identify announcements that include deprecated attributes (e.g., attribute 28, BGP Entropy Label Capability) and print them in JSON.
- [peer_index_table.rs](peer_index_table.rs) — Read a Table Dump v2 RIB and pretty-print the Peer Index Table in JSON.
- [only-to-customer.rs](only-to-customer.rs) — Find and display paths bearing the Only-To-Customer (OTC, RFC 9234) attribute.

## Error Handling and Robustness
- [fallible_parsing.rs](fallible_parsing.rs) — Demonstrate fallible record/element iterators that let you handle parse errors explicitly while continuing to process.

## Local-only and Misc
- [local_only/src/main.rs](local_only/src/main.rs) — Minimal example that reads a local updates.bz2 file; intended for local experimentation (not network fetching).
