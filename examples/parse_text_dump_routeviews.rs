use bgpkit_parser::BgpkitParser;
use std::io::Read;

/// This example parses a route-views `sh ip bgp` snapshot
/// (`oix-full-snapshot-*.bz2`) into `BgpElem`s.
///
/// `BgpkitParser::new_text` handles the bzip2 decompression and timestamp
/// inference. Route-views snapshots omit the `BGP table version` / `local AS`
/// preamble, so parsed elements carry the sentinel peer identity `0.0.0.0` /
/// AS0.
///
/// The full snapshot is the entire global routing table (gigabytes of text),
/// so this example caps the input at ~20 MB via a manual reader. Remove the
/// cap to parse the complete file.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let url = "https://archive.routeviews.org/oix-route-views/2026.07/oix-full-snapshot-2026-07-01-0000.bz2";

    log::info!("opening {url} (first 20 MB)");
    let mut reader = oneio::get_reader(url).unwrap();
    // Cap the input for this demonstration: read at most 20 MB of decompressed
    // data, then feed it into the text-dump parser.
    let mut buf = Vec::with_capacity(20 * 1024 * 1024);
    let _ = reader.by_ref().take(20 * 1024 * 1024).read_to_end(&mut buf);
    let timestamp = bgpkit_parser::parser::text_dump::infer_timestamp_from_path(url).unwrap_or(0.0);
    let parser =
        BgpkitParser::from_text_reader_with_timestamp(std::io::Cursor::new(buf), timestamp)
            .unwrap();
    log::info!("parsing text dump (timestamp={timestamp})");

    let mut count = 0;
    for elem in parser {
        if count < 5 {
            println!("{elem}");
        }
        count += 1;
    }
    log::info!("parsed {count} elements");
}
