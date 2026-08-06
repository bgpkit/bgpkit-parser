use bgpkit_parser::BgpkitParser;

/// This example parses a route-views `sh ip bgp` snapshot
/// (`oix-full-snapshot-*.bz2`) into `BgpElem`s.
///
/// `BgpkitParser::new_text` handles the bzip2 decompression and timestamp
/// inference, and streams elements one route line at a time (constant memory).
///
/// Route-views snapshots omit the `BGP table version` / `local AS` preamble,
/// so parsed elements carry the sentinel peer identity `0.0.0.0` / AS0.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let url = "https://archive.routeviews.org/oix-route-views/2026.07/oix-full-snapshot-2026-07-01-0000.bz2";

    log::info!("opening {url}");
    let parser = BgpkitParser::new_text(url).unwrap();
    log::info!("streaming text dump");

    let mut count = 0;
    for elem in parser {
        if count < 5 {
            println!("{elem}");
        }
        count += 1;
    }
    log::info!("parsed {count} elements");
}
