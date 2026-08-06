use bgpkit_parser::BgpkitParser;

/// This example parses a PCH daily routing table snapshot, which is a Cisco
/// `sh ip bgp` fixed-width text dump (gzip-compressed), into `BgpElem`s.
///
/// `BgpkitParser::new_text` auto-detects decompression, infers the snapshot
/// timestamp from the file name, and returns elements through the same
/// `for elem in parser` interface used for MRT files.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let url = "https://downloads.pch.net/files/Routing_Data/IPv4_daily_snapshots/2026/07/route-collector.bom2.pch.net/route-collector.bom2.pch.net-ipv4_bgp_routes.2026.07.01.gz";

    log::info!("opening {url}");
    let parser = BgpkitParser::new_text(url).unwrap();
    log::info!("parsing text dump");

    let mut count = 0;
    for elem in parser {
        if count < 5 {
            println!("{elem}");
        }
        count += 1;
    }
    log::info!("parsed {count} elements");
}
