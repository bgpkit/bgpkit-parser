use bgpkit_parser::BgpkitParser;

/// This example demonstrates `BgpkitParser::new_auto`, which auto-detects
/// whether the input is an MRT file or a Cisco `sh ip bgp` text dump and
/// parses accordingly — no need to know the format in advance.
///
/// The same `for elem in parser` loop works for both MRT and text dumps.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // A Cisco `sh ip bgp` text dump from PCH — new_auto detects and parses it.
    let text_url = "https://downloads.pch.net/files/Routing_Data/IPv4_daily_snapshots/2026/07/route-collector.bom2.pch.net/route-collector.bom2.pch.net-ipv4_bgp_routes.2026.07.01.gz";
    log::info!("auto-detecting and parsing text dump: {text_url}");
    let count = BgpkitParser::new_auto(text_url)
        .unwrap()
        .into_elem_iter()
        .count();
    log::info!("text dump: {count} elements");

    // A standard MRT RIB file — new_auto treats it as MRT (lazy streaming).
    let mrt_url = "https://spaces.bgpkit.org/parser/update-example.gz";
    log::info!("auto-detecting and parsing MRT file: {mrt_url}");
    let count = BgpkitParser::new_auto(mrt_url)
        .unwrap()
        .into_elem_iter()
        .count();
    log::info!("MRT file: {count} elements");
}
