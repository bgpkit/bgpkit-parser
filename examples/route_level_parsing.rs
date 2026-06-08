use bgpkit_parser::{BgpkitParser, Filterable};
use std::time::Instant;

/// This example demonstrates the lightweight route-level parser (`into_route_iter()`)
/// which provides significantly faster processing when you only need basic route
/// information (prefix, AS path, peer metadata) without full BGP attributes.
///
/// Performance characteristics:
/// - Updates files: ~10-15% faster (fewer attributes to skip)
/// - RIB dump files: ~50-70% faster (many attributes per route)
///
/// Use `into_route_iter()` when you need:
/// - prefix, AS path, peer IP/AS, timestamp
/// - Fast scanning/filtering of large datasets
/// - No need for communities, MED, next-hop, local-pref, etc.
///
/// Use `into_elem_iter()` when you need:
/// - Full BGP attributes (communities, MED, next-hop, local-pref, etc.)
/// - Community-based filtering
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Example 1: Download and parse an updates file using route iterator
    log::info!("=== Example 1: Route-level parsing ===");

    let url = "http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2";

    let start = Instant::now();
    let parser = BgpkitParser::new(url).unwrap();

    let mut route_count = 0;
    'routes: for batch in parser.into_route_iter() {
        for route in batch.routes() {
            let route = route.unwrap();
            if route_count < 3 {
                log::info!(
                    "Route {}: {} via AS{} (peer: {})",
                    route_count + 1,
                    route.prefix,
                    route.peer_asn,
                    route.peer_ip
                );
                if let Some(path) = route.as_path {
                    log::info!("  AS Path: {}", path);
                }
            }
            route_count += 1;
            if route_count >= 1000 {
                break 'routes;
            }
        }
    }
    let route_time = start.elapsed();
    log::info!(
        "Route-level parsing: {} routes in {:.3}s",
        route_count,
        route_time.as_secs_f64()
    );

    // Example 2: Compare with element-level parsing
    log::info!("\n=== Example 2: Element-level parsing (full attributes) ===");

    let start = Instant::now();
    let parser = BgpkitParser::new(url).unwrap();

    let mut elem_count = 0;
    for elem in parser.into_elem_iter().take(1000) {
        if elem_count < 3 {
            log::info!(
                "Element {}: {} via AS{} (next-hop: {:?})",
                elem_count + 1,
                elem.prefix,
                elem.peer_asn,
                elem.next_hop
            );
            if let Some(ref communities) = elem.communities {
                log::info!("  Communities: {:?}", communities);
            }
        }
        elem_count += 1;
    }
    let elem_time = start.elapsed();
    log::info!(
        "Element-level parsing: {} elements in {:.3}s",
        elem_count,
        elem_time.as_secs_f64()
    );

    // Example 3: Filtering with route elements
    log::info!("\n=== Example 3: Filtering route elements ===");

    let parser = BgpkitParser::new(url).unwrap();
    // Filter for routes from peer AS49788 (seen in the output above)
    let filter = bgpkit_parser::Filter::new("peer_asn", "49788").unwrap();

    let mut filtered_count = 0;
    let mut seen = 0;
    'routes: for batch in parser.into_route_iter() {
        for route in batch.all_routes() {
            let route = route.unwrap();
            if route.match_filter(&filter) {
                filtered_count += 1;
                if filtered_count <= 3 {
                    log::info!(
                        "Matched filter (peer_asn=49788): {} from AS{}",
                        route.prefix,
                        route.peer_asn
                    );
                }
            }
            seen += 1;
            if seen >= 1000 {
                break 'routes;
            }
        }
    }
    log::info!(
        "Total routes matching filter (first 1000): {}",
        filtered_count
    );

    // Example 4: Demonstrate AS path filtering
    log::info!("\n=== Example 4: AS path filtering ===");

    let parser = BgpkitParser::new(url).unwrap();
    // Filter for routes with AS1299 somewhere in the path
    let as_path_filter = bgpkit_parser::Filter::new("as_path", "1299").unwrap();

    let mut as_path_matches = 0;
    let mut seen = 0;
    'routes: for batch in parser.into_route_iter() {
        for route in batch.all_routes() {
            let route = route.unwrap();
            if route.match_filter(&as_path_filter) {
                as_path_matches += 1;
                if as_path_matches <= 3 {
                    log::info!(
                        "AS Path contains 1299: {} - path: {:?}",
                        route.prefix,
                        route.as_path.map(|p| p.to_string())
                    );
                }
            }
            seen += 1;
            if seen >= 1000 {
                break 'routes;
            }
        }
    }
    log::info!(
        "Total routes with AS1299 in path (first 1000): {}",
        as_path_matches
    );

    log::info!("\n=== Summary ===");
    log::info!(
        "Route-level: {:.3}s | Element-level: {:.3}s",
        route_time.as_secs_f64(),
        elem_time.as_secs_f64()
    );
    log::info!("");
    log::info!("Performance gain is most significant for RIB dumps with many attributes.");
    log::info!("For update files, the difference is smaller since there are fewer attributes.");
    log::info!("Note: Community filters are NOT supported with route elements.");
}
