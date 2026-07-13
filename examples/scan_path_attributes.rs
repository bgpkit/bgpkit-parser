/// Scan MRT archives for interesting BGP path attributes.
///
/// Iterates over recent RouteViews and RIPE RIS update files, scanning for
/// deprecated, unknown/unassigned, and raw-retained attributes.
///
/// The optional argument selects the archive month (`YYYY.MM`); the example
/// samples days 1 and 2 at fixed intervals from that month.
///
/// Usage:
/// ```bash
/// cargo run --example scan_path_attributes -- 2026.06
/// ```
use bgpkit_parser::BgpkitParser;
use std::collections::HashMap;

/// Scan a single MRT file, sampling up to `max_elems` elements.
fn scan_file(url: &str, max_elems: u64) -> Result<(HashMap<String, u64>, u64), String> {
    let parser = BgpkitParser::new(url).map_err(|e| format!("parser error: {e}"))?;
    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut processed = 0u64;

    for elem in parser.into_elem_iter() {
        // Check unknown/unassigned and raw-retained known attributes
        if let Some(ref unknown) = elem.unknown {
            for raw in unknown {
                let key = format!("unknown(code={}, type={:?})", raw.code, raw.attr_type());
                *counts.entry(key).or_default() += 1;
            }
        }

        // Check deprecated attributes
        if let Some(ref deprecated) = elem.deprecated {
            for raw in deprecated {
                let key = format!("deprecated(code={})", raw.code);
                *counts.entry(key).or_default() += 1;
            }
        }

        processed += 1;
        if processed >= max_elems {
            break;
        }
    }
    Ok((counts, processed))
}

fn main() {
    let month = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "2026.06".to_string());
    let month_bytes = month.as_bytes();
    if month_bytes.len() != 7
        || month_bytes[4] != b'.'
        || !month_bytes[..4]
            .iter()
            .chain(&month_bytes[5..])
            .all(|byte| byte.is_ascii_digit())
    {
        eprintln!("Usage: scan_path_attributes [YYYY.MM]");
        std::process::exit(2);
    }

    let archive_month = month.replace('.', "");
    println!("=== BGP Path Attribute Scanner ({month}) ===");
    println!("Looks for unsupported/raw/deprecated attributes in public archive files.\n");

    // RouteViews collectors
    let collectors = [
        "route-views4",
        "route-views6",
        "route-views2",
        "route-views3",
        "route-views.linx",
        "route-views.eqix",
        "route-views.amsix",
    ];

    let mut urls: Vec<String> = Vec::new();

    // RouteViews update files — days 1 and 2, sampling hours 0 and 12
    for collector in &collectors {
        for day in [1, 2] {
            for hour in [0, 12] {
                let url = format!(
                    "http://archive.routeviews.org/{}/bgpdata/{}/UPDATES/updates.{}{:02}.{:04}00.bz2",
                    collector, month, archive_month, day, hour
                );
                urls.push(url);
            }
        }
    }

    // RIPE RIS update files
    for rrc in 0..=6 {
        for day in [1, 2] {
            let url = format!(
                "https://data.ris.ripe.net/rrc{:02}/{}/updates.{}{:02}.0000.gz",
                rrc, month, archive_month, day
            );
            urls.push(url);
        }
    }

    println!(
        "Candidates: {} files (sampling 50K elements each)",
        urls.len()
    );
    println!();

    let mut found_files: Vec<(String, HashMap<String, u64>)> = Vec::new();

    for url in &urls {
        print!("  {:65}", url);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        match scan_file(url, 50_000) {
            Ok((counts, processed)) => {
                if counts.is_empty() {
                    println!("  ({}K elems, nothing)", processed / 1000);
                } else {
                    println!("  ({}K elems, {} hits)", processed / 1000, counts.len());
                    found_files.push((url.clone(), counts));
                }
            }
            Err(e) => {
                eprintln!("  error: {}", e);
            }
        }
    }

    println!();
    if found_files.is_empty() {
        println!("No interesting attributes found in the scanned window.");
        println!(
            "This is expected: deprecated and specialized attributes are rare in public data."
        );
    } else {
        println!("=== Files with interesting attributes ===");
        println!();
        for (url, counts) in &found_files {
            println!("File: {}", url);
            let mut entries: Vec<_> = counts.iter().collect();
            entries.sort_by_key(|(k, _)| String::clone(k));
            for (key, count) in &entries {
                println!("  {}: {}", key, count);
            }
            println!();
        }
    }
}
