//! Phase 1: Collect RIB dump data and calculate time differences
//!
//! This script downloads RIB dumps from route-views2 and rrc00 collectors,
//! parses them, and calculates the time difference between the dump timestamp
//! (from the filename) and the actual update timestamp in each RIB entry.
//!
//! Output: CSV file with columns: collector, prefix, origin_asn, time_diff_secs

use bgpkit_parser::BgpkitParser;
use csv::Writer;
use indicatif::{ProgressBar, ProgressStyle};

use serde::Serialize;
use std::fs::File;
use std::sync::Mutex;

/// Record structure for CSV output
#[derive(Debug, Serialize)]
struct TimeDiffRecord {
    collector: String,
    prefix: String,
    origin_asn: u32,
    time_diff_secs: i64,
}

/// Collector configuration
struct CollectorConfig {
    name: &'static str,
    url: &'static str,
    dump_timestamp: f64,
}

fn main() {
    println!("=== RIB Time Difference Study - Phase 1: Data Collection ===\n");

    // Unix timestamp for 2025-01-01T00:00:00Z
    let dump_timestamp: f64 = 1735689600.0;

    // Define collectors and their RIB dump URLs for 2025-01-01T00:00:00Z
    let collectors = vec![
        CollectorConfig {
            name: "route-views2",
            url: "http://archive.routeviews.org/bgpdata/2025.01/RIBS/rib.20250101.0000.bz2",
            dump_timestamp,
        },
        CollectorConfig {
            name: "rrc00",
            url: "https://data.ris.ripe.net/rrc00/2025.01/bview.20250101.0000.gz",
            dump_timestamp,
        },
    ];

    // Create output directory if it doesn't exist
    std::fs::create_dir_all("output").expect("Failed to create output directory");

    // Collect all records
    let all_records: Vec<TimeDiffRecord> = collectors
        .into_iter()
        .flat_map(|config| process_collector(config))
        .collect();

    // Write to CSV
    let output_path = "output/rib_time_diff.csv";
    println!(
        "\nWriting {} records to {}...",
        all_records.len(),
        output_path
    );

    let file = File::create(output_path).expect("Failed to create output CSV file");
    let mut writer = Writer::from_writer(file);

    for record in &all_records {
        writer.serialize(record).expect("Failed to write record");
    }

    writer.flush().expect("Failed to flush CSV writer");

    println!("Phase 1 complete! Data saved to {}", output_path);
    println!("\nSummary:");
    println!("  Total records: {}", all_records.len());

    // Print per-collector summary
    let route_views_count = all_records
        .iter()
        .filter(|r| r.collector == "route-views2")
        .count();
    let rrc00_count = all_records
        .iter()
        .filter(|r| r.collector == "rrc00")
        .count();

    println!("  route-views2: {} entries", route_views_count);
    println!("  rrc00: {} entries", rrc00_count);
}

/// Process a single collector and return all time diff records
fn process_collector(config: CollectorConfig) -> Vec<TimeDiffRecord> {
    println!("Processing collector: {}", config.name);
    println!("  URL: {}", config.url);
    println!(
        "  Dump timestamp: {} (2025-01-01T00:00:00Z)",
        config.dump_timestamp
    );

    // Create parser
    let parser = match BgpkitParser::new(config.url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  Error creating parser for {}: {}", config.name, e);
            return Vec::new();
        }
    };

    // Collect elements into a vector first to get count for progress bar
    println!("  Downloading and parsing RIB dump...");

    let records = Mutex::new(Vec::new());
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    progress.set_message(format!("Processing {} entries...", config.name));

    let count = Mutex::new(0u64);

    // Process elements
    parser.into_elem_iter().for_each(|elem| {
        // Only process announcements (not withdrawals) as they have origin ASN
        if !elem.is_announcement() {
            return;
        }

        // Get origin ASN - skip if not available or if it's an AS set
        let origin_asn = match elem.get_origin_asn_opt() {
            Some(asn) => asn,
            None => return,
        };

        // Calculate time difference: dump_timestamp - entry_timestamp
        // Positive value means the entry was updated before the dump
        let time_diff_secs = (config.dump_timestamp - elem.timestamp) as i64;

        let record = TimeDiffRecord {
            collector: config.name.to_string(),
            prefix: elem.prefix.to_string(),
            origin_asn,
            time_diff_secs,
        };

        let mut records_guard = records.lock().unwrap();
        records_guard.push(record);

        let mut count_guard = count.lock().unwrap();
        *count_guard += 1;
        if *count_guard % 100000 == 0 {
            progress.set_message(format!(
                "Processed {} entries from {}...",
                *count_guard, config.name
            ));
        }
    });

    progress.finish_with_message(format!(
        "Completed {} - {} entries processed",
        config.name,
        *count.lock().unwrap()
    ));

    records.into_inner().unwrap()
}
