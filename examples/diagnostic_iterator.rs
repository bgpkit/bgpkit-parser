//! Classify malformed MRT records and export their raw bytes.
//!
//! The diagnostic iterator distinguishes clean records, parsed records with
//! recoverable RFC 7606 validation findings, and fatal parse failures.
//!
//! Run with:
//! ```bash
//! cargo run --release --example diagnostic_iterator -- <MRT_FILE_OR_URL> [OUTPUT_DIR]
//! ```

use bgpkit_parser::{BgpkitParser, DiagnosticEvent};
use std::path::{Path, PathBuf};

fn main() {
    let source = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: diagnostic_iterator <MRT_FILE_OR_URL> [OUTPUT_DIR]");
        std::process::exit(2);
    });
    let output_dir = std::env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("diagnostic-records"));

    let parser = BgpkitParser::new(&source).unwrap_or_else(|error| {
        eprintln!("Unable to open {source}: {error}");
        std::process::exit(1);
    });

    let mut clean = 0;
    let mut validation = 0;
    let mut parse_errors = 0;

    for (index, event) in parser.into_diagnostic_iter().enumerate() {
        match event {
            DiagnosticEvent::Record(_) => clean += 1,
            DiagnosticEvent::Validation {
                warnings,
                raw_record,
                ..
            } => {
                validation += 1;
                let path = output_path(&output_dir, index, "validation");
                save_raw_record(&raw_record, &path);
                eprintln!(
                    "record {index}: {} validation finding(s) -> {}",
                    warnings.len(),
                    path.display()
                );
            }
            DiagnosticEvent::ParseError {
                error,
                common_header,
                raw_bytes,
            } => {
                parse_errors += 1;
                eprintln!("record {index}: {error}");
                if let Some(header) = common_header {
                    eprintln!("  header: {header}");
                }
                if let Some(bytes) = raw_bytes {
                    let path = output_path(&output_dir, index, "parse-error");
                    save_bytes(&bytes, &path);
                }
            }
            _ => {}
        }
    }

    println!("clean records: {clean}");
    println!("records with validation findings: {validation}");
    println!("fatal parse errors: {parse_errors}");
}

fn output_path(output_dir: &Path, index: usize, kind: &str) -> PathBuf {
    output_dir.join(format!("{index:08}-{kind}.mrt"))
}

fn save_raw_record(raw_record: &bgpkit_parser::RawMrtRecord, path: &PathBuf) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create output directory");
    }
    raw_record
        .write_raw_bytes(path)
        .expect("failed to write diagnostic record");
}

fn save_bytes(bytes: &[u8], path: &PathBuf) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create output directory");
    }
    std::fs::write(path, bytes).expect("failed to write diagnostic record");
    eprintln!("  saved {} bytes to {}", bytes.len(), path.display());
}
