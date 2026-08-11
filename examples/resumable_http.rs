//! Parse a remote MRT file with the experimental resumable HTTP reader.
//!
//! The reader reconnects with an HTTP Range request after an interrupted
//! download. A server that does not support ranges, or a file that changes
//! during a reconnect, produces a fallible-iterator error instead of mixing
//! inconsistent bytes.
//!
//! Run with:
//! ```bash
//! cargo run --release --example resumable_http -- [MRT_FILE_URL]
//! ```

use bgpkit_parser::BgpkitParser;

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://data.ris.ripe.net/rrc00/latest-update.gz".to_owned());

    let parser = BgpkitParser::new_resumable_http(&url).unwrap_or_else(|error| {
        eprintln!("Unable to open {url}: {error}");
        std::process::exit(1);
    });

    let mut records = 0;
    for result in parser.into_fallible_record_iter() {
        match result {
            Ok(_) => records += 1,
            Err(error) => {
                eprintln!("Parsing stopped after {records} records: {error}");
                if let Some(bytes) = error.bytes {
                    eprintln!("The failed record consumed {} bytes.", bytes.len());
                }
                std::process::exit(1);
            }
        }
    }

    println!("Parsed {records} MRT records from {url}");
}
