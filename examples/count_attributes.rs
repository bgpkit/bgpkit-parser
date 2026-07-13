//! Count BGP path attributes in an MRT file by wire code.
//!
//! This counts every parsed occurrence, including known-but-unsupported,
//! deprecated, and unassigned attributes retained as raw bytes.
//!
//! Run with:
//! ```bash
//! cargo run --release --example count_attributes -- <MRT_FILE_OR_URL>
//! ```
use bgpkit_parser::models::{Attributes, Bgp4MpEnum, BgpMessage, MrtMessage, TableDumpV2Message};
use bgpkit_parser::BgpkitParser;

fn count_attributes(attributes: &Attributes, counts: &mut [u64; 256]) {
    for attribute in attributes {
        counts[attribute.attr_code() as usize] += 1;
    }
}

fn main() {
    let source = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: count_attributes <MRT_FILE_OR_URL>");
        std::process::exit(2);
    });

    let parser = BgpkitParser::new(&source).unwrap_or_else(|error| {
        eprintln!("Unable to open {source}: {error}");
        std::process::exit(1);
    });
    let mut counts = [0_u64; 256];

    for record in parser.into_record_iter() {
        match record.message {
            MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(message)) => {
                if let BgpMessage::Update(update) = message.bgp_message {
                    count_attributes(&update.attributes, &mut counts);
                }
            }
            MrtMessage::TableDumpMessage(message) => {
                count_attributes(&message.attributes, &mut counts);
            }
            MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)) => {
                for entry in &rib.rib_entries {
                    count_attributes(&entry.attributes, &mut counts);
                }
            }
            MrtMessage::TableDumpV2Message(TableDumpV2Message::RibGeneric(rib)) => {
                for entry in &rib.rib_entries {
                    count_attributes(&entry.attributes, &mut counts);
                }
            }
            _ => {}
        }
    }

    println!("attribute_code,count");
    for (code, count) in counts.iter().enumerate().filter(|(_, count)| **count > 0) {
        println!("{code},{count}");
    }
}
