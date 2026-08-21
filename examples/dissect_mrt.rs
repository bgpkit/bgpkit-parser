//! Wireshark-style byte-level dissection of MRT records and BGP messages.
//!
//! The dissectors build a `DissectionNode` tree where every protocol field
//! carries its byte range (`offset`/`length`): MRT common header (including
//! ET microsecond fields), BGP4MP subheader, BGP message header, UPDATE
//! path-attribute internals (AS_PATH segments, communities, MP_REACH
//! structure), and per-prefix NLRI. They are best-effort passes that never
//! fail: truncated input yields a partial tree, which is the basis for
//! "edit a byte, see where parsing breaks" tooling.
//!
//! Run with:
//! ```bash
//! cargo run --release --example dissect_mrt -- <MRT_FILE_OR_URL> [COUNT]
//! ```

use bgpkit_parser::models::DissectionNode;
use bgpkit_parser::parser::mrt::dissect::dissect_mrt_record;
use std::fmt::Write;

/// Render a dissection tree with byte-offset gutters, like a protocol analyzer.
fn render(node: &DissectionNode, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    let _ = writeln!(
        out,
        "{indent}[{:#08x}..{:#08x}] {} ({})",
        node.offset,
        node.offset + node.length,
        node.label,
        node.field
    );
    for child in &node.children {
        render(child, depth + 1, out);
    }
}

fn main() {
    let source = match std::env::args().nth(1) {
        Some(s) => s,
        None => {
            eprintln!("Usage: dissect_mrt <MRT_FILE_OR_URL> [COUNT]");
            std::process::exit(2);
        }
    };
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(3);

    let parser = bgpkit_parser::BgpkitParser::new(&source).unwrap_or_else(|error| {
        eprintln!("Unable to open {source}: {error}");
        std::process::exit(1);
    });

    for (index, raw) in parser.into_raw_record_iter().take(count).enumerate() {
        let tree = dissect_mrt_record(&raw);
        let mut rendered = String::new();
        render(&tree, 0, &mut rendered);
        println!("=== record {index} ===\n{rendered}");
    }

    // Dissectors are best-effort: truncated input cannot fail, it just stops
    // at the last field that could be walked. Demonstrate on cut-down bytes.
    if let Some(raw) = parser_records_for_truncation(&source) {
        let full = raw.raw_bytes();
        let cut = full.len() / 2;
        let tree = bgpkit_parser::parser::mrt::dissect::dissect_mrt_bytes(&full[..cut]);
        println!(
            "=== truncated to {cut}/{} bytes: tree has {} top-level field(s), no error ===",
            full.len(),
            tree.children.len()
        );
    }
}

/// Re-open the source independently so the parser above is not consumed here.
fn parser_records_for_truncation(source: &str) -> Option<bgpkit_parser::RawMrtRecord> {
    bgpkit_parser::BgpkitParser::new(source)
        .ok()?
        .into_raw_record_iter()
        .next()
}
