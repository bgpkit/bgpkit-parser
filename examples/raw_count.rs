//! Count raw MRT records: framing only, no attribute decoding.
use bgpkit_parser::BgpkitParser;

fn main() {
    let path = std::env::args().nth(1).expect("usage: raw_count <file>");
    let parser = BgpkitParser::new(&path).expect("open");
    println!("raw records: {}", parser.into_raw_record_iter().count());
}
