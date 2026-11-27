//! Count parsed MRT records without rendering them (measurement helper).

use bgpkit_parser::BgpkitParser;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: record_count <file>");
    let parser = BgpkitParser::new(&path).expect("open input");
    let mut count = 0usize;
    for record in parser.into_record_iter() {
        std::hint::black_box(&record);
        count += 1;
    }
    println!("records: {count}");
}
