//! Cut the first N raw MRT records of a file into a new fixture (development helper).

use bgpkit_parser::BgpkitParser;
use std::io::Write;

fn main() {
    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .expect("usage: cut_fixture <input> <output> <records>");
    let output = args.next().expect("missing output");
    let count: usize = args.next().expect("missing count").parse().expect("count");

    let parser = BgpkitParser::new(&input).expect("open input");
    let mut out = std::io::BufWriter::new(std::fs::File::create(&output).expect("create output"));
    let mut written = 0usize;
    for record in parser.into_raw_record_iter().take(count) {
        out.write_all(&record.raw_bytes()).expect("write record");
        written += 1;
    }
    out.flush().expect("flush");
    println!("wrote {written} records");
}
