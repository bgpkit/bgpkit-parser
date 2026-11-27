//! Parse every `.gz` file in a directory, the way a broker-style consumer reads thousands of small
//! updates files: one parser per file, elements counted, no output.
//!
//! `cargo run --release --example many_files -- <directory> [filter key=value ...]`
//!
//! Prints the file count, the element count and an FNV hash of the element prefixes so two runs (or
//! two tools) can be shown to have read the same data.
use bgpkit_parser::BgpkitParser;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        !args.is_empty(),
        "usage: many_files <directory> [filter key=value ...]"
    );
    let directory = args.remove(0);
    // `--render` formats every element the way the CLI's default format does, so the run can be
    // compared with a tool that always renders.
    let render = args.iter().any(|arg| arg == "--render");
    args.retain(|arg| arg != "--render");
    let filters: Vec<(String, String)> = args
        .iter()
        .map(|filter| {
            let (key, value) = filter.split_once('=').expect("filter key=value");
            (key.to_string(), value.to_string())
        })
        .collect();

    let mut paths: Vec<_> = std::fs::read_dir(&directory)
        .expect("read directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "gz" || extension == "bz2")
        })
        .collect();
    paths.sort();

    let mut files = 0usize;
    let mut elems = 0usize;
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    // Rendering writes to a sink: the formatting cost is the point, the bytes are not.
    let mut out = std::io::BufWriter::new(std::io::sink());
    for path in &paths {
        let mut parser = BgpkitParser::new(path.to_str().expect("utf-8 path")).expect("open file");
        for (key, value) in &filters {
            parser = parser.add_filter(key, value).expect("valid filter");
        }
        for elem in parser.into_elem_iter() {
            if render {
                use std::io::Write;
                writeln!(out, "{elem}").expect("write element");
            }
            elems += 1;
            let prefix = elem.prefix.prefix;
            hash ^= u64::from(prefix.prefix_len());
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            let bytes = match prefix.addr() {
                std::net::IpAddr::V4(address) => address.octets().to_vec(),
                std::net::IpAddr::V6(address) => address.octets().to_vec(),
            };
            for byte in bytes {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        files += 1;
    }

    println!("files={files} elems={elems} hash={hash}");
}
