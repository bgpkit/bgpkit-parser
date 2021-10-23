use std::io::BufReader;
use bzip2::read::BzDecoder;
use bgpkit_parser::BgpkitParser;

/// This example shows how to download and process a single BGP archive file with BGPKIT Parser.
///
/// The dependency needed for this example are:
/// ```
/// bzip2="0.4"
/// reqwest = { version = "0.11", features = ["json", "blocking", "stream"] }
/// ```
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("downloading updates file");
    // read updates data into bytes
    let data_bytes = reqwest::blocking::get("http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2")
        .unwrap().bytes().unwrap().to_vec();
    // create a buffered reader that wraps around a bzip2 decoder
    let reader = BufReader::new(BzDecoder::new(&*data_bytes));
    // create a parser that takes the buffered reader
    let parser = BgpkitParser::new(reader);

    log::info!("parsing updates file");
    // iterating through the parser. the iterator returns `BgpElem` one at a time.
    for elem in parser {
        // each BGP announcement contains one AS path, which depending on the path segment's type
        // there could be multiple origin ASNs (e.g. AS-Set as the origin)
        if let Some(origins) = &elem.origin_asns {
            if origins.contains(&13335) {
                log::info!("{}", &elem);
            }
        }
    }
    log::info!("done");
}