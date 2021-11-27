use std::fs::File;
use std::io::{BufReader, Read};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use crate::ParserError;

pub(crate) fn get_reader(path: &str) -> Result<Box<dyn Read>, ParserError> {
    let file_type = path.split(".").collect::<Vec<&str>>().last().unwrap().clone();
    assert!(file_type == "gz" || file_type== "bz2");

    let raw_reader: Box<dyn Read> = match path.starts_with("http") {
        true => {
            let response = reqwest::blocking::get(path)?;
            Box::new(response)
        }
        false => {
            Box::new(File::open(path)?)
        }
    };

    match file_type {
        "gz" => {
            let reader = Box::new(GzDecoder::new(raw_reader));
            Ok(Box::new(BufReader::new(reader)))
        }
        "bz2" => {
            let reader = Box::new(BzDecoder::new(raw_reader));
            Ok(Box::new(BufReader::new(reader)))
        }
        t => {
            panic!("unknown file type: {}", t)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::BgpkitParser;

    #[test]
    fn test_open_any() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let url = "http://archive.routeviews.org/bgpdata/2021.10/UPDATES/updates.20211001.0000.bz2";
        let parser = BgpkitParser::new(url).unwrap();

        log::info!("parsing updates file");
        // iterating through the parser. the iterator returns `BgpElem` one at a time.
        for elem in parser {
            // each BGP announcement contains one AS path, which depending on the path segment's type
            // there could be multiple origin ASNs (e.g. AS-Set as the origin)
            if let Some(origins) = &elem.origin_asns {
                if origins.contains(&13335) {
                    // log::info!("{}", &elem);
                }
            }
        }
    }
}