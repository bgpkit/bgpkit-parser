use log::info;
use std::fs::File;
use std::io::{BufReader, Read};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use crate::ParserError;

/// create a [BufReader] on heap from a given path to a file, located locally or remotely.
pub(crate) fn get_reader(path: &str) -> Result<Box<dyn Read>, ParserError> {
    // create reader for reading raw content from local or remote source, bytes can be compressed
    let raw_reader: Box<dyn Read> = match path.starts_with("http") {
        true => {
            let response = reqwest::blocking::get(path)?;
            Box::new(response)
        }
        false => {
            Box::new(File::open(path)?)
        }
    };

    let file_type = path.split(".").collect::<Vec<&str>>().last().unwrap().clone();
    match file_type {
        "gz" => {
            let reader = Box::new(GzDecoder::new(raw_reader));
            Ok(Box::new(BufReader::new(reader)))
        }
        "bz2" => {
            let reader = Box::new(BzDecoder::new(raw_reader));
            Ok(Box::new(BufReader::new(reader)))
        }
        _ => {
            info!("unknown file type of file {}. try to read as uncompressed file", path);
            let reader = Box::new(raw_reader);
            Ok(Box::new(BufReader::new(reader)))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::BgpkitParser;

    #[test]
    fn test_open_remote_bz2() {
        let url = "http://archive.routeviews.org/route-views.sydney/bgpdata/2021.12/UPDATES/updates.20211205.0430.bz2";
        let parser = BgpkitParser::new(url).unwrap();
        let elem_count = parser.into_elem_iter().count();
        assert_eq!(elem_count, 97770);
    }

    #[test]
    fn test_open_remote_gz() {
        let url = "http://data.ris.ripe.net/rrc23/2021.12/updates.20211205.0450.gz";
        let parser = BgpkitParser::new(url).unwrap();
        let elem_count = parser.into_elem_iter().count();
        assert_eq!(elem_count, 41819);
    }

    #[test]
    fn test_remote_uncompressed() {
        let url = "https://bgpkit-data.sfo3.digitaloceanspaces.com/parser/update-example";
        let parser = BgpkitParser::new(url).unwrap();
        let elem_count = parser.into_elem_iter().count();
        assert_eq!(elem_count, 8160);
    }
}