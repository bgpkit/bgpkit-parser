use bgpkit_parser::Elementor;
use bgpkit_parser::models::*;
use bgpkit_parser::BgpkitParser;

/// an very simple example that reads a remote BGP data file and print out the message count.
fn main() -> Result<(), Box<dyn std::error::Error>>{
    let url = "http://archive.routeviews.org/route-views.amsix/bgpdata/2023.02/UPDATES/updates.20230222.0430.bz2";
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();

    // Iterate over the file in order
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();
    let t0 = std::time::Instant::now();
    let mut cnt=  0;
    for _ in parser.into_elem_iter() {
        cnt += 1;
    }

    println!("Total number of routes: {cnt}");
    println!("Time elapsed: {:?}", t0.elapsed());

    // Scan the raw records
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();

    let t0 = std::time::Instant::now();
    let mut cnt = 0;
    for _ in parser.into_raw_record_iter() {
        cnt += 1;
    }
    println!("Total number of records: {cnt}");
    println!("Time elapsed: {:?}s (to chunk into raw records)", t0.elapsed());

    // Iterate with a shared Elementor
    let parser = BgpkitParser::new_cached(url, "/tmp").unwrap();

    let mut record_iter = parser.into_raw_record_iter().peekable();
    let mut elementor = Elementor::new();

    let t0 = std::time::Instant::now();

    // Peek to see if the first element is apeer index table. If so, consume it and set it.
    // See if the first element is a peer index table, if so, we use it.
    if let Some(potential_peer_index) = record_iter.peek().cloned() {
        if let Ok(pit) = potential_peer_index.parse() {
            if matches!(pit.message, MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_))) {
                elementor.set_peer_table(pit)?;
                record_iter.next(); // Consume peeked/cloned item on iterator.
            }
        }
    }

    let total: u64 = record_iter.map(|record| {
        if let Ok(record) = record.parse() {
            if let Ok(iter) = elementor.record_to_elems_iter(record) {
                let count = iter.count();
                return count as u64;
            }
        }
        0
    }).sum();

    println!("Total records: {total}");
    println!("Time elapsed: {:?}", t0.elapsed());
    Ok(())
}
