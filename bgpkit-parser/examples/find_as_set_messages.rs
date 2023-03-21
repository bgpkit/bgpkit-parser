use bgp_models::bgp::AsPathSegment;
use bgpkit_broker::BgpkitBroker;
use bgpkit_parser::BgpkitParser;
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashSet;

fn main() {
    let items = BgpkitBroker::new()
        .data_type("rib")
        .project("route-views")
        .ts_start("2023-03-01T00:00:00Z")
        .ts_end("2023-03-01T00:00:00Z")
        .query()
        .unwrap();

    println!("start parsing {} ribs in parallel", items.len());
    let res: Vec<(String, HashSet<u32>)> = items
        .par_iter()
        .flat_map(|item| {
            let parser = BgpkitParser::new(item.url.as_str()).unwrap();
            let collector = item.collector_id.clone();
            let mut origins: HashSet<u32> = HashSet::new();
            for elem in parser {
                if !elem.elem_type.is_announce() {
                    continue;
                }
                for seg in elem.as_path.as_ref().unwrap().segments() {
                    match seg {
                        AsPathSegment::AsSet(p) | AsPathSegment::ConfedSet(p) => {
                            println!("{elem}");
                            origins.insert(p.last().unwrap().asn);
                        }
                        _ => {}
                    }
                }
            }

            return Some((collector, origins));
        })
        .collect();

    for (collector, origins) in res {
        println!(
            "{collector}\n{}",
            origins.iter().map(|v| v.to_string()).join(", ")
        );
    }
}
