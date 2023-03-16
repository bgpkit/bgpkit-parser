use bgpkit_parser::BgpkitParser;
use itertools::Itertools;

fn main() {
    for elem in BgpkitParser::new(
        "http://archive.routeviews.org/bgpdata/2023.03/RIBS/rib.20230316.0200.bz2",
    )
    .unwrap()
    {
        if let Some(otc) = elem.only_to_customer {
            println!(
                "OTC found: {} for path {}\n{}\n",
                &otc,
                &elem
                    .as_path
                    .as_ref()
                    .unwrap()
                    .to_u32_vec()
                    .unwrap()
                    .iter()
                    .map(|x| x.to_string())
                    .join(":"),
                &elem
            );
        }
    }
}
