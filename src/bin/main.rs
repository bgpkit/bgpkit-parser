use serde_json::json;
use std::path::PathBuf;
use std::io::Write;
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use itertools::Itertools;

use structopt::StructOpt;
use bgpkit_parser::{BgpkitParser, Elementor};

/// bgpkit-parser-cli is a simple cli tool that allow parsing of individual MRT files.
#[derive(StructOpt, Debug)]
#[structopt(name="bgpkit-parser-cli")]
struct Opts {
    /// File path to a MRT file, local or remote.
    #[structopt(name="FILE", parse(from_os_str))]
    file_path: PathBuf,

    /// Output as JSON objects
    #[structopt(long)]
    json: bool,

    /// Pretty-print JSON output
    #[structopt(long)]
    pretty: bool,

    /// Count BGP elems
    #[structopt(short,long)]
    elems_count: bool,

    /// Count MRT records
    #[structopt(short,long)]
    records_count: bool,

    #[structopt(flatten)]
    filters: Filters,
}

#[derive(StructOpt, Debug)]
struct Filters {
    /// Filter by origin AS Number
    #[structopt(short="o", long)]
    origin_asn: Option<u32>,

    /// Filter by network prefix
    #[structopt(short="p", long)]
    prefix: Option<IpNetwork>,

    /// Include super-prefix when filtering
    #[structopt(short="s", long)]
    include_super: bool,

    /// Include sub-prefix when filtering
    #[structopt(short="S", long)]
    include_sub: bool,

    /// Filter by peer IP address
    #[structopt(short="j", long)]
    peer_ip: Vec<IpAddr>,

    /// Filter by peer ASN
    #[structopt(short="J", long)]
    peer_asn: Option<u32>,

    /// Filter by elem type: announce (a) or withdraw (w)
    #[structopt(short="m", long)]
    elem_type: Option<String>,

    /// Filter by start unix timestamp inclusive
    #[structopt(short="t", long)]
    start_ts: Option<f64>,

    /// Filter by end unix timestamp inclusive
    #[structopt(short="T", long)]
    end_ts: Option<f64>,

    /// Filter by AS path regex string
    #[structopt(short="a", long)]
    as_path: Option<String>,
}

fn main() {
    let opts: Opts = Opts::from_args();

    env_logger::init();

    let mut parser = BgpkitParser::new(opts.file_path.to_str().unwrap()).unwrap();

    if let Some(v) = opts.filters.as_path {
        parser = parser.add_filter("as_path", v.to_string().as_str()).unwrap();
    }
    if let Some(v) = opts.filters.origin_asn {
        parser = parser.add_filter("origin_asn", v.to_string().as_str()).unwrap();
    }
    if let Some(v) = opts.filters.prefix {
        let filter_type = match (opts.filters.include_super, opts.filters.include_sub) {
            (false, false) => "prefix",
            (true, false) => "prefix_super",
            (false, true) => "prefix_sub",
            (true, true) => "prefix_super_sub",
        };
        parser = parser.add_filter(filter_type, v.to_string().as_str()).unwrap();
    }
    if !opts.filters.peer_ip.is_empty(){
        let v = opts.filters.peer_ip.iter().map(|p| p.to_string()).join(",").to_string();
        parser = parser.add_filter("peer_ips", v.as_str()).unwrap();
    }
    if let Some(v) = opts.filters.peer_asn {
        parser = parser.add_filter("peer_asn", v.to_string().as_str()).unwrap();
    }
    if let Some(v) = opts.filters.elem_type {
        parser = parser.add_filter("type", v.to_string().as_str()).unwrap();
    }
    if let Some(v) = opts.filters.start_ts {
        parser = parser.add_filter("start_ts", v.to_string().as_str()).unwrap();
    }
    if let Some(v) = opts.filters.end_ts {
        parser = parser.add_filter("end_ts", v.to_string().as_str()).unwrap();
    }

    match (opts.elems_count, opts.records_count) {
        (true, true) => {
            let mut elementor = Elementor::new();
            let (mut records_count, mut elems_count) = (0, 0);
            for record in parser.into_record_iter() {
                records_count += 1;
                elems_count += elementor.record_to_elems(record).iter().count();
            }
            println!("total records: {}", records_count);
            println!("total elems:   {}", elems_count);
        }
        (false, true) => {
            println!("total records: {}", parser.into_record_iter().count());
        }
        (true, false) => {
            println!("total records: {}", parser.into_elem_iter().count());
        }
        (false, false) => {
            let mut stdout = std::io::stdout();
            for elem in parser {
                let output_str = if opts.json {
                    let val = json!(elem);
                    if opts.pretty {
                        serde_json::to_string_pretty(&val).unwrap()
                    } else {
                        val.to_string()
                    }
                } else {
                    elem.to_string()
                };
                if let Err(e) = writeln!(stdout, "{}", &output_str) {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        eprintln!("{}", e);
                    }
                    std::process::exit(1);
                }
            }
        }
    }
}

