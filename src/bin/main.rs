use itertools::Itertools;
use serde_json::json;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;

use bgpkit_parser::{BgpElem, BgpkitParser, Elementor};
use clap::Parser;
use ipnet::IpNet;

/// bgpkit-parser-cli is a simple cli tool that allow parsing of individual MRT files.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Opts {
    /// File path to a MRT file, local or remote.
    #[clap(name = "FILE")]
    file_path: PathBuf,

    /// Set the cache directory for caching remote files. Default behavior does not enable caching.
    #[clap(short, long)]
    cache_dir: Option<PathBuf>,

    /// Output as JSON objects
    #[clap(long)]
    json: bool,

    /// Output as full PSV entries with header
    #[clap(long)]
    psv: bool,

    /// Pretty-print JSON output
    #[clap(long)]
    pretty: bool,

    /// Count BGP elems
    #[clap(short, long)]
    elems_count: bool,

    /// Count MRT records
    #[clap(short, long)]
    records_count: bool,

    #[clap(flatten)]
    filters: Filters,
}

#[derive(Parser, Debug)]
struct Filters {
    /// Filter by origin AS Number
    #[clap(short = 'o', long)]
    origin_asn: Option<u32>,

    /// Filter by network prefix
    #[clap(short = 'p', long)]
    prefix: Option<IpNet>,

    /// Include super-prefix when filtering
    #[clap(short = 's', long)]
    include_super: bool,

    /// Include sub-prefix when filtering
    #[clap(short = 'S', long)]
    include_sub: bool,

    /// Filter by IPv4 only
    #[clap(short = '4', long)]
    ipv4_only: bool,

    /// Filter by IPv6 only
    #[clap(short = '6', long)]
    ipv6_only: bool,

    /// Filter by peer IP address
    #[clap(short = 'j', long)]
    peer_ip: Vec<IpAddr>,

    /// Filter by peer ASN
    #[clap(short = 'J', long)]
    peer_asn: Option<u32>,

    /// Filter by elem type: announce (a) or withdraw (w)
    #[clap(short = 'm', long)]
    elem_type: Option<String>,

    /// Filter by start unix timestamp inclusive
    #[clap(short = 't', long)]
    start_ts: Option<f64>,

    /// Filter by end unix timestamp inclusive
    #[clap(short = 'T', long)]
    end_ts: Option<f64>,

    /// Filter by AS path regex string
    #[clap(short = 'a', long)]
    as_path: Option<String>,
}

fn main() {
    let opts: Opts = Opts::parse();

    env_logger::init();

    let file_path = opts.file_path.to_str().unwrap();

    let parser_opt = match opts.cache_dir {
        None => BgpkitParser::new(file_path),
        Some(c) => BgpkitParser::new_cached(file_path, c.to_str().unwrap()),
    };

    let mut parser = match parser_opt {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    if let Some(v) = opts.filters.as_path {
        parser = parser.add_filter("as_path", v.as_str()).unwrap();
    }
    if let Some(v) = opts.filters.origin_asn {
        parser = parser
            .add_filter("origin_asn", v.to_string().as_str())
            .unwrap();
    }
    if let Some(v) = opts.filters.prefix {
        let filter_type = match (opts.filters.include_super, opts.filters.include_sub) {
            (false, false) => "prefix",
            (true, false) => "prefix_super",
            (false, true) => "prefix_sub",
            (true, true) => "prefix_super_sub",
        };
        parser = parser
            .add_filter(filter_type, v.to_string().as_str())
            .unwrap();
    }
    if !opts.filters.peer_ip.is_empty() {
        let v = opts.filters.peer_ip.iter().map(|p| p.to_string()).join(",");
        parser = parser.add_filter("peer_ips", v.as_str()).unwrap();
    }
    if let Some(v) = opts.filters.peer_asn {
        parser = parser
            .add_filter("peer_asn", v.to_string().as_str())
            .unwrap();
    }
    if let Some(v) = opts.filters.elem_type {
        parser = parser.add_filter("type", v.as_str()).unwrap();
    }
    if let Some(v) = opts.filters.start_ts {
        parser = parser
            .add_filter("start_ts", v.to_string().as_str())
            .unwrap();
    }
    if let Some(v) = opts.filters.end_ts {
        parser = parser.add_filter("end_ts", v.to_string().as_str()).unwrap();
    }

    match (opts.filters.ipv4_only, opts.filters.ipv6_only) {
        (true, true) => {
            eprintln!("Error: --ipv4-only and --ipv6-only cannot be used together");
            std::process::exit(1);
        }
        (false, false) => {
            // no filters on IP version, skip
        }
        (true, false) => {
            parser = parser.add_filter("ip_version", "ipv4").unwrap();
        }
        (false, true) => {
            parser = parser.add_filter("ip_version", "ipv6").unwrap();
        }
    }

    match (opts.elems_count, opts.records_count) {
        (true, true) => {
            let mut elementor = Elementor::new();
            let (mut records_count, mut elems_count) = (0, 0);
            for record in parser.into_record_iter() {
                records_count += 1;
                elems_count += elementor.record_to_elems(record).len();
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
            for (index, elem) in parser.into_elem_iter().enumerate() {
                let output_str = if opts.json {
                    let val = json!(elem);
                    if opts.pretty {
                        serde_json::to_string_pretty(&val).unwrap()
                    } else {
                        val.to_string()
                    }
                } else if opts.psv {
                    if index == 0 {
                        format!("{}\n{}", BgpElem::get_psv_header(), elem.to_psv())
                    } else {
                        elem.to_psv()
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
