use std::fmt::Display;
use std::io;
use std::io::{stdout, BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;

use bgpkit_parser::filter::Filter;
use bgpkit_parser::models::ElemType;
use bgpkit_parser::{BgpkitParser, Elementor, PrefixMatchType};
use clap::Parser;
use ipnet::IpNet;

/// bgpkit-parser-cli is a simple cli tool that allow parsing of individual MRT files.
#[derive(Parser, Debug)]
#[clap(name = "bgpkit-parser-cli")]
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

    let mut parser = match {
        match opts.cache_dir {
            None => BgpkitParser::new(file_path),
            Some(c) => BgpkitParser::new_cached(file_path, c.to_str().unwrap()),
        }
    } {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    if let Some(v) = opts.filters.as_path {
        parser = parser.add_filter(Filter::as_path(v.as_str()).unwrap());
    }
    if let Some(v) = opts.filters.origin_asn {
        parser = parser.add_filter(Filter::OriginAsn(v));
    }
    if let Some(v) = opts.filters.prefix {
        let filter_type = match (opts.filters.include_super, opts.filters.include_sub) {
            (false, false) => PrefixMatchType::Exact,
            (true, false) => PrefixMatchType::IncludeSuper,
            (false, true) => PrefixMatchType::IncludeSub,
            (true, true) => PrefixMatchType::IncludeSuperSub,
        };
        parser = parser.add_filter(Filter::Prefix(v, filter_type));
    }
    if !opts.filters.peer_ip.is_empty() {
        parser = parser.add_filter(Filter::PeerIps(opts.filters.peer_ip.to_owned()));
    }
    if let Some(v) = opts.filters.peer_asn {
        parser = parser.add_filter(Filter::PeerAsn(v));
    }
    if let Some(v) = opts.filters.elem_type {
        let filter_type = match v.as_str() {
            "w" | "withdraw" | "withdrawal" => ElemType::WITHDRAW,
            "a" | "announce" | "announcement" => ElemType::ANNOUNCE,
            x => panic!("cannot parse elem type from {}", x),
        };
        parser = parser.add_filter(Filter::Type(filter_type));
    }
    if let Some(v) = opts.filters.start_ts {
        parser = parser.add_filter(Filter::TsStart(v));
    }
    if let Some(v) = opts.filters.end_ts {
        parser = parser.add_filter(Filter::TsEnd(v));
    }

    match (opts.elems_count, opts.records_count) {
        (true, true) => {
            let mut elementor = Elementor::new();
            let (mut records_count, mut elems_count) = (0, 0);
            for record in parser.into_record_iter() {
                match record {
                    Ok(record) => {
                        records_count += 1;
                        elems_count += elementor.record_to_elems(record).len();
                    }
                    Err(err) => handle_non_fatal_error(&mut stdout(), err),
                }
            }
            println!("total records: {}", records_count);
            println!("total elems:   {}", elems_count);
        }
        (false, true) => {
            println!("total records: {}", parser.into_record_iter().count());
        }
        (true, false) => {
            println!("total elems: {}", parser.into_elem_iter().count());
        }
        (false, false) => {
            let mut stdout = BufWriter::new(stdout().lock());

            for elem in parser {
                match elem {
                    Ok(elem) => {
                        if opts.json {
                            let res = if opts.pretty {
                                serde_json::to_writer_pretty(&mut stdout, &elem)
                            } else {
                                serde_json::to_writer(&mut stdout, &elem)
                            };

                            handle_serde_json_result(&mut stdout, res);
                        } else {
                            let res = writeln!(stdout, "{}", elem);
                            handle_io_result(&mut stdout, res);
                        }
                    }
                    Err(err) => {
                        let res = stdout.flush();
                        handle_io_result(&mut stdout, res);
                        eprintln!("{}", err);
                    }
                }
            }
        }
    }
}

fn handle_serde_json_result<W: Write>(stdout: &mut W, res: serde_json::Result<()>) {
    if let Err(err) = res {
        if err.is_io() {
            // If it was an IO error, we likely wont be able to flush stdout
            eprintln!("{}", err);
            std::process::exit(1);
        }

        handle_non_fatal_error(stdout, err);
    }
}

fn handle_non_fatal_error<W: Write, E: Display>(stdout: &mut W, err: E) {
    // Attempt to flush stdout before printing the error to avoid mangling combined CLI output
    if let Err(flush_err) = stdout.flush() {
        eprintln!("{}", err);
        eprintln!("{}", flush_err);
        std::process::exit(1);
    }

    // Write the error to stderr then flush stderr to avoid mangling combined CLI output
    eprintln!("{}", err);
    if io::stderr().flush().is_err() {
        // If this fails, then we are out of options for logging errors
        std::process::exit(1);
    }
}

fn handle_io_result<W: Write>(stdout: &mut W, res: io::Result<()>) {
    if let Err(err) = res {
        // We can try flushing stdout, but it will almost certainly fail
        let _ = stdout.flush();
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
