use serde_json::json;
use std::path::PathBuf;
use std::io::Write;

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
    #[structopt(short,long)]
    json: bool,

    /// Pretty-print JSON output
    #[structopt(short,long)]
    pretty: bool,

    /// Count BGP elems
    #[structopt(short,long)]
    elems_count: bool,

    /// Count MRT records
    #[structopt(short,long)]
    records_count: bool,
}

fn main() {
    let opts: Opts = Opts::from_args();

    let parser = BgpkitParser::new(opts.file_path.to_str().unwrap()).unwrap();
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

