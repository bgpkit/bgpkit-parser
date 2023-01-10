use criterion::{criterion_group, Criterion};
use bgpkit_parser::BgpkitParser;

fn parse_update(path: &str, print: bool) {
    let parser = BgpkitParser::new(path).unwrap();
    for elem in parser {
        if print {
            let _elem_str = elem.to_string();
        }
    }
}

fn bgpkit_parser_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing update file");
    group.sample_size(10);

    group.bench_function("parse rib no-print", |b| b.iter(|| parse_update("/tmp/rib-example.bz2", false)));
    group.bench_function("parse rib with-print", |b| b.iter(|| parse_update("/tmp/rib-example.bz2", true)));

    group.bench_function("parse update no-print", |b| b.iter(|| parse_update("/tmp/update-example.gz", false)));
    group.bench_function("parse update with-print", |b| b.iter(|| parse_update("/tmp/update-example.gz", true)));

    group.finish();
}

criterion_group!(bgpkit_parser, bgpkit_parser_benches);