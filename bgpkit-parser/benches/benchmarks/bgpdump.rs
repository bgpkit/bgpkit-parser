use std::process::{Command, Stdio};
use criterion::{Criterion,criterion_group};

fn parse_with_bgpdump(path: &str) {
    let _output = Command::new("/opt/homebrew/bin/bgpdump").arg("-M").arg(path)
        .stdout(Stdio::null())
        .output();
}

fn bgpdump_benches(c: &mut Criterion) {

    let mut group = c.benchmark_group("parsing update file");
    group.sample_size(10);

    group.bench_function("parse rib bgpdump", |b| b.iter(|| parse_with_bgpdump("rib-example.bz2")));
    group.bench_function("parse update bgpdump", |b| b.iter(|| parse_with_bgpdump("update-example.gz")));

    group.finish();
}

criterion_group!(bgpdump, bgpdump_benches);
