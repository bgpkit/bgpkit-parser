use criterion::criterion_main;

mod benchmarks;

criterion_main! {
    benchmarks::bgpdump::bgpdump,
    benchmarks::bgpkit_parser::bgpkit_parser,
}