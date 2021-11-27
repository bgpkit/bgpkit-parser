use criterion::criterion_main;

mod benchmarks;

criterion_main! {
    benchmarks::bgpkit_parser::bgpkit_parser,
    benchmarks::bgpdump::bgpdump,
}