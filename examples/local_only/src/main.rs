fn main() {
    let source = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./updates.bz2".to_string());
    for elem in bgpkit_parser::BgpkitParser::new(&source).unwrap() {
        println!("{:?}", elem);
    }
}
