fn main() {
    for elem in bgpkit_parser::BgpkitParser::new("./updates.bz2").unwrap() {
        println!("{:?}", elem);
    }
}
