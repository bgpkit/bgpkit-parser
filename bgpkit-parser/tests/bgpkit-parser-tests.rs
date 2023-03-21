#[cfg(test)]
mod tests {
    use bgp_models::prelude::BgpElem;
    use bgpkit_parser::BgpkitParser;

    #[test]
    fn test_parser_as_paths_conversion() {
        let url = "https://spaces.bgpkit.org/parser/update-example.gz";
        let parser = BgpkitParser::new(url)
            .unwrap()
            .add_filter("peer_ip", "185.1.8.50")
            .unwrap()
            .add_filter("type", "a")
            .unwrap();

        let elems = parser.into_elem_iter().collect::<Vec<BgpElem>>();
        assert_eq!(
            vec![200612, 174, 1299, 31027, 198622],
            elems
                .first()
                .unwrap()
                .as_path
                .as_ref()
                .unwrap()
                .to_u32_vec()
                .unwrap()
        );
    }
}
