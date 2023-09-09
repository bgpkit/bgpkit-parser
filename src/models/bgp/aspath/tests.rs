use crate::models::*;
use itertools::Itertools;
use std::collections::HashSet;

#[test]
fn test_aspath_as4path_merge() {
    let aspath = AsPath::from_sequence([1, 2, 3, 5]);
    let as4path = AsPath::from_sequence([2, 3, 7]);
    let newpath = AsPath::merge_aspath_as4path(&aspath, &as4path).unwrap();
    assert_eq!(newpath.segments[0], AsPathSegment::sequence([1, 2, 3, 7]));
}

#[test]
fn test_get_origin() {
    let aspath = AsPath::from_sequence([1, 2, 3, 5]);
    let origins = aspath.get_singular_origin();
    assert_eq!(origins.unwrap(), Asn::from(5));

    let aspath = AsPath::from_segments(vec![
        AsPathSegment::sequence([1, 2, 3, 5]),
        AsPathSegment::set([7, 8]),
    ]);
    let origins = aspath.iter_origins().map_into::<u32>().collect::<Vec<_>>();
    assert_eq!(origins, vec![7, 8]);
}

#[test]
fn test_aspath_route_iter() {
    let path = AsPath::from_segments(vec![
        AsPathSegment::set([3, 4]),
        AsPathSegment::set([5, 6]),
        AsPathSegment::sequence([7, 8]),
    ]);
    assert_eq!(path.route_len(), 4);

    let mut routes = HashSet::new();
    for route in &path {
        assert!(routes.insert(route));
    }

    assert_eq!(routes.len(), 4);
    assert!(routes.contains(&vec![
        Asn::from(3),
        Asn::from(5),
        Asn::from(7),
        Asn::from(8)
    ]));
    assert!(routes.contains(&vec![
        Asn::from(3),
        Asn::from(6),
        Asn::from(7),
        Asn::from(8)
    ]));
    assert!(routes.contains(&vec![
        Asn::from(4),
        Asn::from(5),
        Asn::from(7),
        Asn::from(8)
    ]));
    assert!(routes.contains(&vec![
        Asn::from(4),
        Asn::from(6),
        Asn::from(7),
        Asn::from(8)
    ]));
}
