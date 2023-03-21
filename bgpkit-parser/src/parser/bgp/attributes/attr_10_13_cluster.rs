use crate::parser::ReadUtils;
use crate::ParserError;
use bgp_models::prelude::*;
use std::io::Cursor;

#[allow(unused)]
fn parse_cluster_id(
    input: &mut Cursor<&[u8]>,
    afi: &Option<Afi>,
) -> Result<AttributeValue, ParserError> {
    let afi = match afi {
        None => &Afi::Ipv4,
        Some(a) => a,
    };
    let addr = input.read_address(afi)?;
    Ok(AttributeValue::Clusters(vec![addr]))
}

pub fn parse_clusters(
    input: &mut Cursor<&[u8]>,
    afi: &Option<Afi>,
    total_bytes: usize,
) -> Result<AttributeValue, ParserError> {
    // FIXME: in https://tools.ietf.org/html/rfc4456, the CLUSTER_LIST is a set of CLUSTER_ID each represented by a 4-byte number
    let mut clusters = Vec::new();
    let initial_pos = input.position();
    while input.position() - initial_pos < total_bytes as u64 {
        let afi = match afi {
            None => &Afi::Ipv4,
            Some(a) => a,
        };

        let addr = input.read_address(afi)?;

        clusters.push(addr);
    }
    Ok(AttributeValue::Clusters(clusters))
}
