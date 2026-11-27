//! Streaming PSV rendering.
//!
//! Every field is appended to the caller's buffer, so a caller that renders many elements reuses
//! one allocation. Numbers, IPv4 addresses, prefixes and the AS path are written as digits instead
//! of going through `core::fmt`, which otherwise pays a formatter call per field per row. Values
//! with intricate text (IPv6 addresses, extended communities, `Origin`) delegate to their `Display`
//! implementation, so their wording has exactly one definition.

use crate::models::{
    AsPath, AsPathSegment, Asn, BgpElem, Community, ElemType, MetaCommunity, NetworkPrefix,
};
use std::fmt::{Display, Write as _};
use std::net::IpAddr;

/// Append one PSV row, without a trailing newline.
pub fn write_elem(elem: &BgpElem, out: &mut String) {
    out.push_str(match elem.elem_type {
        ElemType::ANNOUNCE => "A",
        ElemType::WITHDRAW => "W",
    });
    out.push('|');
    push_timestamp(out, elem.timestamp);
    out.push('|');
    push_ip(out, elem.peer_ip);
    out.push('|');
    push_u32(out, u32::from(elem.peer_asn));
    out.push('|');
    push_prefix(out, &elem.prefix);
    out.push('|');
    if let Some(path) = &elem.as_path {
        push_as_path(out, path);
    }
    out.push('|');
    push_asns(out, elem.origin_asns.as_deref());
    out.push('|');
    push_opt_display(out, elem.origin.as_ref());
    out.push('|');
    if let Some(next_hop) = elem.next_hop {
        push_ip(out, next_hop);
    }
    out.push('|');
    push_opt_u32(out, elem.local_pref);
    out.push('|');
    push_opt_u32(out, elem.med);
    out.push('|');
    push_communities(out, elem.communities.as_deref());
    out.push('|');
    out.push_str(if elem.atomic { "true" } else { "false" });
    out.push('|');
    push_opt_asn(out, elem.aggr_asn);
    out.push('|');
    if let Some(aggr_ip) = elem.aggr_ip {
        push_ip(out, IpAddr::V4(aggr_ip));
    }
    out.push('|');
    push_opt_asn(out, elem.only_to_customer);
}

/// Append a `u32` as decimal digits.
#[inline]
fn push_u32(out: &mut String, mut value: u32) {
    if value < 10 {
        out.push((b'0' + value as u8) as char);
        return;
    }
    let mut buffer = [0u8; 10];
    let mut start = buffer.len();
    while value > 0 {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    // Only ASCII digits were written.
    out.push_str(std::str::from_utf8(&buffer[start..]).unwrap_or_default());
}

#[inline]
fn push_opt_u32(out: &mut String, value: Option<u32>) {
    if let Some(value) = value {
        push_u32(out, value);
    }
}

#[inline]
fn push_opt_asn(out: &mut String, value: Option<Asn>) {
    if let Some(value) = value {
        push_u32(out, u32::from(value));
    }
}

#[inline]
fn push_opt_display<T: Display>(out: &mut String, value: Option<&T>) {
    if let Some(value) = value {
        let _ = write!(out, "{value}");
    }
}

/// Integers stay integers; fractional values keep the standard float formatting.
#[inline]
fn push_timestamp(out: &mut String, timestamp: f64) {
    if timestamp >= 0.0 && timestamp < u32::MAX as f64 && timestamp.fract() == 0.0 {
        push_u32(out, timestamp as u32);
    } else {
        let _ = write!(out, "{timestamp}");
    }
}

/// IPv4 is written digit by digit; IPv6 keeps its `Display` text.
#[inline]
fn push_ip(out: &mut String, address: IpAddr) {
    match address {
        IpAddr::V4(address) => push_ipv4(out, address),
        IpAddr::V6(_) => {
            let _ = write!(out, "{address}");
        }
    }
}

#[inline]
fn push_ipv4(out: &mut String, address: std::net::Ipv4Addr) {
    let octets = address.octets();
    push_u32(out, octets[0] as u32);
    for octet in &octets[1..] {
        out.push('.');
        push_u32(out, *octet as u32);
    }
}

/// `network/mask`, matching `NetworkPrefix`'s `Display`.
#[inline]
fn push_prefix(out: &mut String, prefix: &NetworkPrefix) {
    match prefix.prefix {
        ipnet::IpNet::V4(network) => {
            push_ipv4(out, network.addr());
            out.push('/');
            push_u32(out, network.prefix_len() as u32);
        }
        ipnet::IpNet::V6(_) => {
            let _ = write!(out, "{}", prefix.prefix);
        }
    }
}

/// Mirror of `AsPath`'s `Display`: segments separated by a space, sets in braces.
fn push_as_path(out: &mut String, path: &AsPath) {
    for (index, segment) in path.iter_segments().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        match segment {
            AsPathSegment::AsSequence(values) | AsPathSegment::ConfedSequence(values) => {
                let mut asns = values.iter();
                if let Some(first) = asns.next() {
                    push_u32(out, u32::from(*first));
                    for asn in asns {
                        out.push(' ');
                        push_u32(out, u32::from(*asn));
                    }
                }
            }
            AsPathSegment::AsSet(values) | AsPathSegment::ConfedSet(values) => {
                out.push('{');
                let mut asns = values.iter();
                if let Some(first) = asns.next() {
                    push_u32(out, u32::from(*first));
                    for asn in asns {
                        out.push(',');
                        push_u32(out, u32::from(*asn));
                    }
                }
                out.push('}');
            }
        }
    }
}

/// Space-separated ASNs.
fn push_asns(out: &mut String, asns: Option<&[Asn]>) {
    let Some(asns) = asns else { return };
    for (index, asn) in asns.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        push_u32(out, u32::from(*asn));
    }
}

/// Space-separated communities. Plain and large communities are written as digits; the extended
/// forms keep their `Display` text because their sub-type wording is not repeated here.
fn push_communities(out: &mut String, communities: Option<&[MetaCommunity]>) {
    let Some(communities) = communities else {
        return;
    };
    for (index, community) in communities.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        match community {
            MetaCommunity::Plain(community) => push_plain_community(out, community),
            MetaCommunity::Large(community) => {
                push_u32(out, community.global_admin);
                out.push(':');
                push_u32(out, community.local_data[0]);
                out.push(':');
                push_u32(out, community.local_data[1]);
            }
            other => {
                let _ = write!(out, "{other}");
            }
        }
    }
}

/// Mirror of `Community`'s `Display`.
fn push_plain_community(out: &mut String, community: &Community) {
    match community {
        Community::NoExport => out.push_str("no-export"),
        Community::NoAdvertise => out.push_str("no-advertise"),
        Community::NoExportSubConfed => out.push_str("no-export-sub-confed"),
        Community::Custom(asn, value) => {
            push_u32(out, u32::from(*asn));
            out.push(':');
            push_u32(out, *value as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{LargeCommunity, NetworkPrefix, Origin};
    use std::str::FromStr;

    /// Reference implementation: the original template, every field through `Display`.
    fn reference(elem: &BgpElem) -> String {
        fn opt<T: Display>(value: &Option<T>) -> String {
            value.as_ref().map(|v| v.to_string()).unwrap_or_default()
        }
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            match elem.elem_type {
                ElemType::ANNOUNCE => "A",
                ElemType::WITHDRAW => "W",
            },
            elem.timestamp,
            elem.peer_ip,
            elem.peer_asn,
            elem.prefix,
            opt(&elem.as_path),
            elem.origin_asns
                .as_ref()
                .map(|asns| asns
                    .iter()
                    .map(|asn| asn.to_string())
                    .collect::<Vec<_>>()
                    .join(" "))
                .unwrap_or_default(),
            opt(&elem.origin),
            opt(&elem.next_hop),
            opt(&elem.local_pref),
            opt(&elem.med),
            elem.communities
                .as_ref()
                .map(|communities| communities
                    .iter()
                    .map(|community| community.to_string())
                    .collect::<Vec<_>>()
                    .join(" "))
                .unwrap_or_default(),
            elem.atomic,
            opt(&elem.aggr_asn),
            opt(&elem.aggr_ip),
            opt(&elem.only_to_customer),
        )
    }

    fn sample() -> Vec<BgpElem> {
        let mut elems = vec![BgpElem {
            timestamp: 1_760_000_000.0,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::from_str("23.159.16.22").expect("ip"),
            peer_asn: Asn::new_32bit(835),
            prefix: NetworkPrefix::from_str("138.99.97.0/24").expect("prefix"),
            as_path: Some(AsPath::from_sequence([835u32, 3257, 28657])),
            origin_asns: Some(vec![Asn::new_32bit(28657)]),
            origin: Some(Origin::IGP),
            next_hop: Some(IpAddr::from_str("23.159.16.22").expect("ip")),
            local_pref: Some(0),
            med: Some(0),
            communities: Some(vec![
                MetaCommunity::Plain(Community::Custom(Asn::new_16bit(835), 10005)),
                MetaCommunity::Large(LargeCommunity {
                    global_admin: 3257,
                    local_data: [30627, 51300],
                }),
            ]),
            atomic: false,
            ..BgpElem::default()
        }];
        elems.push(BgpElem {
            timestamp: 1_760_000_001.5,
            elem_type: ElemType::WITHDRAW,
            peer_ip: IpAddr::from_str("2001:db8::1").expect("ip"),
            peer_asn: Asn::new_32bit(64512),
            prefix: NetworkPrefix::from_str("2001:db8:1::/48").expect("prefix"),
            origin: Some(Origin::INCOMPLETE),
            atomic: true,
            aggr_asn: Some(Asn::new_32bit(64512)),
            aggr_ip: Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            only_to_customer: Some(Asn::new_32bit(64513)),
            ..BgpElem::default()
        });
        elems
    }

    #[test]
    fn matches_display_reference() {
        for elem in sample() {
            let mut rendered = String::new();
            write_elem(&elem, &mut rendered);
            assert_eq!(rendered, reference(&elem));
        }
    }

    #[test]
    fn as_path_sets_use_braces() {
        let elem = BgpElem {
            as_path: Some(AsPath::from_segments(vec![AsPathSegment::AsSet(
                vec![Asn::new_32bit(1), Asn::new_32bit(2)].into(),
            )])),
            ..BgpElem::default()
        };
        let mut rendered = String::new();
        write_elem(&elem, &mut rendered);
        assert!(rendered.contains("|{1,2}|"), "rendered: {rendered}");
    }
}
