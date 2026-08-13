//! Construct an RFC 9234 BGP OPEN and write it in a classic PCAP Ethernet frame.
//!
//! The output contains one Ethernet II / IPv4 / TCP packet carrying a BGP OPEN on TCP port 179.
//! It is a deterministic fixture, not a complete TCP or BGP session. The BGP Identifier and the
//! lower-layer addresses are documentation prefixes and locally administered MAC addresses.
//!
//! ## Generate and inspect
//!
//! ```text
//! cargo run --example bgp_open_role_pcap -- /tmp/bgp-open-role.pcap
//! tshark -r /tmp/bgp-open-role.pcap -V
//! ```
//!
//! TShark 4.4.16 decodes the generated packet as `eth:ethertype:ip:tcp:bgp`:
//!
//! ```text
//! Frame 1: 134 bytes on wire
//! Ethernet II, Src: 02:00:00:00:00:01, Dst: 02:00:00:00:00:02
//! Internet Protocol Version 4, Src: 192.0.2.10, Dst: 198.51.100.20
//! Transmission Control Protocol, Src Port: 50000, Dst Port: 179, Seq: 1, Len: 80
//! Border Gateway Protocol - OPEN Message
//!     Length: 80
//!     My AS: 65007
//!     Hold Time: 180
//!     BGP Identifier: 192.0.2.1
//!     Optional Parameters Length: 51
//!     Capability: BGP Role
//!         BGP Role: Customer (3)
//! ```

use bgpkit_parser::models::{
    Asn, AsnLength, BgpMessage, BgpOpenMessage, CapabilityValue, OptParam, ParamValue,
};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DESTINATION_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SOURCE_IP: [u8; 4] = [192, 0, 2, 10];
const DESTINATION_IP: [u8; 4] = [198, 51, 100, 20];
const SOURCE_PORT: u16 = 50_000;
const BGP_PORT: u16 = 179;

fn capability_param(capability: &[u8]) -> OptParam {
    OptParam {
        param_type: 2,
        // The OPEN parser recognizes the RFC 9234 capability below on round trip.
        // Raw capability bytes are used because capability constructors are not public API.
        param_value: ParamValue::Raw(capability.to_vec()),
    }
}

fn open_with_customer_role() -> BgpOpenMessage {
    BgpOpenMessage {
        version: 4,
        asn: Asn::new_16bit(65007),
        hold_time: 180,
        bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
        extended_length: false,
        opt_params: vec![
            capability_param(&[1, 4, 0, 1, 0, 1]),        // MP IPv4 unicast
            capability_param(&[1, 4, 0, 2, 0, 1]),        // MP IPv6 unicast
            capability_param(&[65, 4, 0, 0, 253, 239]),   // Four-octet ASN 65007
            capability_param(&[64, 6, 0, 0, 0, 1, 1, 0]), // Graceful Restart IPv4
            capability_param(&[69, 8, 0, 1, 1, 3, 0, 2, 1, 3]), // ADD-PATH IPv4 and IPv6
            capability_param(&[9, 1, 3]),                 // RFC 9234 BGP Role: Customer
        ],
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => unreachable!("chunks(2) only returns chunks of one or two octets"),
        };
        sum += u32::from(word);
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(tcp_segment: &[u8]) -> u16 {
    let tcp_length =
        u16::try_from(tcp_segment.len()).expect("TCP segment length is bounded by IPv4");
    let mut pseudo_header = Vec::with_capacity(12 + tcp_segment.len());
    pseudo_header.extend_from_slice(&SOURCE_IP);
    pseudo_header.extend_from_slice(&DESTINATION_IP);
    pseudo_header.extend_from_slice(&[0, 6]);
    pseudo_header.extend_from_slice(&tcp_length.to_be_bytes());
    pseudo_header.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo_header)
}

fn ethernet_ipv4_tcp_frame(bgp_open: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let tcp_length = 20usize
        .checked_add(bgp_open.len())
        .ok_or("TCP segment length overflow")?;
    let ip_total_length = 20usize
        .checked_add(tcp_length)
        .ok_or("IPv4 packet length overflow")?;
    let ip_total_length = u16::try_from(ip_total_length)?;

    let mut frame = Vec::with_capacity(14 + usize::from(ip_total_length));
    frame.extend_from_slice(&DESTINATION_MAC);
    frame.extend_from_slice(&SOURCE_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4

    let ip_start = frame.len();
    frame.extend_from_slice(&[
        0x45,
        0x00, // IPv4, 20-byte header, DSCP/ECN
        0x00,
        0x00, // total length, set below
        0x00,
        0x01, // identification
        0x40,
        0x00, // don't fragment
        64,
        6, // TTL, TCP protocol number
        0x00,
        0x00, // header checksum, set below
        SOURCE_IP[0],
        SOURCE_IP[1],
        SOURCE_IP[2],
        SOURCE_IP[3],
        DESTINATION_IP[0],
        DESTINATION_IP[1],
        DESTINATION_IP[2],
        DESTINATION_IP[3],
    ]);
    frame[ip_start + 2..ip_start + 4].copy_from_slice(&ip_total_length.to_be_bytes());
    let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp_start = frame.len();
    frame.extend_from_slice(&SOURCE_PORT.to_be_bytes());
    frame.extend_from_slice(&BGP_PORT.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes()); // sequence number
    frame.extend_from_slice(&0u32.to_be_bytes()); // acknowledgement number
    frame.extend_from_slice(&0x5008u16.to_be_bytes()); // 20-byte header, PSH
    frame.extend_from_slice(&u16::MAX.to_be_bytes()); // window
    frame.extend_from_slice(&[0x00, 0x00]); // checksum, set below
    frame.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    frame.extend_from_slice(bgp_open);

    let checksum = tcp_checksum(&frame[tcp_start..]);
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
    Ok(frame)
}

fn classic_pcap(frame: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let captured_length = u32::try_from(frame.len())?;
    let mut pcap = Vec::with_capacity(24 + 16 + frame.len());
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // classic-PCAP, little endian
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes()); // UTC correction
    pcap.extend_from_slice(&0u32.to_le_bytes()); // timestamp precision
    pcap.extend_from_slice(&65_535u32.to_le_bytes()); // snapshot length
    pcap.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    pcap.extend_from_slice(&0u32.to_le_bytes()); // timestamp seconds
    pcap.extend_from_slice(&0u32.to_le_bytes()); // timestamp microseconds
    pcap.extend_from_slice(&captured_length.to_le_bytes());
    pcap.extend_from_slice(&captured_length.to_le_bytes());
    pcap.extend_from_slice(frame);
    Ok(pcap)
}

fn write_pcap(path: &Path, pcap: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut output = File::create(path)?;
    output.write_all(pcap)?;
    output.flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "bgp-open-role.pcap".to_owned());
    let open = open_with_customer_role();
    let wire = BgpMessage::Open(open).encode(AsnLength::Bits32)?;

    let mut parser_input = wire.clone();
    let parsed = bgpkit_parser::parser::bgp::parse_bgp_message(
        &mut parser_input,
        false,
        &AsnLength::Bits32,
    )?;
    let BgpMessage::Open(parsed_open) = parsed else {
        return Err("encoded BGP OPEN parsed as another message type".into());
    };
    let has_role_capability = matches!(
        parsed_open.opt_params.last().map(|parameter| &parameter.param_value),
        Some(ParamValue::Capacities(capabilities))
            if matches!(capabilities.first().map(|capability| &capability.value),
                Some(CapabilityValue::BgpRole(_)))
    );
    if !has_role_capability || wire[75..] != [2, 3, 9, 1, 3] {
        return Err("BGP OPEN did not round-trip with RFC 9234 Customer role".into());
    }

    let frame = ethernet_ipv4_tcp_frame(&wire)?;
    let pcap = classic_pcap(&frame)?;
    write_pcap(Path::new(&output), &pcap)?;
    println!(
        "wrote {output}: {} bytes, BGP OPEN {} bytes",
        pcap.len(),
        wire.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_checksum_valid_ethernet_ipv4_tcp_pcap_with_customer_role(
    ) -> Result<(), Box<dyn Error>> {
        let wire = BgpMessage::Open(open_with_customer_role()).encode(AsnLength::Bits32)?;
        assert_eq!(wire.len(), 80);
        assert_eq!(&wire[16..19], &[0, 80, 1]);
        assert_eq!(&wire[75..], &[2, 3, 9, 1, 3]);

        let frame = ethernet_ipv4_tcp_frame(&wire)?;
        assert_eq!(frame.len(), 134);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(internet_checksum(&frame[14..34]), 0);
        assert_eq!(tcp_checksum(&frame[34..]), 0);
        assert_eq!(&frame[54..], wire.as_ref());

        let pcap = classic_pcap(&frame)?;
        assert_eq!(pcap.len(), 174);
        assert_eq!(&pcap[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(pcap[32..36].try_into()?), 134);
        assert_eq!(&pcap[40..], frame.as_slice());
        Ok(())
    }
}
