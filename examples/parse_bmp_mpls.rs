//! Example: Extract MPLS-labeled NLRI from BMP Route Monitoring messages
//!
//! BMP (BGP Monitoring Protocol) is used by routers to export BGP messages to monitoring stations.
//! This example shows how to parse a BMP message containing MPLS-labeled NLRI (SAFI 4)
//! and extract the label stack information.
//!
//! MPLS-labeled NLRI is used for:
//! - MPLS VPNs (L3VPN) - labels identify customer VPNs
//! - Traffic engineering - different labels for different paths  
//! - BGP-free core - core routers only swap labels, don't run BGP
//!
//! ## Usage
//!
//! This example constructs a synthetic BMP message with MPLS-labeled NLRI, then parses it
//! to demonstrate how to access MPLS label stack information.

use bgpkit_parser::models::{
    Afi, Asn, AsnLength, Attribute, AttributeValue, BgpMessage, BgpUpdateMessage,
    LabeledNetworkPrefix, MplsLabel, Nlri, Origin, Safi,
};
use bgpkit_parser::parser::parse_bmp_msg;
use bytes::Bytes;
use std::net::IpAddr;

/// Construct a synthetic BMP Route Monitoring message with MPLS-labeled NLRI
///
/// This function creates a valid BMP message containing:
/// - BMP Common Header (version=3, type=0 Route Monitoring)
/// - BMP Per-Peer Header (peer AS 65001, peer IP 192.0.2.1)
/// - BGP UPDATE message with MP_REACH_NLRI (AFI=IPv4, SAFI=MplsLabel=4)
///   containing a labeled prefix 10.0.0.0/24 with a 2-label stack [100, 200]
fn create_bmp_mpls_message() -> Vec<u8> {
    // Create the BGP UPDATE message with MPLS-labeled NLRI

    // First, create the MPLS labels
    // Label 100 (outer) - used for traffic engineering
    let label_100 = MplsLabel::try_new(100).unwrap();
    // Label 200 (inner, Bottom-of-Stack) - used for VPN identification
    let label_200 = MplsLabel::try_new(200).unwrap();

    // Create the labeled network prefix: 10.0.0.0/24 with label stack
    let prefix_net: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
    let labeled_prefix = LabeledNetworkPrefix::try_new(
        prefix_net,
        smallvec::smallvec![label_100, label_200],
        None, // no path_id
    )
    .unwrap();

    // Create the MP_REACH_NLRI attribute with MPLS SAFI
    let nlri = Nlri::new_labeled_reachable(
        Afi::Ipv4,
        Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        vec![labeled_prefix],
    );

    // Build the attributes using From trait (automatically sets correct flags)
    let mut attributes = bgpkit_parser::models::Attributes::default();
    attributes.add_attr(Attribute::from(AttributeValue::Origin(Origin::IGP)));
    attributes.add_attr(Attribute::from(AttributeValue::from(
        bgpkit_parser::models::AsPath::from_sequence([65001]),
    )));
    attributes.add_attr(Attribute::from(AttributeValue::MpReachNlri(nlri)));

    // Debug: print attributes before encoding

    // Create the BGP UPDATE message
    let bgp_update = BgpUpdateMessage {
        withdrawn_prefixes: vec![],
        attributes,
        announced_prefixes: vec![], // MPLS prefixes are in MP_REACH_NLRI, not here
    };

    let bgp_msg = BgpMessage::Update(bgp_update);

    // Encode the BGP message
    let bgp_bytes = bgp_msg.encode(AsnLength::Bits32);

    // Now construct the BMP message
    // BMP Common Header (6 bytes) + Per-Peer Header (42 bytes) + BGP message

    let mut bmp_msg = Vec::new();

    // === BMP Common Header (6 bytes) ===
    bmp_msg.push(0x03); // Version: 3

    // Length: 6 (common header) + 42 (per-peer header) + bgp_bytes.len()
    // Note: Per-peer header is actually 42 bytes for IPv4 peer (not 48)
    // Peer Type(1) + Flags(1) + Dist(8) + Addr(16) + AS(4) + ID(4) + Timestamp(8) = 42
    let total_len = 6 + 42 + bgp_bytes.len();
    bmp_msg.extend_from_slice(&(total_len as u32).to_be_bytes());

    bmp_msg.push(0x00); // Type: 0 (Route Monitoring)

    // === BMP Per-Peer Header (42 bytes) ===
    bmp_msg.push(0x00); // Peer Type: 0 (Global Instance Peer)
    bmp_msg.push(0x00); // Peer Flags: 0x00 (IPv4 peer)

    // Peer Distinguisher: 8 bytes (0 for non-VPN)
    bmp_msg.extend_from_slice(&[0u8; 8]);

    // Peer Address: 16 bytes (IPv4 in IPv6-mapped format ::ffff:192.0.2.1)
    bmp_msg.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02,
        0x01,
    ]);

    // Peer AS: 4 bytes (65001)
    bmp_msg.extend_from_slice(&(65001u32).to_be_bytes());

    // Peer BGP ID: 4 bytes (192.0.2.1)
    bmp_msg.extend_from_slice(&[0xc0, 0x00, 0x02, 0x01]);

    // Timestamp: 8 bytes total (4 bytes seconds + 4 bytes microseconds)
    // Using timestamp 1709905408 seconds (2024-03-08) + 0 microseconds
    bmp_msg.extend_from_slice(&[0x65, 0x8f, 0x5e, 0x00]); // Seconds
    bmp_msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Microseconds

    // === BGP Message ===
    bmp_msg.extend_from_slice(&bgp_bytes);

    // Verify the length matches what we wrote in the header
    assert_eq!(bmp_msg.len(), total_len, "BMP message length mismatch!");

    bmp_msg
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BMP MPLS Route Monitoring Parser ===\n");

    // Create the synthetic BMP message
    let bmp_bytes = create_bmp_mpls_message();
    println!(
        "✓ Created synthetic BMP message ({} bytes)",
        bmp_bytes.len()
    );

    // Parse the BMP message
    let mut bytes = Bytes::from(bmp_bytes);
    let bmp_msg = parse_bmp_msg(&mut bytes)?;
    println!("✓ Parsed BMP message successfully");
    println!("  BMP Message Type: {:?}\n", bmp_msg.common_header.msg_type);

    // Extract the BGP message from BMP Route Monitoring
    use bgpkit_parser::parser::bmp::messages::BmpMessageBody;
    if let BmpMessageBody::RouteMonitoring(rm) = bmp_msg.message_body {
        println!("=== BGP UPDATE Message ===");

        // The BGP message is already parsed within the BMP message
        let bgp_msg = rm.bgp_message;

        if let BgpMessage::Update(ref update) = bgp_msg {
            println!("✓ Parsed BGP UPDATE\n");

            // Process the attributes to find MPLS NLRI
            let mut mpls_found = false;

            for attr in &update.attributes {
                match attr {
                    AttributeValue::Origin(origin) => {
                        println!("ORIGIN: {:?}", origin);
                    }
                    AttributeValue::AsPath { path, .. } => {
                        println!("AS_PATH: {}", path);
                    }
                    AttributeValue::MpReachNlri(nlri) => {
                        println!("\n=== MP_REACH_NLRI Found ===");
                        println!("  AFI: {:?}", nlri.afi);
                        println!("  SAFI: {:?} (value={})", nlri.safi, nlri.safi as u8);
                        println!("  Next Hop: {:?}", nlri.next_hop);

                        // Check if this is MPLS-labeled NLRI (SAFI = 4)
                        if nlri.safi == Safi::MplsLabel {
                            mpls_found = true;
                            println!("  → This is MPLS-labeled NLRI (SAFI=4)!");

                            // Extract labeled prefixes
                            println!(
                                "  labeled_prefixes is_some: {}",
                                nlri.labeled_prefixes.is_some()
                            );
                            if let Some(ref labeled_prefixes) = nlri.labeled_prefixes {
                                println!(
                                    "\n  Labeled Prefixes (count: {}):",
                                    labeled_prefixes.len()
                                );

                                for (i, labeled) in labeled_prefixes.iter().enumerate() {
                                    println!("\n  [{}] Prefix: {}", i + 1, labeled.prefix);
                                    println!(
                                        "       Label Stack ({} labels):",
                                        labeled.labels.len()
                                    );

                                    for (j, label) in labeled.labels.iter().enumerate() {
                                        let position = if j == 0 { "outer" } else { "inner" };
                                        let is_last = j == labeled.labels.len() - 1;
                                        let bos_marker = if is_last { "(BoS)" } else { "" };

                                        println!(
                                            "         Label {} ({}): value={} {}",
                                            j + 1,
                                            position,
                                            label.value(),
                                            bos_marker
                                        );

                                        // Check for special labels
                                        if label.is_ipv4_explicit_null() {
                                            println!("           → IPv4 Explicit Null");
                                        } else if label.is_ipv6_explicit_null() {
                                            println!("           → IPv6 Explicit Null");
                                        } else if label.is_implicit_null() {
                                            println!("           → Implicit Null (PHP)");
                                        } else if label.is_reserved() {
                                            println!("           → Reserved label range");
                                        }
                                    }

                                    // Interpret the label stack
                                    if labeled.labels.len() >= 2 {
                                        println!("\n       Interpretation:");
                                        println!("         - Outer label ({}): Traffic engineering / transport label", 
                                                 labeled.labels[0].value());
                                        println!("         - Inner label ({}): VPN identifier / service label", 
                                                 labeled.labels[1].value());
                                    }
                                }
                            } else {
                                println!("  No labeled prefixes found (this shouldn't happen for SAFI=4)");
                            }
                        } else {
                            println!("  → Regular NLRI (not MPLS)");
                            println!("  Standard prefixes: {:?}", nlri.prefixes);
                        }
                    }
                    AttributeValue::MpUnreachNlri(nlri) => {
                        println!("\n=== MP_UNREACH_NLRI (Withdrawal) ===");
                        println!("  AFI: {:?}", nlri.afi);
                        println!("  SAFI: {:?}", nlri.safi);
                        // Note: Per RFC 8277 §2.4, withdrawals carry NO labels
                        // only the prefix itself
                        println!("  Withdrawn prefixes: {:?}", nlri.prefixes);

                        if nlri.safi == Safi::MplsLabel {
                            println!("  → MPLS withdrawal (no labels per RFC 8277 §2.4)");
                        }
                    }
                    _ => {}
                }
            }

            if !mpls_found {
                println!("\n⚠ No MPLS-labeled NLRI found in this message");
            } else {
                println!("\n✓ Successfully extracted MPLS label stack information!");
            }

            // Show what the element iterator would see (MPLS stripped)
            println!("\n=== Element Iterator Output (MPLS data stripped) ===");
            let elems = bgpkit_parser::parser::mrt::mrt_elem::Elementor::bgp_to_elems(
                bgp_msg,
                0.0,
                &std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                &Asn::from(65001),
            );
            println!("  Element iterator produced {} elements", elems.len());
            println!("  Note: MPLS labels are NOT included in BgpElem iterator");
            println!("        Access them via MpReachNlri attribute directly");
        }
    } else {
        println!("⚠ Not a Route Monitoring message");
    }

    Ok(())
}
