use super::nlri::{encode_length, parse_length};
use super::*;
use crate::models::NetworkPrefix;
use std::str::FromStr;

/// Test cases based on RFC 8955 examples
#[cfg(test)]
mod rfc_examples {
    use super::*;

    #[test]
    fn test_rfc8955_example_1() {
        // "Packets to 192.0.2.0/24 and TCP port 25"
        // Length: 0x0b
        // Destination Prefix: 01 18 c0 00 02
        // Protocol: 03 81 06
        // Port: 04 81 19

        let data = vec![
            0x0B, // Length: 11 bytes
            0x01, // Type 1: Destination Prefix
            0x18, // /24
            0xC0, 0x00, 0x02, // 192.0.2.0
            0x03, // Type 3: IP Protocol
            0x81, // end=1, and=0, len=00, eq=1
            0x06, // TCP (6)
            0x04, // Type 4: Port
            0x81, // end=1, and=0, len=00, eq=1
            0x19, // Port 25
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 3);

        // Check destination prefix
        match &nlri.components[0] {
            FlowSpecComponent::DestinationPrefix(prefix) => {
                assert_eq!(prefix.to_string(), "192.0.2.0/24");
            }
            _ => panic!("Expected destination prefix"),
        }

        // Check IP protocol
        match &nlri.components[1] {
            FlowSpecComponent::IpProtocol(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].value, 6);
                assert!(ops[0].equal);
                assert!(ops[0].end_of_list);
            }
            _ => panic!("Expected IP protocol"),
        }

        // Check port
        match &nlri.components[2] {
            FlowSpecComponent::Port(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].value, 25);
                assert!(ops[0].equal);
                assert!(ops[0].end_of_list);
            }
            _ => panic!("Expected port"),
        }

        // Test round-trip encoding
        let encoded = encode_flowspec_nlri(&nlri);
        assert_eq!(encoded, data);
    }

    #[test]
    fn test_rfc8955_example_2_partial() {
        // "Packets to 192.0.2.0/24 from 203.0.113.0/24 and port {range [137, 139] or 8080}"
        // This is a simplified version focusing on the prefix components

        let data = vec![
            0x0E, // Length: 14 bytes (corrected)
            0x01, // Type 1: Destination Prefix
            0x18, // /24
            0xC0, 0x00, 0x02, // 192.0.2.0
            0x02, // Type 2: Source Prefix
            0x18, // /24
            0xCB, 0x00, 0x71, // 203.0.113.0
            0x04, // Type 4: Port
            0x91, // end=1, and=0, len=01, eq=1
            0x1F, 0x90, // Port 8080
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 3);

        // Check destination prefix
        match &nlri.components[0] {
            FlowSpecComponent::DestinationPrefix(prefix) => {
                assert_eq!(prefix.to_string(), "192.0.2.0/24");
            }
            _ => panic!("Expected destination prefix"),
        }

        // Check source prefix
        match &nlri.components[1] {
            FlowSpecComponent::SourcePrefix(prefix) => {
                assert_eq!(prefix.to_string(), "203.0.113.0/24");
            }
            _ => panic!("Expected source prefix"),
        }

        // Check port (simplified to just 8080)
        match &nlri.components[2] {
            FlowSpecComponent::Port(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].value, 8080);
                assert!(ops[0].equal);
                assert_eq!(ops[0].value_length, 2);
            }
            _ => panic!("Expected port"),
        }
    }

    #[test]
    fn test_tcp_flags_component() {
        // TCP flags with SYN+ACK (0x12)
        let data = vec![
            0x03, // Length: 3 bytes (corrected)
            0x09, // Type 9: TCP Flags
            0x81, // end=1, and=0, len=00, not=0, match=1 (partial match)
            0x12, // SYN+ACK flags
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        match &nlri.components[0] {
            FlowSpecComponent::TcpFlags(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].bitmask, 0x12);
                assert!(ops[0].match_flag); // Partial match
                assert!(!ops[0].not);
                assert!(ops[0].end_of_list);
            }
            _ => panic!("Expected TCP flags"),
        }
    }

    #[test]
    fn test_packet_length_range() {
        // Packet length >= 1000 bytes
        let data = vec![
            0x04, // Length: 4 bytes (content after length byte)
            0x0A, // Type 10: Packet Length
            0x93, // end=1, and=0, len=01, 0, lt=0, gt=1, eq=1 (>=)
            0x03, 0xE8, // 1000 bytes
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        match &nlri.components[0] {
            FlowSpecComponent::PacketLength(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].value, 1000);
                assert!(ops[0].greater_than);
                assert!(ops[0].equal);
                assert!(!ops[0].less_than);
                assert_eq!(ops[0].value_length, 2);
            }
            _ => panic!("Expected packet length"),
        }
    }

    #[test]
    fn test_dscp_marking() {
        // DSCP value 46 (EF - Expedited Forwarding)
        let data = vec![
            0x03, // Length: 3 bytes
            0x0B, // Type 11: DSCP
            0x81, // end=1, and=0, len=00, eq=1
            0x2E, // DSCP 46 (EF)
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        match &nlri.components[0] {
            FlowSpecComponent::Dscp(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].value, 46);
                assert!(ops[0].equal);
            }
            _ => panic!("Expected DSCP"),
        }
    }

    #[test]
    fn test_fragment_component() {
        // Fragment: first fragment
        let data = vec![
            0x03, // Length: 3 bytes
            0x0C, // Type 12: Fragment
            0x81, // end=1, and=0, len=00, not=0, match=1
            0x01, // First fragment bit
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        match &nlri.components[0] {
            FlowSpecComponent::Fragment(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].bitmask, 0x01);
                assert!(ops[0].match_flag);
                assert!(!ops[0].not);
            }
            _ => panic!("Expected fragment"),
        }
    }

    #[test]
    fn test_ipv6_flow_label() {
        // IPv6 Flow Label = 0x12345 (RFC 8956)
        let data = vec![
            0x06, // Length: 6 bytes
            0x0D, // Type 13: Flow Label
            0xA1, // end=1, and=0, len=10, eq=1 (4-byte value)
            0x00, 0x01, 0x23, 0x45, // Flow Label value (20-bit in 4-byte field)
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        match &nlri.components[0] {
            FlowSpecComponent::FlowLabel(ops) => {
                assert_eq!(ops.len(), 1);
                assert_eq!(ops[0].value, 0x00012345);
                assert!(ops[0].equal);
                assert_eq!(ops[0].value_length, 4);
            }
            _ => panic!("Expected flow label"),
        }
    }

    #[test]
    fn test_complex_port_range() {
        // Port range: 80 OR 443
        let data = vec![
            0x06, // Length: 6 bytes (corrected)
            0x04, // Type 4: Port
            0x01, // end=0, and=0 (OR), len=00, eq=1
            0x50, // Port 80
            0x91, // end=1, and=0, len=01, eq=1
            0x01, 0xBB, // Port 443 (2 bytes)
        ];

        let nlri = parse_flowspec_nlri(&data).unwrap();
        assert_eq!(nlri.components.len(), 1);

        match &nlri.components[0] {
            FlowSpecComponent::Port(ops) => {
                assert_eq!(ops.len(), 2);

                // First operator: == 80, OR with next
                assert_eq!(ops[0].value, 80);
                assert!(ops[0].equal);
                assert!(!ops[0].and_with_next);
                assert!(!ops[0].end_of_list);

                // Second operator: == 443, end of list
                assert_eq!(ops[1].value, 443);
                assert!(ops[1].equal);
                assert!(!ops[1].and_with_next);
                assert!(ops[1].end_of_list);
            }
            _ => panic!("Expected port"),
        }

        // Verify the operators are correctly parsed
        if let FlowSpecComponent::Port(ops) = &nlri.components[0] {
            assert_eq!(ops.len(), 2);
            assert_eq!(ops[0].value, 80);
            assert_eq!(ops[1].value, 443);
        }
    }
}

/// Test error conditions and edge cases
#[cfg(test)]
mod error_handling {
    use super::*;

    #[test]
    fn test_insufficient_data() {
        let data = vec![0x05, 0x01]; // Claims 5 bytes but only has 2
        let result = parse_flowspec_nlri(&data);
        assert!(matches!(result, Err(FlowSpecError::InsufficientData)));
    }

    #[test]
    fn test_invalid_component_type() {
        let data = vec![
            0x03, // Length: 3 bytes
            0xFF, // Invalid component type
            0x81, 0x06, // Some data
        ];

        let result = parse_flowspec_nlri(&data);
        assert!(matches!(
            result,
            Err(FlowSpecError::InvalidComponentType(0xFF))
        ));
    }

    #[test]
    fn test_extended_length_encoding() {
        // Test length >= 240
        let mut data = Vec::new();
        encode_length(1000, &mut data);

        let mut offset = 0;
        let parsed_length = parse_length(&data, &mut offset).unwrap();
        assert_eq!(parsed_length, 1000);

        // Test maximum length (4095)
        let mut data = Vec::new();
        encode_length(4095, &mut data);

        let mut offset = 0;
        let parsed_length = parse_length(&data, &mut offset).unwrap();
        assert_eq!(parsed_length, 4095);
    }
}

/// IPv6-specific test cases from RFC 8956
#[cfg(test)]
mod ipv6_tests {
    use super::*;

    #[test]
    fn test_ipv6_destination_prefix() {
        let nlri = FlowSpecNlri::new(vec![FlowSpecComponent::DestinationPrefix(
            NetworkPrefix::from_str("2001:db8::/32").unwrap(),
        )]);

        assert!(nlri.is_ipv6());
        assert!(!nlri.is_ipv4());
    }

    #[test]
    fn test_ipv6_prefix_with_offset() {
        // Test IPv6 prefix with offset (theoretical - actual parsing would need more implementation)
        let nlri = FlowSpecNlri::new(vec![FlowSpecComponent::DestinationIpv6Prefix {
            offset: 32,
            prefix: NetworkPrefix::from_str("2001:db8::/64").unwrap(),
        }]);

        assert!(nlri.is_ipv6());

        match &nlri.components[0] {
            FlowSpecComponent::DestinationIpv6Prefix { offset, prefix } => {
                assert_eq!(*offset, 32);
                assert_eq!(prefix.to_string(), "2001:db8::/64");
            }
            _ => panic!("Expected IPv6 destination prefix with offset"),
        }
    }

    #[test]
    fn test_flow_label_component() {
        let nlri = FlowSpecNlri::new(vec![FlowSpecComponent::FlowLabel(vec![
            NumericOperator::equal_to(0x12345),
        ])]);

        assert!(nlri.is_ipv6()); // Flow label implies IPv6
        assert!(!nlri.is_ipv4());
    }
}
