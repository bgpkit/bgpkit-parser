# BGP Capabilities Implementation

This document describes the comprehensive implementation of IANA-defined BGP capability codes with RFC support in bgpkit-parser.

## Overview

BGP capabilities are negotiated during the BGP OPEN message exchange to establish what features are supported between BGP speakers. The bgpkit-parser library provides full support for parsing and encoding the most commonly used BGP capabilities, with structured data types for easy programmatic access.

## Implementation Coverage

| Code | Name | RFC | Implementation Level | Details |
|------|------|-----|---------------------|---------|
| 0 | Reserved | RFC5492 | Not Applicable | Reserved value - no implementation needed |
| 1 | Multiprotocol Extensions for BGP-4 | RFC2858 | **Full** | Complete parsing/encoding with AFI/SAFI support |
| 2 | Route Refresh Capability for BGP-4 | RFC2918 | **Full** | Simple flag capability (length 0) |
| 3 | Outbound Route Filtering Capability | RFC5291 | Basic | Enum support with raw byte storage |
| 4 | Multiple routes to a destination capability | RFC8277 | Not Implemented | Deprecated per RFC specification |
| 5 | Extended Next Hop Encoding | RFC8950 | **Full** | Multi-entry capability for NLRI/NextHop combinations |
| 6 | BGP Extended Message | RFC8654 | Basic | Enum support with raw byte storage |
| 7 | BGPsec Capability | RFC8205 | Basic | Enum support with raw byte storage |
| 8 | Multiple Labels Capability | RFC8277 | Basic | Enum support with raw byte storage |
| 9 | BGP Role | RFC9234 | **Full** | Complete role-based relationship support |
| 64 | Graceful Restart Capability | RFC4724 | **Full** | Complex capability with restart flags and per-AF state |
| 65 | Support for 4-octet AS number capability | RFC6793 | **Full** | 4-byte AS number support |
| 69 | ADD-PATH Capability | RFC7911 | **Full** | Multi-entry with AFI/SAFI and send/receive modes |
| 70 | Enhanced Route Refresh Capability | RFC7313 | Basic | Enum support with raw byte storage |

## Implementation Statistics

**Total IANA BGP Capability Codes with RFC Support: 14**
- **Full Implementation:** 7 capabilities (50%)
- **Basic Implementation:** 5 capabilities (36%)
- **Not Implemented:** 2 capabilities (14% - reserved/deprecated)

## Architecture

The BGP capabilities implementation follows a structured approach with multiple layers:

### Core Components

**1. Capability Type Enumeration (`BgpCapabilityType`)**
```rust
pub enum BgpCapabilityType {
    MULTIPROTOCOL_EXTENSIONS_FOR_BGP_4 = 1,
    ROUTE_REFRESH_CAPABILITY_FOR_BGP_4 = 2,
    // ... all IANA-defined capability codes
}
```

**2. Capability Value Types (`CapabilityValue`)**
```rust
pub enum CapabilityValue {
    Raw(Vec<u8>),                                    // Fallback for basic implementation
    MultiprotocolExtensions(MultiprotocolExtensionsCapability),
    RouteRefresh(RouteRefreshCapability),
    ExtendedNextHop(ExtendedNextHopCapability),
    GracefulRestart(GracefulRestartCapability),
    FourOctetAs(FourOctetAsCapability),
    AddPath(AddPathCapability),
    BgpRole(BgpRoleCapability),
}
```

**3. Structured Capability Types**
Each fully implemented capability has its own struct with:
- Parsing methods (`parse()`) that decode from raw bytes
- Encoding methods (`encode()`) that serialize to bytes
- Validation and error handling
- Comprehensive test coverage

### File Organization

- **`src/models/bgp/capabilities.rs`** - Core capability types and parsing logic
- **`src/models/bgp/mod.rs`** - BGP message structures and CapabilityValue enum
- **`src/parser/bgp/messages.rs`** - BGP OPEN message parsing with capability handling

## Detailed Capability Implementations

### Full Implementation Capabilities

**RFC2858 - Multiprotocol Extensions**
- Supports AFI/SAFI combinations for multiprotocol routing
- 4-byte format: AFI (2 bytes) + Reserved (1 byte) + SAFI (1 byte)
- Used for IPv6, MPLS VPN, and other address families

**RFC2918 - Route Refresh**  
- Simple flag capability with no parameters (length 0)
- Enables dynamic route refresh without session restart

**RFC4724 - Graceful Restart**
- Complex capability with restart flags, timer, and per-address-family state
- Supports forwarding state preservation during BGP restarts
- Variable length based on number of supported address families

**RFC6793 - 4-octet AS Number**
- Carries the speaker's 4-byte AS number
- Fixed 4-byte format for extended AS number space

**RFC7911 - ADD-PATH**
- Multi-entry capability supporting multiple paths per prefix
- Each entry: AFI (2 bytes) + SAFI (1 byte) + Send/Receive mode (1 byte)
- Enables path diversity and improved convergence

**RFC8950 - Extended Next Hop**
- Multi-entry capability for IPv4 NLRI with IPv6 next hops
- Each entry: NLRI AFI (2 bytes) + NLRI SAFI (2 bytes) + NextHop AFI (2 bytes)
- Critical for IPv4-over-IPv6 deployments

**RFC9234 - BGP Role**
- Single-byte capability defining BGP speaker relationships
- Supports Provider, Customer, Peer, Route Server, and Route Server Client roles
- Enables automatic route leak prevention

### Basic Implementation Capabilities

Capabilities with basic implementation are recognized by the parser and stored as raw bytes:
- RFC5291 - Outbound Route Filtering
- RFC7313 - Enhanced Route Refresh  
- RFC8205 - BGPsec
- RFC8277 - Multiple Labels  
- RFC8654 - BGP Extended Message

This approach provides forward compatibility while focusing implementation effort on the most commonly used capabilities.

## Error Handling

The implementation includes robust error handling:
- **Graceful Fallback**: If structured parsing fails, capabilities fall back to raw byte storage
- **Length Validation**: All capabilities validate expected data lengths
- **Format Validation**: Values are checked against RFC specifications
- **Unknown Capabilities**: Unrecognized capability codes are stored as raw bytes

## Usage Examples

### Parsing BGP OPEN Messages
```rust
use bgpkit_parser::*;

// Parse BGP OPEN message from MRT data
let open_msg = parse_bgp_open_message(&mut data)?;

// Access capabilities
for param in &open_msg.opt_params {
    if let ParamValue::Capability(cap) = &param.param_value {
        match &cap.value {
            CapabilityValue::MultiprotocolExtensions(mp) => {
                println!("Supports {}/{}", mp.afi, mp.safi);
            }
            CapabilityValue::GracefulRestart(gr) => {
                println!("Graceful restart time: {}s", gr.restart_time);
            }
            // ... handle other capability types
            _ => {}
        }
    }
}
```

### Creating Capabilities
```rust
use bgpkit_parser::models::capabilities::*;

// Create multiprotocol extensions capability
let mp_cap = MultiprotocolExtensionsCapability::new(Afi::Ipv6, Safi::Unicast);

// Create ADD-PATH capability
let addpath_entries = vec![
    AddPathAddressFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        send_receive: AddPathSendReceive::SendReceive,
    }
];
let addpath_cap = AddPathCapability::new(addpath_entries);
```

## Testing and Validation

The implementation includes comprehensive testing:
- **26 test cases** covering all implemented capabilities
- **Round-trip testing** ensuring encode/decode consistency  
- **Error condition testing** validating proper error handling
- **RFC compliance testing** verifying format adherence
- **Edge case testing** including empty capabilities and invalid data

## Performance Considerations

- **Zero-copy parsing** where possible using `bytes::Bytes`
- **Lazy evaluation** - capabilities are only parsed when accessed
- **Minimal allocations** through efficient buffer management
- **Fallback mechanisms** prevent parsing failures from blocking message processing

## Future Enhancements

While the current implementation covers all major BGP capabilities, there are opportunities for enhancement:

### Potential Extensions

**Additional Structured Implementations**
- RFC5291 - Outbound Route Filtering could benefit from structured parsing for ORF types and filtering rules
- RFC7313 - Enhanced Route Refresh could have structured support for additional refresh types
- RFC8654 - BGP Extended Message could validate maximum message sizes

**Capability Negotiation Utilities**
- Helper functions for capability compatibility checking
- Automatic capability negotiation recommendation based on peer capabilities
- Common capability set detection between BGP speakers

**Advanced Features**
- Capability change notification system
- Capability-aware BGP session management
- Integration with BGP policy engines based on negotiated capabilities

### Contribution Guidelines

The BGP capabilities implementation follows these design principles:
- **RFC Compliance**: All implementations strictly follow RFC specifications
- **Backward Compatibility**: New features must not break existing code
- **Test Coverage**: All capabilities require comprehensive test suites
- **Documentation**: Each capability includes usage examples and RFC references
- **Performance**: Implementations should minimize memory allocations and parsing overhead

Contributors interested in extending BGP capability support should focus on:
1. Commonly used capabilities first
2. Clear structured data types that reflect RFC specifications  
3. Comprehensive error handling and validation
4. Round-trip encoding/decoding tests
5. Real-world usage examples

This implementation provides a solid foundation for BGP capability handling in the bgpkit-parser library, supporting the most critical capabilities used in modern BGP deployments while maintaining flexibility for future extensions.