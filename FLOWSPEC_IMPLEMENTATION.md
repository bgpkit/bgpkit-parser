# Flow Specification Implementation Logic

This document details all logic and bitwise operations involved in implementing Flow Specification (Flow-Spec) parsing according to RFC 8955, RFC 8956, and RFC 9117.

## 1. NLRI Encoding Format

### 1.1 Length Field Encoding

Flow-Spec NLRI starts with a length field indicating the size of the NLRI value:

```
Length < 240 octets:
  [1 octet length]

Length ≥ 240 octets (Extended Length):
  [0xF0 + high nibble][low byte]
  
  Calculation:
  - actual_length = ((first_byte & 0x0F) << 8) | second_byte
  - Maximum value: 4095 octets
```

**Implementation Logic:**
```rust
fn parse_length(data: &[u8], offset: &mut usize) -> Result<u16, Error> {
    if *offset >= data.len() {
        return Err(Error::InsufficientData);
    }
    
    let first_byte = data[*offset];
    *offset += 1;
    
    if first_byte < 240 {
        Ok(first_byte as u16)
    } else {
        if *offset >= data.len() {
            return Err(Error::InsufficientData);
        }
        let second_byte = data[*offset];
        *offset += 1;
        Ok(((first_byte & 0x0F) as u16) << 8 | second_byte as u16)
    }
}
```

### 1.2 NLRI Value Structure

After the length field, the NLRI value consists of ordered components:

```
NLRI Value = [Component 1][Component 2]...[Component N]

Component = [Type (1 octet)][Component-specific data]
```

**Ordering Rule:** Components MUST appear in increasing numerical order by type. Each type can appear at most once.

## 2. Component Types and Encoding

### 2.1 IPv4 Flow-Spec Components (RFC 8955)

| Type | Name              | Encoding                           | Operator Type |
|------|-------------------|------------------------------------|---------------|
| 1    | Destination Prefix| `<type><length><prefix>`          | N/A           |
| 2    | Source Prefix     | `<type><length><prefix>`          | N/A           |
| 3    | IP Protocol       | `<type>[numeric_op, value]+`      | Numeric       |
| 4    | Port              | `<type>[numeric_op, value]+`      | Numeric       |
| 5    | Destination Port  | `<type>[numeric_op, value]+`      | Numeric       |
| 6    | Source Port       | `<type>[numeric_op, value]+`      | Numeric       |
| 7    | ICMP Type         | `<type>[numeric_op, value]+`      | Numeric       |
| 8    | ICMP Code         | `<type>[numeric_op, value]+`      | Numeric       |
| 9    | TCP Flags         | `<type>[bitmask_op, bitmask]+`     | Bitmask       |
| 10   | Packet Length     | `<type>[numeric_op, value]+`      | Numeric       |
| 11   | DSCP              | `<type>[numeric_op, value]+`      | Numeric       |
| 12   | Fragment          | `<type>[bitmask_op, bitmask]+`     | Bitmask       |

### 2.2 IPv6 Flow-Spec Extensions (RFC 8956)

| Type | Name                | Encoding                              | Notes                    |
|------|---------------------|---------------------------------------|--------------------------|
| 1    | Destination IPv6 Prefix | `<type><length><offset><prefix>`  | Supports offset matching |
| 2    | Source IPv6 Prefix      | `<type><length><offset><prefix>`  | Supports offset matching |
| 7    | ICMPv6 Type        | `<type>[numeric_op, value]+`         | IPv6-specific            |
| 8    | ICMPv6 Code        | `<type>[numeric_op, value]+`         | IPv6-specific            |
| 13   | Flow Label         | `<type>[numeric_op, value]+`         | 20-bit IPv6 Flow Label   |

### 2.3 Prefix Encoding (Types 1 & 2)

**IPv4 Prefix:**
```
[length octet][prefix bits padded to octet boundary]

Example: 192.0.2.0/24
  Length: 24 (0x18)
  Prefix: 0xC0 0x00 0x02
```

**IPv6 Prefix with Offset:**
```
[length octet][offset octet][prefix bits][optional padding]

Example: Match bits 32-63 of 2001:db8::/64
  Length: 32 (match 32 bits)
  Offset: 32 (skip first 32 bits)  
  Prefix: 0x00 0x00 0x0D 0xB8
```

## 3. Operator Encoding and Bitwise Operations

### 3.1 Numeric Operator Format

```
 0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| e | a |  len  | 0 |lt |gt |eq |
+---+---+---+---+---+---+---+---+
```

**Bit Definitions:**
- `e` (bit 7): End-of-list flag (1 = last operator in sequence)
- `a` (bit 6): AND flag (0 = OR with next, 1 = AND with next)
- `len` (bits 5-4): Value length encoding
  - `00` = 1 octet
  - `01` = 2 octets  
  - `10` = 4 octets
  - `11` = 8 octets
- `0` (bit 3): Reserved, must be 0
- `lt` (bit 2): Less-than comparison
- `gt` (bit 1): Greater-than comparison  
- `eq` (bit 0): Equal comparison

**Comparison Logic:**
```rust
fn evaluate_numeric(operator: u8, packet_value: u64, rule_value: u64) -> bool {
    let lt = (operator & 0x04) != 0;
    let gt = (operator & 0x02) != 0;
    let eq = (operator & 0x01) != 0;
    
    match (lt, gt, eq) {
        (false, false, false) => false,           // 000: always false
        (false, false, true)  => packet_value == rule_value,  // 001: ==
        (false, true, false)  => packet_value > rule_value,   // 010: >
        (false, true, true)   => packet_value >= rule_value,  // 011: >=
        (true, false, false)  => packet_value < rule_value,   // 100: <
        (true, false, true)   => packet_value <= rule_value,  // 101: <=
        (true, true, false)   => packet_value != rule_value,  // 110: !=
        (true, true, true)    => true,            // 111: always true
    }
}
```

### 3.2 Bitmask Operator Format

```
 0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| e | a |  len  | 0 | 0 |not| m |
+---+---+---+---+---+---+---+---+
```

**Additional Bits:**
- `not` (bit 1): Logical negation (1 = negate result)
- `m` (bit 0): Match type (0 = exact match, 1 = partial match)

**Bitmask Logic:**
```rust
fn evaluate_bitmask(operator: u8, packet_value: u64, rule_mask: u64) -> bool {
    let not_flag = (operator & 0x02) != 0;
    let match_flag = (operator & 0x01) != 0;
    
    let result = if match_flag {
        // Partial match: any bits in mask must match
        (packet_value & rule_mask) != 0
    } else {
        // Exact match: all bits in mask must match exactly
        (packet_value & rule_mask) == rule_mask
    };
    
    if not_flag { !result } else { result }
}
```

### 3.3 Operator Sequence Evaluation

Components with multiple operators use logical operations:

```rust
fn evaluate_component_operators(operators: &[(u8, u64)], packet_value: u64) -> bool {
    let mut result = false;
    let mut current_and_chain = true;
    
    for (i, &(operator, rule_value)) in operators.iter().enumerate() {
        let is_end = (operator & 0x80) != 0;
        let is_and = (operator & 0x40) != 0;
        
        let match_result = if is_numeric_component {
            evaluate_numeric(operator, packet_value, rule_value)
        } else {
            evaluate_bitmask(operator, packet_value, rule_value)
        };
        
        if i == 0 {
            current_and_chain = match_result;
        } else if is_and {
            current_and_chain = current_and_chain && match_result;
        } else {
            result = result || current_and_chain;
            current_and_chain = match_result;
        }
        
        if is_end {
            result = result || current_and_chain;
            break;
        }
    }
    
    result
}
```

## 4. Traffic Action Extended Communities

### 4.1 Community Type Encoding

All Flow-Spec traffic actions use non-transitive extended communities:

**Base Type:** `0x80` (Non-transitive, two-octet AS-specific)

| Subtype | Name             | Format                    | Semantic                |
|---------|------------------|---------------------------|-------------------------|
| 0x06    | Traffic Rate     | `AS(2) + Float(4)`       | Rate limit in bytes/sec |
| 0x07    | Traffic Action   | `AS(2) + Flags(4)`       | Action flags            |
| 0x08    | RT Redirect      | `AS(2) + Target(4)`      | VRF redirect target     |
| 0x09    | Traffic Marking  | `AS(2) + DSCP(1) + 0(3)` | DSCP marking            |

### 4.2 Traffic Rate Community

```rust
struct TrafficRateAction {
    as_number: u16,
    rate_bytes_per_sec: f32,  // IEEE 754 single precision
}

// Rate of 0.0 means "discard all traffic"
// Positive rate means "limit to this rate"
```

### 4.3 Traffic Action Community

```rust
struct TrafficActionFlags {
    terminal: bool,  // Stop processing additional flow-specs
    sample: bool,    // Enable traffic sampling
    // Other bits reserved
}

impl TrafficActionFlags {
    fn from_bytes(bytes: [u8; 4]) -> Self {
        Self {
            terminal: (bytes[3] & 0x01) != 0,
            sample: (bytes[3] & 0x02) != 0,
        }
    }
}
```

## 5. Parsing Implementation Logic

### 5.1 Complete NLRI Parser

```rust
fn parse_flowspec_nlri(data: &[u8]) -> Result<FlowSpecNlri, Error> {
    let mut offset = 0;
    let length = parse_length(data, &mut offset)?;
    
    let end_offset = offset + length as usize;
    let mut components = Vec::new();
    let mut last_type = 0u8;
    
    while offset < end_offset {
        let component_type = data[offset];
        offset += 1;
        
        // Verify ordering
        if component_type <= last_type {
            return Err(Error::InvalidComponentOrder);
        }
        last_type = component_type;
        
        let component = match component_type {
            1 | 2 => parse_prefix_component(data, &mut offset, component_type)?,
            3..=8 | 10..=11 => parse_numeric_component(data, &mut offset, component_type)?,
            9 | 12 => parse_bitmask_component(data, &mut offset, component_type)?,
            13 => parse_flow_label_component(data, &mut offset)?, // IPv6 only
            _ => return Err(Error::UnknownComponentType(component_type)),
        };
        
        components.push(component);
    }
    
    Ok(FlowSpecNlri { components })
}
```

### 5.2 Component-Specific Parsers

```rust
fn parse_numeric_component(data: &[u8], offset: &mut usize, type_val: u8) -> Result<Component, Error> {
    let mut operators = Vec::new();
    
    loop {
        if *offset >= data.len() {
            return Err(Error::InsufficientData);
        }
        
        let operator = data[*offset];
        *offset += 1;
        
        let value_len = match (operator >> 4) & 0x03 {
            0 => 1,
            1 => 2, 
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };
        
        if *offset + value_len > data.len() {
            return Err(Error::InsufficientData);
        }
        
        let value = read_value(&data[*offset..*offset + value_len]);
        *offset += value_len;
        
        let is_end = (operator & 0x80) != 0;
        operators.push((operator, value));
        
        if is_end {
            break;
        }
    }
    
    Ok(Component::Numeric { type_val, operators })
}
```

## 6. Validation Rules (RFC 9117)

### 6.1 Flow-Spec Route Validation

A Flow Specification route is valid if ONE of these conditions is met:

1. **Originator Match:** The originator of the Flow-Spec route matches the originator of the best-match unicast route for the destination prefix.

2. **AS_PATH Validation:** The AS_PATH attribute is either:
   - Empty (local route), OR
   - Contains only AS_CONFED_SEQUENCE segments

### 6.2 Implementation Logic

```rust
fn validate_flowspec_route(
    flowspec_route: &FlowSpecRoute,
    unicast_rib: &UnicastRib,
) -> ValidationResult {
    // Extract destination prefix from Flow-Spec NLRI
    let dest_prefix = extract_destination_prefix(&flowspec_route.nlri)?;
    
    // Find best-match unicast route
    let best_unicast = unicast_rib.longest_prefix_match(&dest_prefix)?;
    
    // Check originator match
    if flowspec_route.originator == best_unicast.originator {
        return ValidationResult::Valid;
    }
    
    // Check AS_PATH validation
    match &flowspec_route.as_path {
        AsPath::Empty => ValidationResult::Valid,
        AsPath::Segments(segments) => {
            if segments.iter().all(|seg| matches!(seg, AsPathSegment::ConfedSequence(_))) {
                ValidationResult::Valid
            } else {
                ValidationResult::Invalid
            }
        }
    }
}
```

## 7. Data Structures

### 7.1 Core Flow-Spec Types

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpecNlri {
    pub components: Vec<FlowSpecComponent>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FlowSpecComponent {
    DestinationPrefix(NetworkPrefix),
    SourcePrefix(NetworkPrefix),
    IpProtocol(Vec<NumericOperator>),
    Port(Vec<NumericOperator>),
    DestinationPort(Vec<NumericOperator>),
    SourcePort(Vec<NumericOperator>),
    IcmpType(Vec<NumericOperator>),
    IcmpCode(Vec<NumericOperator>),
    TcpFlags(Vec<BitmaskOperator>),
    PacketLength(Vec<NumericOperator>),
    Dscp(Vec<NumericOperator>),
    Fragment(Vec<BitmaskOperator>),
    // IPv6-specific
    FlowLabel(Vec<NumericOperator>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NumericOperator {
    pub end_of_list: bool,
    pub and_with_next: bool,
    pub value_length: u8,
    pub less_than: bool,
    pub greater_than: bool,
    pub equal: bool,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitmaskOperator {
    pub end_of_list: bool,
    pub and_with_next: bool,
    pub value_length: u8,
    pub not: bool,
    pub match_flag: bool,
    pub bitmask: u64,
}
```

This implementation logic covers all aspects of Flow-Spec parsing including bitwise operations, component encoding, operator evaluation, and validation procedures as specified in the RFCs.