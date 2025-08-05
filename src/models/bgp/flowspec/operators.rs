use super::FlowSpecError;

/// Numeric operator for Flow-Spec components (RFC 8955 Section 4.2.1)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NumericOperator {
    /// End-of-list flag (bit 7)
    pub end_of_list: bool,
    /// AND flag - true=AND with next, false=OR with next (bit 6)
    pub and_with_next: bool,
    /// Value length in octets (bits 5-4): 00=1, 01=2, 10=4, 11=8
    pub value_length: u8,
    /// Less-than comparison (bit 2)
    pub less_than: bool,
    /// Greater-than comparison (bit 1)
    pub greater_than: bool,
    /// Equal comparison (bit 0)
    pub equal: bool,
    /// The comparison value
    pub value: u64,
}

/// Bitmask operator for Flow-Spec components (RFC 8955 Section 4.2.2)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BitmaskOperator {
    /// End-of-list flag (bit 7)
    pub end_of_list: bool,
    /// AND flag - true=AND with next, false=OR with next (bit 6)
    pub and_with_next: bool,
    /// Value length in octets (bits 5-4): 00=1, 01=2, 10=4, 11=8
    pub value_length: u8,
    /// NOT flag - logical negation (bit 1)
    pub not: bool,
    /// Match flag - true=partial match, false=exact match (bit 0)
    pub match_flag: bool,
    /// The bitmask value
    pub bitmask: u64,
}

impl NumericOperator {
    /// Create a new numeric operator from raw byte and value
    pub fn from_byte_and_value(operator_byte: u8, value: u64) -> Result<Self, FlowSpecError> {
        let value_length = match (operator_byte >> 4) & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(FlowSpecError::InvalidOperator(operator_byte)),
        };

        // Bit 3 must be 0 for numeric operators
        if (operator_byte & 0x08) != 0 {
            return Err(FlowSpecError::InvalidOperator(operator_byte));
        }

        Ok(NumericOperator {
            end_of_list: (operator_byte & 0x80) != 0,
            and_with_next: (operator_byte & 0x40) != 0,
            value_length,
            less_than: (operator_byte & 0x04) != 0,
            greater_than: (operator_byte & 0x02) != 0,
            equal: (operator_byte & 0x01) != 0,
            value,
        })
    }

    /// Convert to byte representation
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;

        if self.end_of_list {
            byte |= 0x80;
        }
        if self.and_with_next {
            byte |= 0x40;
        }

        // Encode length
        let len_bits = match self.value_length {
            1 => 0x00,
            2 => 0x10,
            4 => 0x20,
            8 => 0x30,
            _ => 0x00, // Default to 1 byte
        };
        byte |= len_bits;

        // Bit 3 is reserved (0)

        if self.less_than {
            byte |= 0x04;
        }
        if self.greater_than {
            byte |= 0x02;
        }
        if self.equal {
            byte |= 0x01;
        }

        byte
    }

    /// Create equality operator
    pub fn equal_to(value: u64) -> Self {
        let value_length = if value <= 0xFF {
            1
        } else if value <= 0xFFFF {
            2
        } else if value <= 0xFFFFFFFF {
            4
        } else {
            8
        };

        NumericOperator {
            end_of_list: true,
            and_with_next: false,
            value_length,
            less_than: false,
            greater_than: false,
            equal: true,
            value,
        }
    }

    /// Create range operator (greater than or equal)
    pub fn greater_than_or_equal(value: u64) -> Self {
        let value_length = if value <= 0xFF {
            1
        } else if value <= 0xFFFF {
            2
        } else if value <= 0xFFFFFFFF {
            4
        } else {
            8
        };

        NumericOperator {
            end_of_list: true,
            and_with_next: false,
            value_length,
            less_than: false,
            greater_than: true,
            equal: true,
            value,
        }
    }
}

impl BitmaskOperator {
    /// Create a new bitmask operator from raw byte and value
    pub fn from_byte_and_value(operator_byte: u8, bitmask: u64) -> Result<Self, FlowSpecError> {
        let value_length = match (operator_byte >> 4) & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(FlowSpecError::InvalidOperator(operator_byte)),
        };

        // Bits 3 and 2 must be 0 for bitmask operators
        if (operator_byte & 0x0C) != 0 {
            return Err(FlowSpecError::InvalidOperator(operator_byte));
        }

        Ok(BitmaskOperator {
            end_of_list: (operator_byte & 0x80) != 0,
            and_with_next: (operator_byte & 0x40) != 0,
            value_length,
            not: (operator_byte & 0x02) != 0,
            match_flag: (operator_byte & 0x01) != 0,
            bitmask,
        })
    }

    /// Convert to byte representation
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;

        if self.end_of_list {
            byte |= 0x80;
        }
        if self.and_with_next {
            byte |= 0x40;
        }

        // Encode length
        let len_bits = match self.value_length {
            1 => 0x00,
            2 => 0x10,
            4 => 0x20,
            8 => 0x30,
            _ => 0x00, // Default to 1 byte
        };
        byte |= len_bits;

        // Bits 3 and 2 are reserved (0)

        if self.not {
            byte |= 0x02;
        }
        if self.match_flag {
            byte |= 0x01;
        }

        byte
    }

    /// Create exact match operator
    pub fn exact_match(bitmask: u64) -> Self {
        let value_length = if bitmask <= 0xFF {
            1
        } else if bitmask <= 0xFFFF {
            2
        } else if bitmask <= 0xFFFFFFFF {
            4
        } else {
            8
        };

        BitmaskOperator {
            end_of_list: true,
            and_with_next: false,
            value_length,
            not: false,
            match_flag: false,
            bitmask,
        }
    }

    /// Create partial match operator
    pub fn partial_match(bitmask: u64) -> Self {
        let value_length = if bitmask <= 0xFF {
            1
        } else if bitmask <= 0xFFFF {
            2
        } else if bitmask <= 0xFFFFFFFF {
            4
        } else {
            8
        };

        BitmaskOperator {
            end_of_list: true,
            and_with_next: false,
            value_length,
            not: false,
            match_flag: true,
            bitmask,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numeric_operator_creation() {
        let op = NumericOperator::equal_to(25);
        assert!(op.equal);
        assert!(!op.less_than);
        assert!(!op.greater_than);
        assert_eq!(op.value, 25);
        assert_eq!(op.value_length, 1);
    }

    #[test]
    fn test_numeric_operator_byte_conversion() {
        let op = NumericOperator {
            end_of_list: true,
            and_with_next: false,
            value_length: 1,
            less_than: false,
            greater_than: false,
            equal: true,
            value: 25,
        };

        let byte = op.to_byte();
        assert_eq!(byte, 0x81); // 10000001: end_of_list=1, len=00, eq=1

        let parsed_op = NumericOperator::from_byte_and_value(byte, 25).unwrap();
        assert_eq!(parsed_op.end_of_list, op.end_of_list);
        assert_eq!(parsed_op.equal, op.equal);
        assert_eq!(parsed_op.value, op.value);
    }

    #[test]
    fn test_bitmask_operator_creation() {
        let op = BitmaskOperator::exact_match(0x06); // TCP SYN+FIN flags
        assert!(!op.match_flag);
        assert!(!op.not);
        assert_eq!(op.bitmask, 0x06);
        assert_eq!(op.value_length, 1);
    }

    #[test]
    fn test_invalid_operator_byte() {
        // Bit 3 should be 0 for numeric operators
        let result = NumericOperator::from_byte_and_value(0x08, 25);
        assert!(matches!(result, Err(FlowSpecError::InvalidOperator(0x08))));

        // Bits 3 and 2 should be 0 for bitmask operators
        let result = BitmaskOperator::from_byte_and_value(0x0C, 25);
        assert!(matches!(result, Err(FlowSpecError::InvalidOperator(0x0C))));
    }
}
