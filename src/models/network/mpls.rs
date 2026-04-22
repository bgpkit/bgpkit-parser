//! MPLS Labeled NLRI support - RFC 3107 and RFC 8277
//!
//! This module provides support for parsing and encoding MPLS-labeled BGP NLRI
//! as specified in RFC 3107 (Carrying Label Information in BGP-4) and its
//! successor RFC 8277 (Using BGP to Bind MPLS Labels to Address Prefixes).
//!
//! ## RFC 8277 Modes
//!
//! RFC 8277 defines two distinct NLRI encoding modes:
//!
//! - **SingleLabel** (§2.2): Used when Multiple Labels Capability is not negotiated.
//!   Exactly one label is encoded, and the S (Bottom-of-Stack) bit MUST be ignored
//!   on reception.
//!
//! - **MultiLabel** (§2.3): Used when Multiple Labels Capability (Code 8) is negotiated.
//!   Multiple labels can be encoded with the BoS bit delimiting the stack.

use crate::models::network::{Afi, NetworkPrefix};
#[cfg(feature = "parser")]
use bytes::{Buf, Bytes};
use ipnet::IpNet;
use smallvec::SmallVec;
use std::fmt::{Debug, Formatter};

/// MPLS Label value (20-bit, 0-1,048,575)
#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct MplsLabel(u32);

impl MplsLabel {
    /// Maximum valid label value (20-bit mask)
    pub const MAX_VALUE: u32 = 0x000F_FFFF;

    /// IPv4 Explicit NULL label (RFC 3032)
    pub const IPV4_EXPLICIT_NULL: u32 = 0;
    /// IPv6 Explicit NULL label (RFC 3032)
    pub const IPV6_EXPLICIT_NULL: u32 = 2;
    /// Implicit NULL label (RFC 3032)
    pub const IMPLICIT_NULL: u32 = 3;

    /// Create a new MplsLabel with validation.
    /// Returns Err if value exceeds 20-bit range.
    pub fn try_new(value: u32) -> Result<Self, MplsLabelError> {
        if value > Self::MAX_VALUE {
            return Err(MplsLabelError::LabelValueTooLarge(value));
        }
        Ok(Self(value))
    }

    /// Create a new MplsLabel from a value that is already known to be valid.
    /// Used internally when decoding from wire format.
    pub(crate) fn new_masked(value: u32) -> Self {
        Self(value & Self::MAX_VALUE)
    }

    /// Get the label value (0..=0xFFFFF)
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Check if label is in reserved range (0-15 per RFC 3032)
    pub fn is_reserved(&self) -> bool {
        self.0 <= 15
    }

    /// Check if label is Implicit NULL (value 3)
    pub fn is_implicit_null(&self) -> bool {
        self.0 == Self::IMPLICIT_NULL
    }

    /// Check if label is IPv4 Explicit NULL (value 0)
    pub fn is_ipv4_explicit_null(&self) -> bool {
        self.0 == Self::IPV4_EXPLICIT_NULL
    }

    /// Check if label is IPv6 Explicit NULL (value 2)
    pub fn is_ipv6_explicit_null(&self) -> bool {
        self.0 == Self::IPV6_EXPLICIT_NULL
    }

    /// Encode label to 3-byte wire format per RFC 3032.
    ///
    /// Wire format: bits 23-4 = label value, bits 3-1 = reserved (0), bit 0 = Bottom-of-Stack
    pub fn encode(&self, is_bottom: bool) -> [u8; 3] {
        let raw = (self.0 << 4) | (if is_bottom { 1 } else { 0 });
        [(raw >> 16) as u8, (raw >> 8) as u8, raw as u8]
    }

    /// Decode label from 3-byte wire format per RFC 3032.
    ///
    /// Returns (label, bottom_of_stack_flag).
    /// Note: Reserved bits (3-1) are ignored.
    pub fn decode(bytes: [u8; 3]) -> (Self, bool) {
        let raw = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        let label_value = raw >> 4;
        let bos = (raw & 0x01) != 0;
        (Self::new_masked(label_value), bos)
    }
}

impl Debug for MplsLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MplsLabel({})", self.0)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MplsLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MplsLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// Error type for MplsLabel construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MplsLabelError {
    LabelValueTooLarge(u32),
}

impl std::fmt::Display for MplsLabelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MplsLabelError::LabelValueTooLarge(v) => {
                write!(
                    f,
                    "MPLS label value {} exceeds maximum 0x{:X}",
                    v,
                    MplsLabel::MAX_VALUE
                )
            }
        }
    }
}

impl std::error::Error for MplsLabelError {}

/// RFC 8277 parsing mode for labeled NLRI
///
/// RFC 8277 defines two distinct encoding modes that are NOT compatible on the wire:
///
/// - **SingleLabel** (§2.2): No Multiple Labels Capability negotiated. Exactly one label,
///   S-bit MUST be ignored on reception.
///
/// - **MultiLabel** (§2.3): Multiple Labels Capability negotiated. Multiple labels allowed,
///   use BoS bit to delimit stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LabeledNlriMode {
    /// RFC 8277 §2.2: Single-label encoding (no Multiple Labels Capability negotiated).
    /// In this mode, exactly one label is expected and the S-bit is ignored.
    /// Note: Using this mode with multi-label data will result in parse errors.
    SingleLabel,
    /// RFC 8277 §2.3: Multi-label encoding (Multiple Labels Capability negotiated).
    /// This is the default as it correctly handles both single-label and multi-label prefixes.
    #[default]
    MultiLabel,
}

/// Configuration for parsing labeled NLRI
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LabeledNlriConfig {
    /// ADD-PATH enabled (RFC 7911). When true, parse 4-byte path_id before each NLRI.
    ///
    /// **CRITICAL**: ADD-PATH cannot be autodetected from NLRI bytes alone. If ADD-PATH
    /// is present on wire but this is false, the path_id bytes will be misinterpreted
    /// as NLRI length, causing complete stream desynchronization. The caller MUST
    /// configure this correctly based on session state.
    pub add_path: bool,

    /// RFC 8277 parsing mode (§2.2 SingleLabel vs §2.3 MultiLabel)
    pub mode: LabeledNlriMode,

    /// Maximum label stack depth for DoS protection.
    /// RFC 8277 allows up to 254 (255 means unlimited).
    /// Range: 1..=254
    pub max_labels: u8,

    /// Peer-negotiated maximum labels from Multiple Labels Capability.
    /// If set and `mode` is MultiLabel, enforce this limit per RFC 8277 §2.1.
    /// Receiving more labels than advertised produces a treat-as-withdraw error.
    /// None means no peer limit (use local `max_labels` only).
    pub peer_max_labels: Option<u8>,
}

impl LabeledNlriConfig {
    /// Create a new config with validation.
    /// Returns Err if max_labels is 0 or >254, or if peer_max_labels is Some(0).
    /// Note: per RFC 8277 §2.1, peer_max_labels of 1 is accepted (only 0 is forbidden).
    pub fn try_new(
        add_path: bool,
        mode: LabeledNlriMode,
        max_labels: u8,
        peer_max_labels: Option<u8>,
    ) -> Result<Self, LabeledNlriConfigError> {
        if max_labels == 0 || max_labels > 254 {
            return Err(LabeledNlriConfigError::InvalidMaxLabels(max_labels));
        }
        if let Some(peer) = peer_max_labels {
            if peer == 0 {
                return Err(LabeledNlriConfigError::InvalidPeerMaxLabels(peer));
            }
        }
        Ok(Self {
            add_path,
            mode,
            max_labels,
            peer_max_labels,
        })
    }
}

impl Default for LabeledNlriConfig {
    fn default() -> Self {
        Self {
            add_path: false,
            mode: LabeledNlriMode::default(),
            max_labels: 16,
            peer_max_labels: None,
        }
    }
}

/// Error type for LabeledNlriConfig construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabeledNlriConfigError {
    InvalidMaxLabels(u8),
    InvalidPeerMaxLabels(u8),
}

impl std::fmt::Display for LabeledNlriConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LabeledNlriConfigError::InvalidMaxLabels(v) => {
                write!(f, "max_labels {} is invalid, must be 1-254", v)
            }
            LabeledNlriConfigError::InvalidPeerMaxLabels(v) => {
                write!(f, "peer_max_labels {} is invalid, must be 2-254 or None", v)
            }
        }
    }
}

impl std::error::Error for LabeledNlriConfigError {}

/// A network prefix with MPLS labels (RFC 3107/8277)
#[derive(Debug, PartialEq, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LabeledNetworkPrefix {
    /// The IP prefix (IPv4 or IPv6)
    pub prefix: IpNet,
    /// MPLS label stack, ordered from top to bottom
    /// Uses SmallVec to avoid heap allocations for the common 1-2 label case
    pub labels: SmallVec<[MplsLabel; 2]>,
    /// ADD-PATH path identifier (RFC 7911)
    pub path_id: Option<u32>,
}

/// Error type for LabeledNetworkPrefix construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabeledNetworkPrefixError {
    EmptyLabelStack,
    PrefixLengthOverflow { total_bits: usize, max: usize },
}

impl std::fmt::Display for LabeledNetworkPrefixError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LabeledNetworkPrefixError::EmptyLabelStack => {
                write!(f, "labeled prefix must have at least one label")
            }
            LabeledNetworkPrefixError::PrefixLengthOverflow { total_bits, max } => {
                write!(
                    f,
                    "total NLRI length {} bits exceeds maximum {} bits",
                    total_bits, max
                )
            }
        }
    }
}

impl std::error::Error for LabeledNetworkPrefixError {}

impl LabeledNetworkPrefix {
    /// Create a new labeled prefix with validation.
    /// Returns Err if labels is empty or if total length exceeds 255 bits.
    pub fn try_new(
        prefix: IpNet,
        labels: SmallVec<[MplsLabel; 2]>,
        path_id: Option<u32>,
    ) -> Result<Self, LabeledNetworkPrefixError> {
        if labels.is_empty() {
            return Err(LabeledNetworkPrefixError::EmptyLabelStack);
        }

        // Validate total length fits in u8 (0-255 bits per RFC 4760)
        // Using checked arithmetic to prevent overflow
        let label_bits = labels.len().checked_mul(24).ok_or(
            LabeledNetworkPrefixError::PrefixLengthOverflow {
                total_bits: usize::MAX,
                max: 255,
            },
        )?;
        let prefix_bits = prefix.prefix_len() as usize;
        let total_bits = label_bits.checked_add(prefix_bits).ok_or(
            LabeledNetworkPrefixError::PrefixLengthOverflow {
                total_bits: usize::MAX,
                max: 255,
            },
        )?;

        if total_bits > 255 {
            return Err(LabeledNetworkPrefixError::PrefixLengthOverflow {
                total_bits,
                max: 255,
            });
        }

        Ok(Self {
            prefix,
            labels,
            path_id,
        })
    }

    /// Get the top label (first in the stack)
    pub fn top_label(&self) -> Option<&MplsLabel> {
        self.labels.first()
    }

    /// Get the bottom label (last in the stack)
    pub fn bottom_label(&self) -> Option<&MplsLabel> {
        self.labels.last()
    }

    /// Check if the prefix has multiple labels
    pub fn has_multiple_labels(&self) -> bool {
        self.labels.len() > 1
    }

    /// Get the number of labels
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }
}

/// Error type for labeled NLRI encoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabeledNlriEncodeError {
    EmptyLabelStack,
    TotalBitsOverflow {
        total_bits: usize,
        max: usize,
    },
    SingleLabelModeWithMultipleLabels {
        label_count: usize,
    },
    LabelCountExceedsPeerLimit {
        actual: usize,
        peer_max: u8,
    },
    /// ADD-PATH capability was not negotiated but path_id is present
    AddPathNotNegotiated,
}

impl std::fmt::Display for LabeledNlriEncodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LabeledNlriEncodeError::EmptyLabelStack => {
                write!(f, "cannot encode labeled prefix with empty label stack")
            }
            LabeledNlriEncodeError::TotalBitsOverflow { total_bits, max } => {
                write!(
                    f,
                    "total NLRI length {} bits exceeds maximum {} bits",
                    total_bits, max
                )
            }
            LabeledNlriEncodeError::SingleLabelModeWithMultipleLabels { label_count } => {
                write!(f, "single-label mode cannot encode {} labels", label_count)
            }
            LabeledNlriEncodeError::LabelCountExceedsPeerLimit { actual, peer_max } => {
                write!(f, "label count {} exceeds peer limit {}", actual, peer_max)
            }
            LabeledNlriEncodeError::AddPathNotNegotiated => {
                write!(f, "ADD-PATH not negotiated but path_id is present")
            }
        }
    }
}

impl std::error::Error for LabeledNlriEncodeError {}

#[cfg(feature = "parser")]
/// Parse labeled NLRI from MP_REACH_NLRI (announcements) per RFC 8277.
///
/// This function handles both §2.2 SingleLabel mode (ignore S-bit) and
/// §2.3 MultiLabel mode (use BoS bit to delimit stack).
pub fn parse_labeled_nlri(
    input: &mut Bytes,
    afi: Afi,
    config: &LabeledNlriConfig,
) -> Result<Vec<LabeledNetworkPrefix>, crate::error::ParserError> {
    use crate::error::ParserError;

    let mut result = Vec::new();

    while input.has_remaining() {
        // 1. Parse path_id if ADD-PATH enabled (RFC 7911)
        let path_id = if config.add_path {
            if input.remaining() < 4 {
                return Err(ParserError::TruncatedLabeledNlri);
            }
            Some(input.get_u32())
        } else {
            None
        };

        // 2. Parse total length field (1 byte, 0-255 bits per RFC 4760)
        if input.remaining() < 1 {
            return Err(ParserError::TruncatedLabeledNlri);
        }
        let total_bits = input.get_u8() as usize;

        // Validation: total_bits must be at least 24 (minimum for one label)
        if total_bits < 24 {
            return Err(ParserError::InvalidLabeledNlriLength);
        }

        // 3. CRITICAL: Calculate NLRI byte boundary and slice the buffer
        // This prevents reading beyond the declared NLRI into the next one
        let nlri_bytes = total_bits.div_ceil(8);
        if input.remaining() < nlri_bytes {
            return Err(ParserError::TruncatedLabeledNlri);
        }

        // Create a bounded view of just this NLRI's bytes
        let nlri_data = input.copy_to_bytes(nlri_bytes);
        let mut nlri_input = nlri_data;

        // 4. Parse labels based on mode
        let mut labels: SmallVec<[MplsLabel; 2]> = SmallVec::new();

        match config.mode {
            LabeledNlriMode::SingleLabel => {
                // RFC 8277 §2.2: Exactly one label, S-bit MUST be ignored
                if nlri_input.remaining() < 3 {
                    return Err(ParserError::TruncatedLabeledNlri);
                }
                let label_bytes = [
                    nlri_input.get_u8(),
                    nlri_input.get_u8(),
                    nlri_input.get_u8(),
                ];
                // Decode to get label value, but IGNORE the BoS bit per §2.2
                let (label, _bos) = MplsLabel::decode(label_bytes);
                labels.push(label);
            }

            LabeledNlriMode::MultiLabel => {
                // RFC 8277 §2.3: Read labels until BoS=1
                loop {
                    // DoS protection: enforce max label stack depth
                    if labels.len() >= config.max_labels as usize {
                        return Err(ParserError::MaxLabelStackDepthExceeded);
                    }

                    // Check peer limit if configured
                    if let Some(peer_max) = config.peer_max_labels {
                        if labels.len() >= peer_max as usize {
                            return Err(ParserError::PeerMaxLabelsExceeded);
                        }
                    }

                    if nlri_input.remaining() < 3 {
                        return Err(ParserError::TruncatedLabeledNlri);
                    }

                    let label_bytes = [
                        nlri_input.get_u8(),
                        nlri_input.get_u8(),
                        nlri_input.get_u8(),
                    ];
                    let (label, bos) = MplsLabel::decode(label_bytes);
                    labels.push(label);

                    if bos {
                        break;
                    }
                }
            }
        }

        // 5. Calculate and validate prefix length
        let label_bits = labels
            .len()
            .checked_mul(24)
            .ok_or(ParserError::InvalidLabeledNlriLength)?;

        // Use checked_sub to prevent integer underflow
        let prefix_bits = total_bits
            .checked_sub(label_bits)
            .ok_or(ParserError::InvalidLabeledNlriLength)?;

        // Validate prefix_bits against AFI-specific maximums
        let max_prefix_bits = match afi {
            Afi::Ipv4 => 32,
            Afi::Ipv6 => 128,
            _ => return Err(ParserError::InvalidLabeledNlriLength),
        };

        if prefix_bits > max_prefix_bits {
            return Err(ParserError::InvalidLabeledNlriLength);
        }

        // 6. Parse prefix bytes from bounded buffer
        let prefix_bytes = prefix_bits.div_ceil(8);

        if nlri_input.remaining() < prefix_bytes {
            return Err(ParserError::TruncatedPrefix);
        }

        let prefix_data = nlri_input.copy_to_bytes(prefix_bytes);
        let prefix = parse_prefix_with_masking(afi, &prefix_data, prefix_bits as u8)?;

        // 7. Verify all NLRI bytes were consumed (sanity check)
        if nlri_input.has_remaining() {
            return Err(ParserError::InvalidLabeledNlriLength);
        }

        // 8. Create result
        result.push(LabeledNetworkPrefix {
            prefix,
            labels,
            path_id,
        });
    }

    Ok(result)
}

#[cfg(feature = "parser")]
/// Parse prefix with trailing bit masking per RFC 4760.
///
/// Uses stack-allocated arrays to avoid heap allocations on the hot path.
fn parse_prefix_with_masking(
    afi: Afi,
    data: &[u8],
    prefix_bits: u8,
) -> Result<IpNet, crate::error::ParserError> {
    use crate::error::ParserError;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let full_bytes = (prefix_bits as usize) / 8;
    let remainder_bits = prefix_bits % 8;

    match afi {
        Afi::Ipv4 => {
            let mut octets = [0u8; 4];
            let copy_len = data.len().min(4);
            octets[..copy_len].copy_from_slice(&data[..copy_len]);

            // Mask trailing bits in the last partial byte
            if remainder_bits > 0 && copy_len > full_bytes {
                let mask = 0xFF << (8 - remainder_bits);
                octets[full_bytes] &= mask;
            }

            let addr = Ipv4Addr::from(octets);
            Ok(IpNet::V4(
                ipnet::Ipv4Net::new(addr, prefix_bits).map_err(|_| ParserError::InvalidPrefix)?,
            ))
        }
        Afi::Ipv6 => {
            let mut octets = [0u8; 16];
            let copy_len = data.len().min(16);
            octets[..copy_len].copy_from_slice(&data[..copy_len]);

            // Mask trailing bits in the last partial byte
            if remainder_bits > 0 && copy_len > full_bytes {
                let mask = 0xFF << (8 - remainder_bits);
                octets[full_bytes] &= mask;
            }

            let addr = Ipv6Addr::from(octets);
            Ok(IpNet::V6(
                ipnet::Ipv6Net::new(addr, prefix_bits).map_err(|_| ParserError::InvalidPrefix)?,
            ))
        }
        _ => Err(ParserError::InvalidLabeledNlriLength),
    }
}

#[cfg(feature = "parser")]
/// Parse labeled withdrawal NLRI from MP_UNREACH_NLRI per RFC 8277 §2.4.
///
/// Withdrawals for SAFI 4 are parsed into standard `NetworkPrefix` (not `LabeledNetworkPrefix`)
/// because RFC 8277 withdrawals carry no label semantics - the 3-byte compatibility field is opaque.
pub fn parse_labeled_withdrawal_nlri(
    input: &mut Bytes,
    afi: Afi,
    config: &LabeledNlriConfig,
) -> Result<Vec<NetworkPrefix>, crate::error::ParserError> {
    use crate::error::ParserError;

    let mut result = Vec::new();

    // Handle empty MP_UNREACH_NLRI (End-of-RIB marker)
    if !input.has_remaining() {
        return Ok(result);
    }

    while input.has_remaining() {
        // 1. Parse path_id if ADD-PATH enabled (RFC 7911)
        let path_id = if config.add_path {
            if input.remaining() < 4 {
                return Err(ParserError::TruncatedLabeledNlri);
            }
            Some(input.get_u32())
        } else {
            None
        };

        // 2. Parse total length field
        if input.remaining() < 1 {
            return Err(ParserError::TruncatedLabeledNlri);
        }
        let total_bits = input.get_u8() as usize;

        // Validation: RFC 8277 §2.4 requires the 3-byte compatibility field
        if total_bits < 24 {
            return Err(ParserError::InvalidLabeledNlriLength);
        }

        // 3. CRITICAL: Calculate and bound NLRI bytes
        let nlri_bytes = total_bits.div_ceil(8);
        if input.remaining() < nlri_bytes {
            return Err(ParserError::TruncatedLabeledNlri);
        }

        let nlri_data = input.copy_to_bytes(nlri_bytes);
        let mut nlri_input = nlri_data;

        // 4. Skip 3-byte compatibility field (opaque, NOT a label)
        // Per RFC 8277 §2.4: "MUST be ignored on reception"
        if nlri_input.remaining() < 3 {
            return Err(ParserError::TruncatedLabeledNlri);
        }
        let _compatibility_field = [
            nlri_input.get_u8(),
            nlri_input.get_u8(),
            nlri_input.get_u8(),
        ];

        // 5. Calculate prefix length using checked arithmetic
        let prefix_bits = total_bits
            .checked_sub(24) // 24 bits for the compatibility field
            .ok_or(ParserError::InvalidLabeledNlriLength)?;

        // Validate prefix_bits against AFI-specific maximums
        let max_prefix_bits = match afi {
            Afi::Ipv4 => 32,
            Afi::Ipv6 => 128,
            _ => return Err(ParserError::InvalidLabeledNlriLength),
        };

        if prefix_bits > max_prefix_bits {
            return Err(ParserError::InvalidLabeledNlriLength);
        }

        // 6. Parse prefix bytes from bounded buffer
        let prefix_bytes = prefix_bits.div_ceil(8);

        if nlri_input.remaining() < prefix_bytes {
            return Err(ParserError::TruncatedPrefix);
        }

        let prefix_data = nlri_input.copy_to_bytes(prefix_bytes);
        let prefix = parse_prefix_with_masking(afi, &prefix_data, prefix_bits as u8)?;

        // Verify all NLRI bytes were consumed
        if nlri_input.has_remaining() {
            return Err(ParserError::InvalidLabeledNlriLength);
        }

        // 7. Create result as plain NetworkPrefix (withdrawals have no label semantics)
        result.push(NetworkPrefix::new(prefix, path_id));
    }

    Ok(result)
}

/// Encode a labeled prefix for MP_REACH_NLRI per RFC 8277.
///
/// This function respects the encoding mode:
/// - SingleLabel mode: Exactly one label, BoS=1
/// - MultiLabel mode: All labels with proper BoS bits
///
/// # Arguments
///
/// * `prefix` - The labeled prefix to encode
/// * `mode` - The RFC 8277 encoding mode (SingleLabel or MultiLabel)
/// * `add_path` - Whether ADD-PATH capability was negotiated (required for path_id encoding)
/// * `peer_max_labels` - Optional peer-negotiated maximum labels
///
/// # Errors
///
/// Returns error if:
/// - Label stack is empty
/// - Total NLRI length exceeds 255 bits
/// - SingleLabel mode with multiple labels
/// - ADD-PATH not negotiated but path_id is present
/// - Label count exceeds peer_max_labels
pub fn encode_labeled_prefix(
    prefix: &LabeledNetworkPrefix,
    mode: LabeledNlriMode,
    add_path: bool,
    peer_max_labels: Option<u8>,
) -> Result<Vec<u8>, LabeledNlriEncodeError> {
    // 1. Validate non-empty label stack
    if prefix.labels.is_empty() {
        return Err(LabeledNlriEncodeError::EmptyLabelStack);
    }

    // Check ADD-PATH capability before encoding path_id
    if prefix.path_id.is_some() && !add_path {
        return Err(LabeledNlriEncodeError::AddPathNotNegotiated);
    }

    let mut output = Vec::new();

    // 2. Write path_id if present (only when ADD-PATH is negotiated)
    if let Some(path_id) = prefix.path_id {
        output.extend_from_slice(&path_id.to_be_bytes());
    }

    // 3. Calculate total length in bits using checked arithmetic
    let label_bits =
        prefix
            .labels
            .len()
            .checked_mul(24)
            .ok_or(LabeledNlriEncodeError::TotalBitsOverflow {
                total_bits: usize::MAX,
                max: 255,
            })?;
    let prefix_bits = prefix.prefix.prefix_len() as usize;
    let total_bits =
        label_bits
            .checked_add(prefix_bits)
            .ok_or(LabeledNlriEncodeError::TotalBitsOverflow {
                total_bits: usize::MAX,
                max: 255,
            })?;

    // Validate: total_bits must fit in u8 (0-255) per RFC 4760
    if total_bits > 255 {
        return Err(LabeledNlriEncodeError::TotalBitsOverflow {
            total_bits,
            max: 255,
        });
    }

    output.push(total_bits as u8);

    // 4. Encode labels based on mode
    match mode {
        LabeledNlriMode::SingleLabel => {
            // RFC 8277 §2.2: Exactly one label, BoS bit SHOULD be 1
            if prefix.labels.len() > 1 {
                return Err(LabeledNlriEncodeError::SingleLabelModeWithMultipleLabels {
                    label_count: prefix.labels.len(),
                });
            }
            let label = &prefix.labels[0];
            let encoded = label.encode(true); // BoS=1
            output.extend_from_slice(&encoded);
        }

        LabeledNlriMode::MultiLabel => {
            // RFC 8277 §2.3: Encode all labels with proper BoS bits
            // Check peer limit if configured
            if let Some(peer_max) = peer_max_labels {
                if prefix.labels.len() > peer_max as usize {
                    return Err(LabeledNlriEncodeError::LabelCountExceedsPeerLimit {
                        actual: prefix.labels.len(),
                        peer_max,
                    });
                }
            }

            for (i, label) in prefix.labels.iter().enumerate() {
                let is_bottom = i == prefix.labels.len() - 1;
                let encoded = label.encode(is_bottom);
                output.extend_from_slice(&encoded);
            }
        }
    }

    // 5. Write prefix bytes (truncated to prefix_bits)
    let prefix_bytes = prefix_bits.div_ceil(8);
    let prefix_octets = match prefix.prefix {
        IpNet::V4(p) => p.addr().octets().to_vec(),
        IpNet::V6(p) => p.addr().octets().to_vec(),
    };
    output.extend_from_slice(&prefix_octets[..prefix_bytes]);

    Ok(output)
}

/// Encode a labeled withdrawal for MP_UNREACH_NLRI per RFC 8277 §2.4.
///
/// The 3-byte compatibility field is opaque and SHOULD be 0x800000.
pub fn encode_labeled_withdrawal(
    prefix: &NetworkPrefix,
) -> Result<Vec<u8>, LabeledNlriEncodeError> {
    let mut output = Vec::new();

    // 1. Write path_id if present (ADD-PATH, RFC 7911)
    if let Some(path_id) = prefix.path_id {
        output.extend_from_slice(&path_id.to_be_bytes());
    }

    // 2. Calculate total length in bits
    // Per RFC 8277 §2.4: 24 bits for compatibility field + prefix bits
    let prefix_bits = prefix.prefix.prefix_len() as usize;
    let total_bits =
        24usize
            .checked_add(prefix_bits)
            .ok_or(LabeledNlriEncodeError::TotalBitsOverflow {
                total_bits: prefix_bits.saturating_add(24),
                max: 255,
            })?;

    // Validate: total_bits must fit in u8 (0-255) per RFC 4760
    if total_bits > 255 {
        return Err(LabeledNlriEncodeError::TotalBitsOverflow {
            total_bits,
            max: 255,
        });
    }

    output.push(total_bits as u8);

    // 3. Write RFC 8277 compatibility field (3 opaque bytes)
    // Per RFC 8277 §2.4: SHOULD be 0x800000 on transmission
    output.extend_from_slice(&[0x80, 0x00, 0x00]);

    // 4. Write prefix bytes (truncated to prefix_bits)
    let prefix_bytes = prefix_bits.div_ceil(8);
    let prefix_octets = match prefix.prefix {
        IpNet::V4(p) => p.addr().octets().to_vec(),
        IpNet::V6(p) => p.addr().octets().to_vec(),
    };
    output.extend_from_slice(&prefix_octets[..prefix_bytes]);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_mpls_label_new() {
        let label = MplsLabel::try_new(100).unwrap();
        assert_eq!(label.value(), 100);
        assert!(!label.is_reserved());
    }

    #[test]
    fn test_mpls_label_too_large() {
        let result = MplsLabel::try_new(0x0010_0000); // 21st bit set
        assert!(result.is_err());
    }

    #[test]
    fn test_mpls_label_reserved() {
        let label = MplsLabel::try_new(0).unwrap();
        assert!(label.is_reserved());
        assert!(label.is_ipv4_explicit_null());

        let label = MplsLabel::try_new(2).unwrap();
        assert!(label.is_reserved());
        assert!(label.is_ipv6_explicit_null());

        let label = MplsLabel::try_new(3).unwrap();
        assert!(label.is_reserved());
        assert!(label.is_implicit_null());

        let label = MplsLabel::try_new(15).unwrap();
        assert!(label.is_reserved());

        let label = MplsLabel::try_new(16).unwrap();
        assert!(!label.is_reserved());
    }

    #[test]
    fn test_mpls_label_encode_decode() {
        let label = MplsLabel::try_new(24001).unwrap();

        // Encode with BoS=1
        let encoded = label.encode(true);
        assert_eq!(encoded, [0x05, 0xDC, 0x11]); // 0x5DC1 << 4 | 1

        // Decode
        let (decoded, bos) = MplsLabel::decode(encoded);
        assert_eq!(decoded.value(), 24001);
        assert!(bos);

        // Encode with BoS=0
        let encoded = label.encode(false);
        assert_eq!(encoded, [0x05, 0xDC, 0x10]); // 0x5DC1 << 4 | 0

        // Decode
        let (decoded, bos) = MplsLabel::decode(encoded);
        assert_eq!(decoded.value(), 24001);
        assert!(!bos);
    }

    #[test]
    fn test_labeled_network_prefix_new() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels = SmallVec::from_vec(vec![MplsLabel::try_new(100).unwrap()]);

        let labeled = LabeledNetworkPrefix::try_new(prefix, labels, None).unwrap();
        assert_eq!(labeled.label_count(), 1);
        assert!(!labeled.has_multiple_labels());
    }

    #[test]
    fn test_labeled_network_prefix_empty_labels() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels: SmallVec<[MplsLabel; 2]> = SmallVec::new();

        let result = LabeledNetworkPrefix::try_new(prefix, labels, None);
        assert!(matches!(
            result,
            Err(LabeledNetworkPrefixError::EmptyLabelStack)
        ));
    }

    #[test]
    fn test_labeled_nlri_config_validation() {
        // Valid config
        let config = LabeledNlriConfig::try_new(false, LabeledNlriMode::SingleLabel, 16, None);
        assert!(config.is_ok());

        // Invalid max_labels (0)
        let result = LabeledNlriConfig::try_new(false, LabeledNlriMode::SingleLabel, 0, None);
        assert!(matches!(
            result,
            Err(LabeledNlriConfigError::InvalidMaxLabels(0))
        ));

        // Invalid max_labels (255)
        let result = LabeledNlriConfig::try_new(false, LabeledNlriMode::SingleLabel, 255, None);
        assert!(matches!(
            result,
            Err(LabeledNlriConfigError::InvalidMaxLabels(255))
        ));

        // Invalid peer_max_labels (0) - only 0 is rejected per RFC 8277 §2.1
        let result = LabeledNlriConfig::try_new(false, LabeledNlriMode::MultiLabel, 16, Some(0));
        assert!(matches!(
            result,
            Err(LabeledNlriConfigError::InvalidPeerMaxLabels(0))
        ));

        // Valid peer_max_labels (1) - RFC 8277 §2.1 allows this
        let result = LabeledNlriConfig::try_new(false, LabeledNlriMode::MultiLabel, 16, Some(1));
        assert!(result.is_ok());
    }

    #[test]
    fn test_encode_labeled_prefix_single_label_mode() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels = SmallVec::from_vec(vec![MplsLabel::try_new(24001).unwrap()]);
        let labeled = LabeledNetworkPrefix::try_new(prefix, labels, None).unwrap();

        // SingleLabel mode should succeed
        let result = encode_labeled_prefix(&labeled, LabeledNlriMode::SingleLabel, false, None);
        assert!(result.is_ok());

        // Should be: total_bits (48 = 0x30), label (0x05DC11), prefix (0xC00002)
        let encoded = result.unwrap();
        assert_eq!(encoded, vec![0x30, 0x05, 0xDC, 0x11, 0xC0, 0x00, 0x02]);
    }

    #[test]
    fn test_encode_labeled_prefix_single_label_mode_multiple_labels() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels = SmallVec::from_vec(vec![
            MplsLabel::try_new(24001).unwrap(),
            MplsLabel::try_new(24002).unwrap(),
        ]);
        let labeled = LabeledNetworkPrefix::try_new(prefix, labels, None).unwrap();

        // SingleLabel mode should fail with multiple labels
        let result = encode_labeled_prefix(&labeled, LabeledNlriMode::SingleLabel, false, None);
        assert!(matches!(
            result,
            Err(LabeledNlriEncodeError::SingleLabelModeWithMultipleLabels { label_count: 2 })
        ));
    }

    #[test]
    fn test_encode_labeled_prefix_multi_label_mode() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels = SmallVec::from_vec(vec![
            MplsLabel::try_new(24001).unwrap(),
            MplsLabel::try_new(24002).unwrap(),
        ]);
        let labeled = LabeledNetworkPrefix::try_new(prefix, labels, None).unwrap();

        // MultiLabel mode should succeed
        let result = encode_labeled_prefix(&labeled, LabeledNlriMode::MultiLabel, false, None);
        assert!(result.is_ok());

        // Should be: total_bits (72 = 0x48),
        // label1 (0x05DC10 - BoS=0), label2 (0x05DC21 - BoS=1),
        // prefix (0xC00002)
        let encoded = result.unwrap();
        assert_eq!(
            encoded,
            vec![0x48, 0x05, 0xDC, 0x10, 0x05, 0xDC, 0x21, 0xC0, 0x00, 0x02]
        );
    }

    #[test]
    fn test_encode_labeled_prefix_multi_label_mode_with_path_id() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels = SmallVec::from_vec(vec![
            MplsLabel::try_new(24001).unwrap(),
            MplsLabel::try_new(24002).unwrap(),
        ]);
        let labeled = LabeledNetworkPrefix::try_new(prefix, labels, Some(123)).unwrap();

        // MultiLabel mode with ADD-PATH enabled should succeed
        let result = encode_labeled_prefix(&labeled, LabeledNlriMode::MultiLabel, true, None);
        assert!(result.is_ok());

        // Should be: path_id (0x0000007B), total_bits (72 = 0x48),
        // label1 (0x05DC10 - BoS=0), label2 (0x05DC21 - BoS=1),
        // prefix (0xC00002)
        let encoded = result.unwrap();
        assert_eq!(
            encoded,
            vec![
                0x00, 0x00, 0x00, 0x7B, 0x48, 0x05, 0xDC, 0x10, 0x05, 0xDC, 0x21, 0xC0, 0x00, 0x02
            ]
        );
    }

    #[test]
    fn test_encode_labeled_withdrawal() {
        let prefix = NetworkPrefix::new(IpNet::from_str("192.0.2.0/24").unwrap(), None);

        let result = encode_labeled_withdrawal(&prefix);
        assert!(result.is_ok());

        // Should be: total_bits (48 = 0x30), compatibility field (0x800000), prefix (0xC00002)
        let encoded = result.unwrap();
        assert_eq!(encoded, vec![0x30, 0x80, 0x00, 0x00, 0xC0, 0x00, 0x02]);
    }

    #[test]
    fn test_encode_labeled_withdrawal_with_path_id() {
        let prefix = NetworkPrefix::new(IpNet::from_str("192.0.2.0/24").unwrap(), Some(123));

        let result = encode_labeled_withdrawal(&prefix);
        assert!(result.is_ok());

        // Should be: path_id (0x0000007B), total_bits (48 = 0x30),
        // compatibility field (0x800000), prefix (0xC00002)
        let encoded = result.unwrap();
        assert_eq!(
            encoded,
            vec![0x00, 0x00, 0x00, 0x7B, 0x30, 0x80, 0x00, 0x00, 0xC0, 0x00, 0x02]
        );
    }

    #[test]
    fn test_encode_labeled_prefix_add_path_not_negotiated() {
        let prefix = IpNet::from_str("192.0.2.0/24").unwrap();
        let labels = SmallVec::from_vec(vec![MplsLabel::try_new(100).unwrap()]);
        let labeled = LabeledNetworkPrefix::try_new(prefix, labels, Some(123)).unwrap();

        // Trying to encode with path_id but add_path=false should fail
        let result = encode_labeled_prefix(&labeled, LabeledNlriMode::SingleLabel, false, None);
        assert!(matches!(
            result,
            Err(LabeledNlriEncodeError::AddPathNotNegotiated)
        ));

        // With add_path=true it should succeed
        let result = encode_labeled_prefix(&labeled, LabeledNlriMode::SingleLabel, true, None);
        assert!(result.is_ok());
    }
}
