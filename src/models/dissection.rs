//! Byte-level dissection types for Wireshark-style field inspection.
//!
//! A [`DissectionNode`] tree annotates every field of a BGP or MRT message
//! with its byte range (`offset`/`length`) so a frontend can highlight the
//! bytes behind any protocol field, and vice versa. Dissection is produced by
//! a separate best-effort pass ([`crate::parser::bgp::dissect`],
//! [`crate::parser::mrt::dissect`]) and is never on the default parsing hot
//! path.

use crate::error::BgpValidationWarning;

/// Byte range within a dissected buffer: `[offset, offset + length)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS), ts(export))]
pub struct Span {
    pub offset: u32,
    pub length: u32,
}

impl Span {
    pub const fn new(offset: u32, length: u32) -> Self {
        Span { offset, length }
    }
}

/// One field of a dissected message.
///
/// `field` is a stable machine-readable identifier using dotted paths, e.g.
/// `bgp.header.marker`, `bgp.update.path_attributes`, or `bgp.attr.32` (the
/// attribute type code suffix identifies which path attribute the node
/// covers). `label` is a human-readable rendering that frontends can display
/// directly. Offsets are relative to the start of the dissected buffer: for a
/// bare BGP message the message itself, and for an MRT record the whole
/// record (common header + message body).
///
/// Best-effort contract: when the input is truncated or malformed, the tree
/// simply stops at the last field that could be walked; a dissector never
/// fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS), ts(export))]
pub struct DissectionNode {
    pub field: String,
    pub label: String,
    pub offset: u32,
    pub length: u32,
    pub children: Vec<DissectionNode>,
}

impl DissectionNode {
    pub fn new(
        field: impl Into<String>,
        label: impl Into<String>,
        offset: u32,
        length: u32,
    ) -> Self {
        DissectionNode {
            field: field.into(),
            label: label.into(),
            offset,
            length,
            children: Vec::new(),
        }
    }

    /// Byte range covered by this node.
    pub const fn span(&self) -> Span {
        Span {
            offset: self.offset,
            length: self.length,
        }
    }

    /// Depth-first search for the first node with an exact `field` match.
    pub fn find(&self, field: &str) -> Option<&DissectionNode> {
        if self.field == field {
            return Some(self);
        }
        self.children.iter().find_map(|child| child.find(field))
    }

    /// Collect all nodes with an exact `field` match, in tree order.
    pub fn find_all<'a>(&'a self, field: &str, out: &mut Vec<&'a DissectionNode>) {
        if self.field == field {
            out.push(self);
        }
        for child in &self.children {
            child.find_all(field, out);
        }
    }
}

/// A validation warning anchored to the byte range it concerns.
///
/// Produced by correlating RFC 7606 warnings with a [`DissectionNode`] tree;
/// the span points at the attribute or NLRI section the warning is about, so
/// a frontend can highlight the offending bytes.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS), ts(export))]
pub struct SpannedWarning {
    pub span: Span,
    pub warning: BgpValidationWarning,
}
