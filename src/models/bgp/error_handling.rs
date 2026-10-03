//! RFC 7606 error-handling approaches and the mapping from malformed path attributes to them.
//!
//! [RFC 7606](https://datatracker.ietf.org/doc/html/rfc7606) replaces the "reset the session on
//! any UPDATE error" rule of RFC 4271 with per-attribute approaches. Later RFCs that define new
//! attributes each name the approach for their own attribute. This module collects those rules
//! in one place:
//!
//! - [`ErrorHandlingApproach`] is the action a compliant speaker takes.
//! - [`malformed_attribute_approach`] is the RFC → attribute table.
//! - [`BgpValidationWarning::error_handling_approach`] classifies one parser finding.
//! - [`Attributes::error_handling_approach`] and
//!   [`BgpUpdateMessage::error_handling_approach`] combine the findings of an UPDATE using the
//!   "strongest action wins" rule of RFC 7606 §3(h).
//!
//! # Session type
//!
//! RFC 7606 treats a malformed LOCAL_PREF, ORIGINATOR_ID or CLUSTER_LIST differently depending on
//! whether it came from an internal or an external peer. MRT data does not record the session
//! type, and route collectors such as RIPE RIS and RouteViews peer over eBGP, so this module
//! assumes **eBGP** and uses "attribute discard" for those three attributes.

use crate::error::BgpValidationWarning;
use crate::models::{Afi, AttrType, Attributes, BgpUpdateMessage, Safi};

/// The action RFC 7606 §2 prescribes for an UPDATE message error.
///
/// Variants are declared from weakest to strongest, so the derived [`Ord`] implements the
/// RFC 7606 §3(h) rule: when an UPDATE has several errors, the strongest approach applies, and
/// `max()` over the individual approaches gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS), ts(export))]
pub enum ErrorHandlingApproach {
    /// Drop the malformed attribute and keep processing the UPDATE. Only allowed for attributes
    /// that do not affect route selection or installation.
    AttributeDiscard,
    /// Treat every route the UPDATE announces as withdrawn.
    TreatAsWithdraw,
    /// Stop accepting routes of the AFI/SAFI the error concerns. A speaker may instead reset
    /// the session.
    AfiSafiDisable,
    /// Send a NOTIFICATION and reset the session.
    SessionReset,
}

impl ErrorHandlingApproach {
    /// Whether the routes the UPDATE announces must not be installed: true for treat-as-withdraw
    /// and every stronger approach.
    pub fn withdraws_routes(&self) -> bool {
        *self >= ErrorHandlingApproach::TreatAsWithdraw
    }
}

/// Whether elem conversion applies RFC 7606 error handling.
///
/// This is `#[non_exhaustive]` so that a later variant can, for example, carry the session type
/// instead of assuming eBGP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ErrorHandlingMode {
    /// Emit every announcement and withdrawal as encoded, whatever the validation findings.
    #[default]
    Preserve,
    /// Apply the RFC 7606 approach of each UPDATE to its elems; see
    /// [`Elementor::with_error_handling`](crate::Elementor::with_error_handling).
    Rfc7606,
}

/// The approach for a malformed path attribute of type `attr_type`, assuming an eBGP session.
///
/// This is the RFC → attribute table. Codes without an assigned rule, including unknown codes,
/// use treat-as-withdraw, which RFC 7606 §8 names as the preferred approach and the safe default
/// for an attribute that may affect route selection.
pub fn malformed_attribute_approach(attr_type: AttrType) -> ErrorHandlingApproach {
    use ErrorHandlingApproach::*;
    match attr_type {
        // RFC 7606 §7.1: length other than 1 or an undefined value.
        AttrType::ORIGIN => TreatAsWithdraw,
        // RFC 7606 §7.2: unrecognized segment type, segment overrun or underrun, or a segment
        // of zero ASNs. RFC 7607 §2 adds AS 0.
        AttrType::AS_PATH => TreatAsWithdraw,
        // RFC 7606 §7.3: length other than 4.
        AttrType::NEXT_HOP => TreatAsWithdraw,
        // RFC 7606 §7.4: length other than 4.
        AttrType::MULTI_EXIT_DISCRIMINATOR => TreatAsWithdraw,
        // RFC 7606 §7.5: attribute discard from an external peer (treat-as-withdraw from an
        // internal peer with a length other than 4).
        AttrType::LOCAL_PREFERENCE => AttributeDiscard,
        // RFC 7606 §7.6: length other than 0.
        AttrType::ATOMIC_AGGREGATE => AttributeDiscard,
        // RFC 7606 §7.7: length other than 6 or 8. RFC 7607 §2 adds AS 0.
        AttrType::AGGREGATOR => AttributeDiscard,
        // RFC 7606 §7.8: length not a non-zero multiple of 4.
        AttrType::COMMUNITIES => TreatAsWithdraw,
        // RFC 7606 §7.9: attribute discard from an external peer (treat-as-withdraw from an
        // internal peer with a length other than 4).
        AttrType::ORIGINATOR_ID => AttributeDiscard,
        // RFC 7606 §7.10: attribute discard from an external peer (treat-as-withdraw from an
        // internal peer with a length that is not a non-zero multiple of 4).
        AttrType::CLUSTER_LIST => AttributeDiscard,
        // RFC 7606 §7.11 and §5.3: session reset or AFI/SAFI disable.
        AttrType::MP_REACHABLE_NLRI => SessionReset,
        // RFC 7606 §7.12 and §5.3: session reset or AFI/SAFI disable.
        AttrType::MP_UNREACHABLE_NLRI => SessionReset,
        // RFC 7606 §7.14: length not a non-zero multiple of 8.
        AttrType::EXTENDED_COMMUNITIES => TreatAsWithdraw,
        // RFC 6793 §6: a malformed AS4_PATH or AS4_AGGREGATOR is discarded. RFC 7607 §2 adds AS 0.
        AttrType::AS4_PATH | AttrType::AS4_AGGREGATOR => AttributeDiscard,
        // RFC 6514 §5: treat as withdrawn (SHOULD).
        AttrType::PMSI_TUNNEL => TreatAsWithdraw,
        // RFC 9012 §13: no valid TLV, or the transitive bit clear.
        AttrType::TUNNEL_ENCAPSULATION => TreatAsWithdraw,
        // RFC 7606 §7.13: any malformation.
        AttrType::TRAFFIC_ENGINEERING => TreatAsWithdraw,
        // RFC 7606 §7.15: length not a non-zero multiple of 20.
        AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES => TreatAsWithdraw,
        // RFC 7311 §3: handled like an unrecognized non-transitive attribute, i.e. ignored.
        AttrType::AIGP => AttributeDiscard,
        // RFC 9552 §8.2.2: attribute discard.
        AttrType::BGP_LS_ATTRIBUTE => AttributeDiscard,
        // RFC 8092 §6: length not a non-zero multiple of 12.
        AttrType::LARGE_COMMUNITIES => TreatAsWithdraw,
        // RFC 8205 §5.2: any syntactic or protocol error.
        AttrType::BGPSEC_PATH => TreatAsWithdraw,
        // RFC 9234 §6: length other than 4.
        AttrType::ONLY_TO_CUSTOMER => TreatAsWithdraw,
        // RFC 10039 §4: malformed, or carried with a family other than IPVPN or EVPN.
        AttrType::BGP_DOMAIN_PATH => TreatAsWithdraw,
        // RFC 9015 §3.2.1: wrong flags, TLV overrun, or a missing Hop TLV or sub-TLV.
        AttrType::SFP_ATTRIBUTE => TreatAsWithdraw,
        // RFC 9026 §3.1: attribute discard.
        AttrType::BFD_DISCRIMINATOR => AttributeDiscard,
        // RFC 8669 §6: attribute discard.
        AttrType::BGP_PREFIX_SID => AttributeDiscard,
        // RFC 9793 §4: attribute discard.
        AttrType::BIER => AttributeDiscard,
        // RFC 7606 §7.16 (revising RFC 6368 §5): treat-as-withdraw.
        AttrType::ATTR_SET => TreatAsWithdraw,
        // No rule assigned: RFC 7606 §8 default.
        AttrType::RESERVED
        | AttrType::PE_DISTINGUISHER_LABELS
        | AttrType::DEVELOPMENT
        | AttrType::Unknown(_) => TreatAsWithdraw,
    }
}

/// Whether the parser fully decodes MP_REACH_NLRI and MP_UNREACH_NLRI of this family, so that a
/// decode failure means the attribute is malformed rather than unsupported. Other families,
/// such as VPN and FlowSpec, use encodings this parser does not implement.
fn decodes_mp_family(afi: u16, safi: u8) -> bool {
    let (Ok(afi), Ok(safi)) = (Afi::try_from(afi), Safi::try_from(safi)) else {
        return false;
    };
    match afi {
        Afi::Ipv4 | Afi::Ipv6 => matches!(
            safi,
            Safi::Unicast | Safi::Multicast | Safi::UnicastMulticast | Safi::MplsLabel
        ),
        Afi::LinkState => matches!(safi, Safi::LinkState | Safi::LinkStateVpn),
    }
}

impl BgpValidationWarning {
    /// The path attribute this finding concerns, if it concerns a single one.
    pub fn attr_type(&self) -> Option<AttrType> {
        match self {
            BgpValidationWarning::AttributeFlagsError { attr_type, .. }
            | BgpValidationWarning::AttributeLengthError { attr_type, .. }
            | BgpValidationWarning::MissingWellKnownAttribute { attr_type }
            | BgpValidationWarning::OptionalAttributeError { attr_type, .. }
            | BgpValidationWarning::DuplicateAttribute { attr_type }
            | BgpValidationWarning::PartialAttributeError { attr_type, .. } => Some(*attr_type),
            BgpValidationWarning::UnrecognizedWellKnownAttribute { attr_type_code } => {
                Some(AttrType::from(*attr_type_code))
            }
            BgpValidationWarning::InvalidOriginAttribute { .. } => Some(AttrType::ORIGIN),
            BgpValidationWarning::InvalidNextHopAttribute { .. } => Some(AttrType::NEXT_HOP),
            BgpValidationWarning::MalformedAsPath { .. } => Some(AttrType::AS_PATH),
            BgpValidationWarning::MalformedNlri { nlri_type, .. } => match *nlri_type {
                "mp_reach" => Some(AttrType::MP_REACHABLE_NLRI),
                "mp_unreach" => Some(AttrType::MP_UNREACHABLE_NLRI),
                _ => None,
            },
            BgpValidationWarning::InvalidNetworkField { .. }
            | BgpValidationWarning::MalformedAttributeList { .. }
            | BgpValidationWarning::UnknownRouteRefreshSubtype { .. }
            | BgpValidationWarning::InvalidRouteRefreshLength { .. } => None,
        }
    }

    /// The RFC 7606 approach for this finding on its own, assuming an eBGP session.
    ///
    /// Returns `None` for findings that are not UPDATE errors (ROUTE-REFRESH findings), and for
    /// an MP_REACH_NLRI or MP_UNREACH_NLRI of a family this parser does not decode, whose decode
    /// failure says nothing about the attribute.
    pub fn error_handling_approach(&self) -> Option<ErrorHandlingApproach> {
        use ErrorHandlingApproach::*;
        // No wildcard arm: a new finding must be classified here.
        let approach = match self {
            // RFC 7606 §3(c): treat-as-withdraw unless the attribute's own specification says
            // otherwise; RFC 7311 §3 covers the AIGP transitive bit.
            BgpValidationWarning::AttributeFlagsError { attr_type, .. } => match attr_type {
                AttrType::AIGP => AttributeDiscard,
                _ => TreatAsWithdraw,
            },
            BgpValidationWarning::AttributeLengthError { attr_type, .. }
            | BgpValidationWarning::OptionalAttributeError { attr_type, .. }
            | BgpValidationWarning::PartialAttributeError { attr_type, .. } => {
                malformed_attribute_approach(*attr_type)
            }
            // RFC 7606 §3(d).
            BgpValidationWarning::MissingWellKnownAttribute { .. } => TreatAsWithdraw,
            // RFC 4271 §6.3, unchanged by RFC 7606.
            BgpValidationWarning::UnrecognizedWellKnownAttribute { .. } => SessionReset,
            BgpValidationWarning::InvalidOriginAttribute { .. }
            | BgpValidationWarning::InvalidNextHopAttribute { .. }
            | BgpValidationWarning::MalformedAsPath { .. } => TreatAsWithdraw,
            // RFC 7606 §3(g): a repeated MP_REACH_NLRI or MP_UNREACH_NLRI resets the session;
            // any other repeated attribute keeps its first occurrence.
            BgpValidationWarning::DuplicateAttribute { attr_type } => match attr_type {
                AttrType::MP_REACHABLE_NLRI | AttrType::MP_UNREACHABLE_NLRI => SessionReset,
                _ => AttributeDiscard,
            },
            // RFC 7606 §3(i) and §5.3: NLRI that cannot be parsed leave nothing to withdraw.
            BgpValidationWarning::InvalidNetworkField { .. } => SessionReset,
            // RFC 7606 §4: attribute-list framing errors.
            BgpValidationWarning::MalformedAttributeList { .. } => TreatAsWithdraw,
            BgpValidationWarning::MalformedNlri {
                nlri_type,
                raw_bytes,
                ..
            } => match *nlri_type {
                "mp_reach" | "mp_unreach" => match raw_bytes.as_slice() {
                    // RFC 7606 §5.3 and §7.11: the AFI/SAFI header is readable, so the
                    // speaker may disable just that family.
                    [afi_hi, afi_lo, safi, ..] => {
                        let afi = u16::from_be_bytes([*afi_hi, *afi_lo]);
                        if !decodes_mp_family(afi, *safi) {
                            return None;
                        }
                        AfiSafiDisable
                    }
                    _ => SessionReset,
                },
                _ => SessionReset,
            },
            BgpValidationWarning::UnknownRouteRefreshSubtype { .. }
            | BgpValidationWarning::InvalidRouteRefreshLength { .. } => return None,
        };
        Some(approach)
    }
}

/// RFC 7606 §5.2: an UPDATE that carries path attributes other than MP_UNREACH_NLRI but no
/// reachable NLRI cannot be treated as withdrawn, so any error stronger than attribute discard
/// resets the session.
pub(crate) fn escalate_without_reachability(
    approach: ErrorHandlingApproach,
    has_reachable_nlri: bool,
    has_attrs_other_than_mp_unreach: bool,
) -> ErrorHandlingApproach {
    if !has_reachable_nlri && has_attrs_other_than_mp_unreach && approach.withdraws_routes() {
        ErrorHandlingApproach::SessionReset
    } else {
        approach
    }
}

/// The strongest approach across `warnings`, per RFC 7606 §3(h).
pub(crate) fn strongest_approach<'a>(
    warnings: impl IntoIterator<Item = &'a BgpValidationWarning>,
) -> Option<ErrorHandlingApproach> {
    warnings
        .into_iter()
        .filter_map(BgpValidationWarning::error_handling_approach)
        .max()
}

/// Bitmask over attribute type codes, used to pick the attributes attribute discard removes.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AttrCodeSet([u64; 4]);

impl AttrCodeSet {
    pub(crate) fn insert(&mut self, code: u8) {
        self.0[(code / 64) as usize] |= 1u64 << (code % 64);
    }

    pub(crate) fn contains(&self, code: u8) -> bool {
        self.0[(code / 64) as usize] & (1u64 << (code % 64)) != 0
    }
}

/// The attributes RFC 7606 attribute discard removes, given an UPDATE's findings: every
/// occurrence of an attribute with a finding, and the second and later occurrences of a
/// repeated attribute (RFC 7606 §3(g)).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DiscardPlan {
    pub(crate) drop_all: AttrCodeSet,
    pub(crate) keep_first: AttrCodeSet,
}

impl DiscardPlan {
    pub(crate) fn from_warnings<'a>(
        warnings: impl IntoIterator<Item = &'a BgpValidationWarning>,
    ) -> Self {
        let mut plan = DiscardPlan::default();
        for warning in warnings {
            let Some(attr_type) = warning.attr_type() else {
                continue;
            };
            match warning {
                BgpValidationWarning::DuplicateAttribute { .. } => {
                    plan.keep_first.insert(u8::from(attr_type))
                }
                _ => plan.drop_all.insert(u8::from(attr_type)),
            }
        }
        plan
    }

    /// Whether the attribute with `code`, seen before iff `seen` is true, survives.
    pub(crate) fn keeps(&self, code: u8, seen: bool) -> bool {
        !self.drop_all.contains(code) && !(seen && self.keep_first.contains(code))
    }
}

impl Attributes {
    /// The strongest RFC 7606 approach across this attribute set's validation findings, or
    /// `None` when there are no UPDATE-relevant findings. See the
    /// [module documentation](crate::models::error_handling) for the eBGP assumption.
    ///
    /// This does not apply the RFC 7606 §5.2 rule for UPDATEs without reachable NLRI; use
    /// [`BgpUpdateMessage::error_handling_approach`] for a whole UPDATE.
    pub fn error_handling_approach(&self) -> Option<ErrorHandlingApproach> {
        strongest_approach(&self.validation_warnings)
    }

    /// Whether any attribute other than MP_UNREACH_NLRI is present.
    pub(crate) fn has_attrs_other_than_mp_unreach(&self) -> bool {
        self.inner
            .iter()
            .any(|attribute| attribute.value.attr_type() != AttrType::MP_UNREACHABLE_NLRI)
    }
}

impl BgpUpdateMessage {
    /// The RFC 7606 approach a compliant eBGP speaker applies to this UPDATE, or `None` when
    /// the UPDATE has no UPDATE-relevant validation findings.
    ///
    /// This is the strongest approach across the findings (RFC 7606 §3(h)), escalated to
    /// session reset when the UPDATE carries attributes but no reachable NLRI (§5.2).
    pub fn error_handling_approach(&self) -> Option<ErrorHandlingApproach> {
        let approach = self.attributes.error_handling_approach()?;
        let has_reachable_nlri = !self.announced_prefixes.is_empty()
            || self.attributes.has_attr(AttrType::MP_REACHABLE_NLRI);
        Some(escalate_without_reachability(
            approach,
            has_reachable_nlri,
            self.attributes.has_attrs_other_than_mp_unreach(),
        ))
    }

    /// Whether RFC 7606 forbids installing the routes this UPDATE announces: true when its
    /// approach is treat-as-withdraw or stronger.
    pub fn is_treat_as_withdraw(&self) -> bool {
        self.error_handling_approach()
            .is_some_and(|approach| approach.withdraws_routes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AttributeValue, NetworkPrefix, Origin};
    use std::str::FromStr;
    use ErrorHandlingApproach::*;

    #[test]
    fn approaches_order_from_weakest_to_strongest() {
        assert!(AttributeDiscard < TreatAsWithdraw);
        assert!(TreatAsWithdraw < AfiSafiDisable);
        assert!(AfiSafiDisable < SessionReset);
        assert!(!AttributeDiscard.withdraws_routes());
        assert!(TreatAsWithdraw.withdraws_routes());
        assert!(SessionReset.withdraws_routes());
    }

    #[test]
    fn table_matches_the_rfcs() {
        let expected = [
            (AttrType::ORIGIN, TreatAsWithdraw),
            (AttrType::AS_PATH, TreatAsWithdraw),
            (AttrType::NEXT_HOP, TreatAsWithdraw),
            (AttrType::MULTI_EXIT_DISCRIMINATOR, TreatAsWithdraw),
            (AttrType::LOCAL_PREFERENCE, AttributeDiscard),
            (AttrType::ATOMIC_AGGREGATE, AttributeDiscard),
            (AttrType::AGGREGATOR, AttributeDiscard),
            (AttrType::COMMUNITIES, TreatAsWithdraw),
            (AttrType::ORIGINATOR_ID, AttributeDiscard),
            (AttrType::CLUSTER_LIST, AttributeDiscard),
            (AttrType::MP_REACHABLE_NLRI, SessionReset),
            (AttrType::MP_UNREACHABLE_NLRI, SessionReset),
            (AttrType::EXTENDED_COMMUNITIES, TreatAsWithdraw),
            (AttrType::AS4_PATH, AttributeDiscard),
            (AttrType::AS4_AGGREGATOR, AttributeDiscard),
            (AttrType::PMSI_TUNNEL, TreatAsWithdraw),
            (AttrType::TUNNEL_ENCAPSULATION, TreatAsWithdraw),
            (AttrType::TRAFFIC_ENGINEERING, TreatAsWithdraw),
            (
                AttrType::IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITIES,
                TreatAsWithdraw,
            ),
            (AttrType::AIGP, AttributeDiscard),
            (AttrType::PE_DISTINGUISHER_LABELS, TreatAsWithdraw),
            (AttrType::BGP_LS_ATTRIBUTE, AttributeDiscard),
            (AttrType::LARGE_COMMUNITIES, TreatAsWithdraw),
            (AttrType::BGPSEC_PATH, TreatAsWithdraw),
            (AttrType::ONLY_TO_CUSTOMER, TreatAsWithdraw),
            (AttrType::BGP_DOMAIN_PATH, TreatAsWithdraw),
            (AttrType::SFP_ATTRIBUTE, TreatAsWithdraw),
            (AttrType::BFD_DISCRIMINATOR, AttributeDiscard),
            (AttrType::BGP_PREFIX_SID, AttributeDiscard),
            (AttrType::BIER, AttributeDiscard),
            (AttrType::ATTR_SET, TreatAsWithdraw),
            (AttrType::Unknown(200), TreatAsWithdraw),
        ];
        for (attr_type, approach) in expected {
            assert_eq!(
                malformed_attribute_approach(attr_type),
                approach,
                "{attr_type:?}"
            );
        }
    }

    fn mp_nlri_warning(nlri_type: &'static str, raw_bytes: Vec<u8>) -> BgpValidationWarning {
        BgpValidationWarning::MalformedNlri {
            nlri_type,
            reason: "test".to_string(),
            raw_bytes,
        }
    }

    #[test]
    fn warnings_classify_per_rfc_7606() {
        let cases = [
            (
                BgpValidationWarning::AttributeFlagsError {
                    attr_type: AttrType::COMMUNITIES,
                    expected_flags: 0xc0,
                    actual_flags: 0x40,
                },
                Some(TreatAsWithdraw),
            ),
            (
                BgpValidationWarning::AttributeFlagsError {
                    attr_type: AttrType::AIGP,
                    expected_flags: 0x80,
                    actual_flags: 0xc0,
                },
                Some(AttributeDiscard),
            ),
            (
                BgpValidationWarning::AttributeLengthError {
                    attr_type: AttrType::ATOMIC_AGGREGATE,
                    expected_length: Some(0),
                    actual_length: 1,
                },
                Some(AttributeDiscard),
            ),
            (
                BgpValidationWarning::OptionalAttributeError {
                    attr_type: AttrType::ONLY_TO_CUSTOMER,
                    reason: String::new(),
                },
                Some(TreatAsWithdraw),
            ),
            (
                BgpValidationWarning::MissingWellKnownAttribute {
                    attr_type: AttrType::ORIGIN,
                },
                Some(TreatAsWithdraw),
            ),
            (
                BgpValidationWarning::UnrecognizedWellKnownAttribute {
                    attr_type_code: 200,
                },
                Some(SessionReset),
            ),
            (
                BgpValidationWarning::InvalidOriginAttribute { value: 3 },
                Some(TreatAsWithdraw),
            ),
            (
                BgpValidationWarning::DuplicateAttribute {
                    attr_type: AttrType::COMMUNITIES,
                },
                Some(AttributeDiscard),
            ),
            (
                BgpValidationWarning::DuplicateAttribute {
                    attr_type: AttrType::MP_REACHABLE_NLRI,
                },
                Some(SessionReset),
            ),
            (
                BgpValidationWarning::MalformedAttributeList {
                    reason: String::new(),
                },
                Some(TreatAsWithdraw),
            ),
            (mp_nlri_warning("announced", vec![0xff]), Some(SessionReset)),
            (mp_nlri_warning("withdrawn", vec![0xff]), Some(SessionReset)),
            // IPv6 unicast: decoded by the parser, so the family can be disabled
            (
                mp_nlri_warning("mp_reach", vec![0x00, 0x02, 0x01, 0x10]),
                Some(AfiSafiDisable),
            ),
            // header too short to name a family
            (
                mp_nlri_warning("mp_unreach", vec![0x00, 0x02]),
                Some(SessionReset),
            ),
            // IPv4 MPLS VPN: not decoded by the parser, so no verdict
            (
                mp_nlri_warning("mp_reach", vec![0x00, 0x01, 0x80, 0x0c]),
                None,
            ),
            (
                BgpValidationWarning::UnknownRouteRefreshSubtype { subtype: 9 },
                None,
            ),
        ];
        for (warning, approach) in cases {
            assert_eq!(warning.error_handling_approach(), approach, "{warning:?}");
        }
    }

    fn update_with(
        attributes: Vec<AttributeValue>,
        warnings: Vec<BgpValidationWarning>,
        announced: &[&str],
    ) -> BgpUpdateMessage {
        let mut attrs = Attributes::default();
        for value in attributes {
            attrs.add_attr(value.into());
        }
        for warning in warnings {
            attrs.add_validation_warning(warning);
        }
        BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: attrs,
            announced_prefixes: announced
                .iter()
                .map(|p| NetworkPrefix::from_str(p).unwrap())
                .collect(),
        }
    }

    #[test]
    fn strongest_finding_wins() {
        let update = update_with(
            vec![AttributeValue::Origin(Origin::IGP)],
            vec![
                BgpValidationWarning::AttributeLengthError {
                    attr_type: AttrType::ATOMIC_AGGREGATE,
                    expected_length: Some(0),
                    actual_length: 1,
                },
                BgpValidationWarning::OptionalAttributeError {
                    attr_type: AttrType::COMMUNITIES,
                    reason: String::new(),
                },
            ],
            &["10.0.0.0/24"],
        );
        assert_eq!(update.error_handling_approach(), Some(TreatAsWithdraw));
        assert!(update.is_treat_as_withdraw());
    }

    #[test]
    fn clean_update_has_no_approach() {
        let update = update_with(
            vec![AttributeValue::Origin(Origin::IGP)],
            vec![],
            &["10.0.0.0/24"],
        );
        assert_eq!(update.error_handling_approach(), None);
        assert!(!update.is_treat_as_withdraw());
    }

    #[test]
    fn attribute_discard_does_not_withdraw() {
        let update = update_with(
            vec![AttributeValue::Origin(Origin::IGP)],
            vec![BgpValidationWarning::DuplicateAttribute {
                attr_type: AttrType::COMMUNITIES,
            }],
            &["10.0.0.0/24"],
        );
        assert_eq!(update.error_handling_approach(), Some(AttributeDiscard));
        assert!(!update.is_treat_as_withdraw());
    }

    #[test]
    fn missing_nlri_escalates_to_session_reset() {
        // RFC 7606 §5.2: attributes but no reachable NLRI, and a treat-as-withdraw error
        let update = update_with(
            vec![AttributeValue::Origin(Origin::IGP)],
            vec![BgpValidationWarning::InvalidOriginAttribute { value: 3 }],
            &[],
        );
        assert_eq!(update.error_handling_approach(), Some(SessionReset));

        // attribute discard is not escalated
        let update = update_with(
            vec![AttributeValue::Origin(Origin::IGP)],
            vec![BgpValidationWarning::DuplicateAttribute {
                attr_type: AttrType::COMMUNITIES,
            }],
            &[],
        );
        assert_eq!(update.error_handling_approach(), Some(AttributeDiscard));
    }

    #[test]
    fn discard_plan_keeps_first_duplicate_and_drops_malformed() {
        let plan = DiscardPlan::from_warnings(&[
            BgpValidationWarning::DuplicateAttribute {
                attr_type: AttrType::COMMUNITIES,
            },
            BgpValidationWarning::AttributeLengthError {
                attr_type: AttrType::ATOMIC_AGGREGATE,
                expected_length: Some(0),
                actual_length: 1,
            },
        ]);
        assert!(plan.keeps(8, false));
        assert!(!plan.keeps(8, true));
        assert!(!plan.keeps(6, false));
        assert!(plan.keeps(1, false));
        assert!(plan.keeps(1, true));
    }
}
