use super::*;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;

/// Segment type names using names from RFC3065.
///
/// <https://datatracker.ietf.org/doc/html/rfc3065#section-5>
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize)]
enum SegmentType {
    AS_SET,
    AS_SEQUENCE,
    AS_CONFED_SEQUENCE,
    AS_CONFED_SET,
}

#[derive(Serialize, Deserialize)]
struct VerboseSegment<'s> {
    ty: SegmentType,
    values: Cow<'s, [Asn]>,
}

impl Serialize for AsPathSegment<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (ty, elements) = match self {
            AsPathSegment::AsSequence(x) => (SegmentType::AS_SEQUENCE, x.as_ref()),
            AsPathSegment::AsSet(x) => (SegmentType::AS_SET, x.as_ref()),
            AsPathSegment::ConfedSequence(x) => (SegmentType::AS_CONFED_SEQUENCE, x.as_ref()),
            AsPathSegment::ConfedSet(x) => (SegmentType::AS_CONFED_SET, x.as_ref()),
        };

        let verbose = VerboseSegment {
            ty,
            values: Cow::Borrowed(elements),
        };

        verbose.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AsPathSegment<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let verbose = VerboseSegment::deserialize(deserializer)?;

        let values = verbose.values;
        match verbose.ty {
            SegmentType::AS_SET => Ok(AsPathSegment::AsSet(values)),
            SegmentType::AS_SEQUENCE => Ok(AsPathSegment::AsSequence(values)),
            SegmentType::AS_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(values)),
            SegmentType::AS_CONFED_SET => Ok(AsPathSegment::ConfedSet(values)),
        }
    }
}

/// Check if we can serialize an `AsPath` using the simplified format and get the number of
/// elements to do so. The ambiguities that could prevent us from doing so are confederation
/// segments and adjacent sequence segments.
fn simplified_format_len(storage: &AsPathStorage) -> Option<usize> {
    match storage {
        AsPathStorage::SingleSequence(x) => Some(x.len()),
        AsPathStorage::Mixed(segments) => {
            let mut elements = 0;
            let mut prev_was_sequence = false;
            for segment in segments {
                match segment {
                    AsPathSegment::AsSequence(seq) if !prev_was_sequence => {
                        prev_was_sequence = true;
                        elements += seq.len();
                    }
                    AsPathSegment::AsSet(_) => {
                        prev_was_sequence = false;
                        elements += 1;
                    }
                    _ => return None,
                }
            }

            Some(elements)
        }
    }
}

/// # Serialization format
/// For the sake of readability and ease of use within other applications, there are verbose and
/// simplified variants for serialization.
///
/// ## Simplified format
/// The simplified format is the default preferred serialization format. This format does not
/// cover confederation segments and involves a single list of ASNs within the path sequence.
/// For sets, a list of set members is used in place of an ASN.
/// ```rust
/// # use bgpkit_parser::models::{Asn, AsPath, AsPathSegment};
///
/// let a: AsPath = serde_json::from_str("[123, 942, 102]").unwrap();
/// let b: AsPath = serde_json::from_str("[231, 432, [643, 836], 352]").unwrap();
///
/// assert_eq!(&a.segments, &[
///     AsPathSegment::sequence([123, 942, 102])
/// ]);
/// assert_eq!(&b.segments, &[
///     AsPathSegment::sequence([231, 432]),
///     AsPathSegment::set([643, 836]),
///     AsPathSegment::sequence([352])
/// ]);
/// ```
///
/// ## Verbose format
/// The verbose format serves as the fallback format for when the simplified format can not be
/// used due to ambiguity. This happens when confederation segments are present, or multiple
/// sequences occur back to back. In this format, segments are explicitly seperated and labeled.
/// Segment types, denoted by the `ty` field, correspond to the names used within RFC3065
/// (`AS_SET`, `AS_SEQUENCE`, `AS_CONFED_SEQUENCE`, `AS_CONFED_SET`).
/// ```rust
/// # use std::borrow::Cow;
/// use bgpkit_parser::models::{Asn, AsPath};
/// # use bgpkit_parser::models::AsPathSegment::*;
///
/// let a = r#"[
///     { "ty": "AS_CONFED_SEQUENCE", "values": [123, 942] },
///     { "ty": "AS_SEQUENCE", "values": [773] },
///     { "ty": "AS_SEQUENCE", "values": [382, 293] }
/// ]"#;
///
/// let parsed: AsPath = serde_json::from_str(a).unwrap();
/// assert_eq!(&parsed.segments, &[
///     ConfedSequence(Cow::Owned(vec![Asn::from(123), Asn::from(942)])),
///     AsSequence(Cow::Owned(vec![Asn::from(773)])),
///     AsSequence(Cow::Owned(vec![Asn::from(382), Asn::from(293)]))
/// ]);
/// ```
impl Serialize for AsPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(num_elements) = simplified_format_len(&self.storage) {
            // Serialize simplified format
            let mut seq_serializer = serializer.serialize_seq(Some(num_elements))?;

            for segment in self.iter_segments() {
                match segment {
                    AsPathSegment::AsSequence(elements) => {
                        elements
                            .iter()
                            .try_for_each(|x| seq_serializer.serialize_element(x))?;
                    }
                    AsPathSegment::AsSet(x) => seq_serializer.serialize_element(&*x)?,
                    _ => unreachable!("simplified_format_len checked for confed segments"),
                }
            }
            return seq_serializer.end();
        }

        // Serialize verbose format
        serializer.collect_seq(self.iter_segments())
    }
}

struct AsPathVisitor;

impl<'de> Visitor<'de> for AsPathVisitor {
    type Value = AsPath;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("list of AS_PATH segments")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // TODO: Implement this portion using the builder once added

        // // Technically, we can handle an input that mixes the simplified and verbose formats,
        // // but we do not want to document this behavior as it may change in future updates.
        // #[derive(Deserialize)]
        // #[serde(untagged)]
        // enum PathElement {
        //     SequenceElement(Asn),
        //     Set(Vec<Asn>),
        //     Verbose(AsPathSegment<'static>),
        // }
        //
        // let mut append_new_sequence = false;
        // let mut segments = Vec::new();
        // while let Some(element) = seq.next_element()? {
        //     match element {
        //         PathElement::SequenceElement(x) => {
        //             if append_new_sequence {
        //                 // If the input is mixed between verbose and regular segments, this flag
        //                 // is used to prevent appending to a verbose sequence.
        //                 append_new_sequence = false;
        //                 segments.push(AsPathSegment::AsSequence(Cow::Owned(Vec::new())));
        //             }
        //
        //             if let Some(AsPathSegment::AsSequence(last_sequence)) = segments.last_mut() {
        //                 last_sequence.to_mut().push(x);
        //             } else {
        //                 segments.push(AsPathSegment::AsSequence(Cow::Owned(vec![x])));
        //             }
        //         }
        //         PathElement::Set(values) => {
        //             segments.push(AsPathSegment::AsSet(Cow::Owned(values)));
        //         }
        //         PathElement::Verbose(verbose) => {
        //             segments.push(verbose);
        //         }
        //     }
        // }
        //
        // Ok(AsPath { segments })
        todo!()
    }
}

impl<'de> Deserialize<'de> for AsPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(AsPathVisitor)
    }
}
