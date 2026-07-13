/// Example: inspecting raw, deprecated, and unknown BGP path attributes.
///
/// v0.18 introduces `AttributeValue::Raw` for known but undecoded attributes,
/// making it possible to inspect, count, and round-trip attributes even when
/// full semantic parsing is not yet implemented.
///
/// Run with:
/// ```bash
/// cargo run --example raw_attributes
/// ```
use bgpkit_parser::models::*;

fn describe_value(value: &AttributeValue) {
    match value {
        AttributeValue::Raw(raw) => {
            println!(
                "  Raw code {} ({} bytes, {:?})",
                raw.code,
                raw.bytes.len(),
                raw.attr_type()
            );
        }
        AttributeValue::Deprecated(raw) => {
            println!("  Deprecated code {} ({} bytes)", raw.code, raw.bytes.len());
        }
        AttributeValue::Unknown(raw) => {
            println!("  Unknown code {} ({} bytes)", raw.code, raw.bytes.len());
        }
        AttributeValue::Aigp(aigp) => {
            println!(
                "  AIGP ({} TLVs, metric={:?})",
                aigp.tlvs.len(),
                aigp.accumulated_metric()
            );
        }
        AttributeValue::BfdDiscriminator(bfd) => {
            println!(
                "  BFD Discriminator (mode={}, discriminator={})",
                bfd.mode, bfd.discriminator
            );
        }
        AttributeValue::BgpPrefixSid(psid) => {
            println!("  BGP Prefix-SID ({} TLVs)", psid.tlvs.len());
        }
        AttributeValue::Bier(bier) => println!("  BIER ({} TLVs)", bier.tlvs.len()),
        AttributeValue::Sfp(sfp) => println!("  SFP ({} TLVs)", sfp.tlvs.len()),
        other => println!("  {:?}", other.attr_type()),
    }
}

fn main() {
    println!("=== Demonstrating raw/deprecated/unknown attribute handling ===\n");

    // Build an Attributes collection from AttributeValue iterators.
    let attributes = Attributes::from_iter(vec![
        // Known but unsupported: PMSI_TUNNEL (code 22)
        AttributeValue::Raw(AttrRaw {
            code: 22,
            bytes: bytes::Bytes::from_static(&[0x01, 0x02, 0x03]),
        }),
        // Deprecated: code 13 (RCID_PATH / CLUSTER_ID)
        AttributeValue::Deprecated(AttrRaw {
            code: 13,
            bytes: bytes::Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]),
        }),
        // Unknown / unassigned: code 127
        AttributeValue::Unknown(AttrRaw {
            code: 127,
            bytes: bytes::Bytes::from_static(&[0xde, 0xad]),
        }),
        // Typed: a structured AIGP attribute
        AttributeValue::Aigp(Aigp {
            tlvs: vec![AigpTlv {
                tlv_type: 1,
                length: 11,
                value: bytes::Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a]),
            }],
        }),
    ]);

    println!("All attributes:");
    for value in &attributes {
        describe_value(value);
    }

    // Check warnings
    println!(
        "\nValidation warnings: {}",
        attributes.validation_warnings().len()
    );

    // Encode and decode round-trip
    let encoded = attributes.encode(AsnLength::Bits32);
    println!("\nEncoded size: {} bytes", encoded.len());

    // Show raw access to the undecoded bytes
    println!("\nRaw bytes access:");
    for value in &attributes {
        match value {
            AttributeValue::Raw(raw) => {
                println!(
                    "  Raw code {}: {} bytes (first bytes: {:02x?})",
                    raw.code,
                    raw.bytes.len(),
                    &raw.bytes[..raw.bytes.len().min(8)]
                );
            }
            AttributeValue::Deprecated(raw) => {
                println!("  Deprecated code {}: {} bytes", raw.code, raw.bytes.len());
            }
            AttributeValue::Unknown(raw) => {
                println!("  Unknown code {}: {} bytes", raw.code, raw.bytes.len());
            }
            _ => {}
        }
    }

    println!("\n=== Done ===");
}
