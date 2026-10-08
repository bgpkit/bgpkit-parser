# BGP Path Attributes

## Unit Test Coverage

| Path Attribute           | RFC                | Codes | Unit Test |
|--------------------------|--------------------|-------|-----------|
| Origin                   | [RFC4271][rfc4271] | 1     | Yes       |
| AS Path                  | [RFC4271][rfc4271] | 2,17  | Yes       |
| Next Hop                 | [RFC4271][rfc4271] | 3     | Yes       |
| Multi Exit Discriminator | [RFC4271][rfc4271] | 4     | Yes       |
| Local Preference         | [RFC4271][rfc4271] | 5     | Yes       |
| Atomic Aggregate         | [RFC4271][rfc4271] | 6     | Yes       |
| Aggregate                | [RFC4271][rfc4271] | 7,18  | Yes       |
| Community                | [RFC1997][rfc1997] | 8     | Yes       |
| Originator ID            | [RFC4456][rfc4456] | 9     | Yes       |
| Cluster List             | [RFC4456][rfc4456] | 10    | Yes       |
| MP NLRI                  | [RFC4760][rfc4760] | 14,15 | Yes       |
| Extended Community       | [RFC4360][rfc4360] | 16,25 | Yes       |
| Large Community          | [RFC8092][rfc8092] | 32    | Yes       |
| Only To Customer         | [RFC9234][rfc9234] | 35    | Yes       |
| Traffic Engineering      | [RFC5543][rfc5543] | 24    | Yes       |
| AIGP                     | [RFC7311][rfc7311] | 26    | Yes       |
| BFD Discriminator        | [RFC9026][rfc9026] | 38    | Yes       |
| BGP Prefix-SID           | [RFC8669][rfc8669] | 40    | Yes       |
| SFP Attribute            | [RFC9015][rfc9015] | 37    | Yes       |
| BIER                     | [RFC9793][rfc9793] | 41    | Yes       |
| Tunnel Encapsulation     | [RFC9012][rfc9012] | 23    | Yes       |
| BGP Link-State           | [RFC7752][rfc7752] | 29    | Yes       |
| BGP Domain Path          | [RFC10039][rfc10039] | 36    | Yes       |

## Known Limitations

| Path Attribute                  | RFC                           | Type Code | Status                      | Notes                            |
|---------------------------------|-------------------------------|-----------|-----------------------------|----------------------------------|
| ATTR_SET                        | [RFC6368][rfc6368]            | 128       | Raw-retained / model only  | Structured nested parser not yet implemented |
| PMSI_TUNNEL                     | [RFC6514][rfc6514]            | 22        | Raw-retained              | Structured parser not implemented |
| PE_DISTINGUISHER_LABELS         | [RFC6514][rfc6514]            | 27        | Raw-retained              | Structured parser not implemented |
| BGPSEC_PATH                     | [RFC8205][rfc8205]            | 33        | Raw-retained              | Structured parser not implemented |

## Error Handling (RFC 7606)

When an attribute is malformed, RFC 7606 and the RFC defining the attribute name the approach a
router takes: **discard** the attribute, **treat-as-withdraw** (TAW) every route in the UPDATE, or
**reset** the session (or disable the AFI/SAFI). `malformed_attribute_approach` in
`src/models/bgp/error_handling.rs` encodes this table; `BgpUpdateMessage::error_handling_approach`
combines an UPDATE's findings, and `BgpkitParser::enable_rfc7606_error_handling` applies the result
to elements. The route iterator checks every attribute header but parses only the values of ORIGIN,
AS_PATH, AS4_PATH, MP_REACH_NLRI and MP_UNREACH_NLRI, so it can miss value errors in other
attributes.

MRT data does not record the session type, so the table assumes **eBGP**, which is how route
collectors peer. Three attributes would be treat-as-withdraw from an iBGP peer instead.

| Path Attribute             | Code  | Malformed when                                      | Approach (eBGP)      | Reference                                   |
|----------------------------|-------|-----------------------------------------------------|----------------------|---------------------------------------------|
| ORIGIN                     | 1     | length ≠ 1, or undefined value                      | TAW                  | [RFC7606 §7.1][rfc7606]                     |
| AS_PATH                    | 2     | bad segment type or length, empty segment, AS 0     | TAW                  | [RFC7606 §7.2][rfc7606], [RFC7607][rfc7607] |
| NEXT_HOP                   | 3     | length ≠ 4                                          | TAW                  | [RFC7606 §7.3][rfc7606]                     |
| MULTI_EXIT_DISC            | 4     | length ≠ 4                                          | TAW                  | [RFC7606 §7.4][rfc7606]                     |
| LOCAL_PREF                 | 5     | length ≠ 4                                          | Discard (iBGP: TAW)  | [RFC7606 §7.5][rfc7606]                     |
| ATOMIC_AGGREGATE           | 6     | length ≠ 0                                          | Discard              | [RFC7606 §7.6][rfc7606]                     |
| AGGREGATOR                 | 7     | length ≠ 6 or 8, AS 0                               | Discard              | [RFC7606 §7.7][rfc7606], [RFC7607][rfc7607] |
| COMMUNITIES                | 8     | length not a non-zero multiple of 4                 | TAW                  | [RFC7606 §7.8][rfc7606]                     |
| ORIGINATOR_ID              | 9     | length ≠ 4                                          | Discard (iBGP: TAW)  | [RFC7606 §7.9][rfc7606]                     |
| CLUSTER_LIST               | 10    | length not a non-zero multiple of 4                 | Discard (iBGP: TAW)  | [RFC7606 §7.10][rfc7606]                    |
| MP_REACH_NLRI              | 14    | length < 5, bad next-hop length, bad NLRI           | AFI/SAFI disable     | [RFC7606 §7.11, §5.3][rfc7606]              |
| MP_UNREACH_NLRI            | 15    | length < 3, bad NLRI                                | AFI/SAFI disable     | [RFC7606 §7.12, §5.3][rfc7606]              |
| EXTENDED_COMMUNITIES       | 16    | length not a non-zero multiple of 8                 | TAW                  | [RFC7606 §7.14][rfc7606]                    |
| AS4_PATH                   | 17    | malformed, AS 0                                     | Discard              | [RFC6793 §6][rfc6793], [RFC7607][rfc7607]   |
| AS4_AGGREGATOR             | 18    | length ≠ 8, AS 0                                    | Discard              | [RFC6793 §6][rfc6793], [RFC7607][rfc7607]   |
| PMSI_TUNNEL                | 22    | undefined tunnel type, bad identifier               | TAW (SHOULD)         | [RFC6514 §5][rfc6514]                       |
| Tunnel Encapsulation       | 23    | no valid TLV, transitive bit clear                  | TAW                  | [RFC9012 §13][rfc9012]                      |
| Traffic Engineering        | 24    | any malformation                                    | TAW                  | [RFC7606 §7.13][rfc7606]                    |
| IPv6 Ext. Community        | 25    | length not a non-zero multiple of 20                | TAW                  | [RFC7606 §7.15][rfc7606]                    |
| AIGP                       | 26    | malformed, transitive bit set                       | Discard              | [RFC7311 §3][rfc7311]                       |
| BGP-LS Attribute           | 29    | malformed                                           | Discard              | [RFC9552][rfc9552]                          |
| LARGE_COMMUNITY            | 32    | length not a non-zero multiple of 12                | TAW                  | [RFC8092 §6][rfc8092]                       |
| BGPsec_PATH                | 33    | syntactic or protocol error                         | TAW                  | [RFC8205 §5.2][rfc8205]                     |
| Only to Customer           | 35    | length ≠ 4                                          | TAW                  | [RFC9234 §6][rfc9234]                       |
| D-PATH                     | 36    | malformed, or not on IPVPN/EVPN routes              | TAW                  | [RFC10039 §4][rfc10039]                     |
| SFP Attribute              | 37    | wrong flags, TLV overrun, missing Hop TLV           | TAW                  | [RFC9015 §3.2.1][rfc9015]                   |
| BFD Discriminator          | 38    | length < 11, bad optional TLV                       | Discard              | [RFC9026][rfc9026]                          |
| BGP Prefix-SID             | 40    | TLV length errors                                   | Discard              | [RFC8669 §6][rfc8669]                       |
| BIER                       | 41    | TLV lengths do not add up                           | Discard              | [RFC9793 §4][rfc9793]                       |
| ATTR_SET                   | 128   | malformed                                           | TAW                  | [RFC7606 §7.16][rfc7606]                    |
| any other code             | –     | –                                                   | TAW                  | [RFC7606 §8][rfc7606]                       |

Rules that are not tied to one attribute:

| Condition                                                        | Approach                    | Reference                    |
|------------------------------------------------------------------|-----------------------------|------------------------------|
| Optional or transitive flag conflicts with the attribute type    | TAW (AIGP: discard)         | [RFC7606 §3(c)][rfc7606]     |
| Missing well-known mandatory attribute                           | TAW                         | [RFC7606 §3(d)][rfc7606]     |
| Attribute runs past the attribute list, or 1–2 trailing bytes    | TAW                         | [RFC7606 §4][rfc7606]        |
| Repeated MP_REACH_NLRI or MP_UNREACH_NLRI                        | Session reset               | [RFC7606 §3(g)][rfc7606]     |
| Any other repeated attribute                                     | Discard all but the first   | [RFC7606 §3(g)][rfc7606]     |
| Unrecognized attribute with the optional bit clear               | Session reset               | [RFC4271 §6.3][rfc4271]      |
| Malformed NLRI or withdrawn routes field                         | Session reset               | [RFC7606 §3(i), §5.3][rfc7606] |
| Attributes but no reachable NLRI, with any error beyond discard  | Session reset               | [RFC7606 §5.2][rfc7606]      |
| Several errors in one UPDATE                                     | The strongest approach      | [RFC7606 §3(h)][rfc7606]     |

An MP_REACH_NLRI or MP_UNREACH_NLRI of a family this parser does not decode, such as VPN or
FlowSpec, gets no verdict when it fails to decode: the failure says nothing about the attribute.

**Legend:**
- **Raw-retained**: Attribute value bytes are preserved as `AttributeValue::Raw(AttrRaw)` and can be re-encoded, but no structured parser exists yet.
- **Model only**: Data structures exist but structured parser/encoder is incomplete.
- Deprecated/historic code points are intentionally handled with `AttributeValue::Deprecated(AttrRaw)` helpers instead of active `AttrType` variants. Code point status should be checked against the IANA BGP Path Attributes registry.

[rfc1997]: https://datatracker.ietf.org/doc/html/rfc1997
[rfc4271]: https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
[rfc4360]: https://datatracker.ietf.org/doc/html/rfc4360
[rfc4456]: https://datatracker.ietf.org/doc/html/rfc4456
[rfc4760]: https://datatracker.ietf.org/doc/html/rfc4760
[rfc5543]: https://datatracker.ietf.org/doc/html/rfc5543
[rfc5701]: https://datatracker.ietf.org/doc/html/rfc5701
[rfc6368]: https://datatracker.ietf.org/doc/html/rfc6368
[rfc6514]: https://datatracker.ietf.org/doc/html/rfc6514
[rfc6793]: https://datatracker.ietf.org/doc/html/rfc6793
[rfc7606]: https://datatracker.ietf.org/doc/html/rfc7606
[rfc7607]: https://datatracker.ietf.org/doc/html/rfc7607
[rfc7311]: https://datatracker.ietf.org/doc/html/rfc7311
[rfc8092]: https://datatracker.ietf.org/doc/html/rfc8092
[rfc8205]: https://datatracker.ietf.org/doc/html/rfc8205
[rfc7752]: https://datatracker.ietf.org/doc/html/rfc7752
[rfc8669]: https://datatracker.ietf.org/doc/html/rfc8669
[rfc9012]: https://datatracker.ietf.org/doc/html/rfc9012
[rfc9015]: https://datatracker.ietf.org/doc/html/rfc9015
[rfc9026]: https://datatracker.ietf.org/doc/html/rfc9026
[rfc9234]: https://datatracker.ietf.org/doc/html/rfc9234
[rfc9552]: https://datatracker.ietf.org/doc/html/rfc9552
[rfc9793]: https://datatracker.ietf.org/doc/html/rfc9793
[rfc10039]: https://datatracker.ietf.org/doc/html/rfc10039
[iana-bgp]: https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
