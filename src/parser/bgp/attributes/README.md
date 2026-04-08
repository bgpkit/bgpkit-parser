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
| Cluster List             | [RFC4456][rfc4456] | 10,13 | Yes       |
| MP NLRI                  | [RFC4760][rfc4760] | 14,15 | Yes       |
| Extended Community       | [RFC4360][rfc4360] | 16,25 | Yes       |
| Large Community          | [RFC8092][rfc8092] | 32    | Yes       |
| Only To Customer         | [RFC9234][rfc9234] | 35    | Yes       |

## Known Limitations

| Path Attribute                  | RFC                           | Type Code | Status                      | Notes                            |
|---------------------------------|-------------------------------|-----------|-----------------------------|----------------------------------|
| AIGP (Accumulated IGP Metric)   | [RFC7311][rfc7311]            | 26        | Type defined, model only    | Parser and encoding not yet implemented |
| ATTR_SET                        | [RFC6368][rfc6368]            | 128       | Type defined, model only    | Parser and encoding not yet implemented |
| PMSI_TUNNEL                     | [RFC6514][rfc6514]            | 22        | Type defined in enum      | Parser not implemented           |
| TRAFFIC_ENGINEERING             | [RFC5543][rfc5543]            | 24        | Type defined in enum      | Parser not implemented           |
| IPv6_EXT_COMMUNITIES            | [RFC5701][rfc5701]            | 25        | ✅ Implemented            | Listed in main table above       |
| PE_DISTINGUISHER_LABELS         | [RFC6514][rfc6514]            | 27        | Type defined in enum      | Parser not implemented           |
| BGPSEC_PATH                     | [RFC8205][rfc8205]            | 33        | Type defined in enum      | Parser not implemented           |
| SFP_ATTRIBUTE                   | [RFC9015][rfc9015]            | 37        | Type defined in enum      | Parser not implemented           |
| BFD_DISCRIMINATOR               | [RFC9026][rfc9026]            | 38        | Type defined in enum      | Parser not implemented           |
| BGP_PREFIX_SID                  | [RFC8669][rfc8669]            | 40        | Type defined in enum      | Parser not implemented           |

**Legend:**
- **Type defined**: Attribute type code is defined in `AttrType` enum (models)
- **Model only**: Data structures exist but parser/encoder not implemented
- **Type defined in enum**: Only the type code exists, no parser or model

[rfc1997]: https://datatracker.ietf.org/doc/html/rfc1997
[rfc4271]: https://datatracker.ietf.org/doc/html/rfc4271#section-4.3
[rfc4360]: https://datatracker.ietf.org/doc/html/rfc4360
[rfc4456]: https://datatracker.ietf.org/doc/html/rfc4456
[rfc4760]: https://datatracker.ietf.org/doc/html/rfc4760
[rfc5543]: https://datatracker.ietf.org/doc/html/rfc5543
[rfc5701]: https://datatracker.ietf.org/doc/html/rfc5701
[rfc6368]: https://datatracker.ietf.org/doc/html/rfc6368
[rfc6514]: https://datatracker.ietf.org/doc/html/rfc6514
[rfc7311]: https://datatracker.ietf.org/doc/html/rfc7311
[rfc8092]: https://datatracker.ietf.org/doc/html/rfc8092
[rfc8205]: https://datatracker.ietf.org/doc/html/rfc8205
[rfc8669]: https://datatracker.ietf.org/doc/html/rfc8669
[rfc9015]: https://datatracker.ietf.org/doc/html/rfc9015
[rfc9026]: https://datatracker.ietf.org/doc/html/rfc9026
[rfc9234]: https://datatracker.ietf.org/doc/html/rfc9234
[iana-bgp]: https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml