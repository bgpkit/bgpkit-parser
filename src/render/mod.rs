/*!
Human-readable record rendering.

The [`text`] module renders one [`MrtRecord`](crate::MrtRecord) as a layered, indented text
block — a full-fidelity transcript of the record: BGP4MP session context,
withdrawn and announced prefixes, every path attribute, and RFC 7606
validation warnings. The format is designed around this crate's own models
(reusing the leaf `Display` implementations), not around any external tool's
output; it is *inspired by bgpdump's human-readable output*.

The [`hex`] module encodes raw record bytes (as yielded by
[`BgpkitParser::into_filtered_raw_record_iter`](crate::BgpkitParser::into_filtered_raw_record_iter))
as single hex strings — the paste format for byte-level dissectors such as
[wirescope](https://wirescope.labs.bgpkit.com).

Rendering is a pure function of the record: no iterators, no I/O, no
session state. RIB entries reference peers by their table index because the
peer table lives in a separate, earlier record.

# Example

```
use bgpkit_parser::render::text::format_record;
use bgpkit_parser::BgpkitParser;

let parser = BgpkitParser::new("tests/fixtures/ripe/rrc00/2000.01/updates.20000102.2014.gz").unwrap();
for record in parser.into_record_iter() {
    println!("{}", format_record(&record));
}
```
*/

pub mod hex;
pub mod text;
