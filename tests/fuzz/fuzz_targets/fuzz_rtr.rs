#![no_main]
use bgpkit_parser::parser::rpki::rtr::{parse_rtr_pdu, read_rtr_pdu};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Slice-based single-PDU parser: must never panic (OOB slice, underflow).
    let _ = parse_rtr_pdu(data);

    // Reader-based parser: must never panic and must not attempt an
    // implausibly large allocation from a crafted length field.
    let mut cursor = Cursor::new(data);
    let _ = read_rtr_pdu(&mut cursor);
});
