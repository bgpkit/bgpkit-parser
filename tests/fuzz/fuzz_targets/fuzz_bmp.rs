#![no_main]
use bgpkit_parser::parser::bmp::{parse_bmp_msg, parse_openbmp_header};
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    // Try BMP common message parsing directly
    let _ = parse_bmp_msg(&mut bytes.clone());

    // Try OpenBMP framed payload: header + inner BMP
    if bytes.len() > 4 {
        let mut b2 = bytes.clone();
        let _ = parse_openbmp_header(&mut b2).and_then(|_| parse_bmp_msg(&mut b2));
    }
});
