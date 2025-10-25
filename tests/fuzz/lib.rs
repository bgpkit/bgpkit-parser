#![no_main]

use libfuzzer_sys::fuzz_target;

// Empty lib to satisfy cargo-fuzz layout; actual targets live in fuzz_targets/

fuzz_target!(|_data: &[u8]| {});
