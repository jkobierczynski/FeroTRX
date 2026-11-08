#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ferotrx_ctl::fuzzing::server(data));
