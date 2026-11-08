#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ferotrx_core::fuzzing::pcap(data));
