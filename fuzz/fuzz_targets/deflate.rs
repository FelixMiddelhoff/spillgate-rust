#![no_main]
#[path = "../common.rs"]
mod common;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    common::run(&["deflate"], data);
});
