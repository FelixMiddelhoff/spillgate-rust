#![no_main]
#[path = "../common.rs"]
mod common;

const CHAINS: [&str; 8] = [
    "gzip, gzip",
    "deflate, gzip",
    "gzip, br",
    "br, zstd",
    "zstd, deflate, gzip",
    "identity, gzip, identity",
    "gzip, deflate, br, zstd",
    "x-gzip, zstd",
];

// The first byte picks the chain, the rest is the body.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Some((first, body)) = data.split_first() {
        common::run(&[CHAINS[usize::from(*first) % CHAINS.len()]], body);
    }
});
