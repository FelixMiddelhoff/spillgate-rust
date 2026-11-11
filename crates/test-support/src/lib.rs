//! Builds the generated conformance inputs of `spec/generators.md` without a compression library.
//!
//! Every construction is the one written down in `spec/generators.md`. The SHA-256 of each generated
//! stream in `conformance/manifest.json` proves that this code builds the same bytes as the reference.
//! Only the standard library and `sha2` are used.

// Lets `json_spec.rs` (shared with the root crate's tests through `#[path]`) name this crate the same way
// from both places.
extern crate self as spillgate_test_support;

use sha2::{Digest, Sha256};

#[cfg(test)]
mod json_spec;

const MAX_MATCH: u64 = 258;
const STORED_BLOCK_LIMIT: usize = 65535;

/// Why a generator spec could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenError(pub String);

impl std::fmt::Display for GenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GenError {}

fn fail<T>(message: impl Into<String>) -> Result<T, GenError> {
    Err(GenError(message.into()))
}

/// A generator spec (`{"kind": ..., "params": {...}}` of the manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// `zeros`: gzip/zlib/raw by `matches`, br/zstd by `size` and `window`.
    Zeros {
        codec: String,
        matches: u64,
        size: u64,
        window: u32,
    },
    /// `data`: the stored construction of `data(seed, size)` wrapped by the codec.
    Data {
        codec: String,
        seed: u64,
        size: u64,
        window: u32,
    },
    /// `wrap`: the output of `inner`, wrapped `times` times in a stored stream.
    Wrap {
        codec: String,
        times: u64,
        inner: Box<Spec>,
        window: u32,
    },
}

/// Data(seed, size): xorshift64 bytes that do not compress.
pub fn data(seed: u64, size: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(((state >> 24) & 0xff) as u8);
    }
    out
}

/// Writes DEFLATE-style fields: least significant bit first; Huffman codes most significant bit first.
#[derive(Default)]
pub struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    count: u32,
}

impl BitWriter {
    /// A new, empty writer.
    pub fn new() -> BitWriter {
        BitWriter::default()
    }

    /// Write the low `n` bits of `value` (n at most 32).
    pub fn bits(&mut self, value: u64, n: u32) {
        self.acc |= value << self.count;
        self.count += n;
        while self.count >= 8 {
            self.out.push((self.acc & 0xff) as u8);
            self.acc >>= 8;
            self.count -= 8;
        }
    }

    /// Write an `n` bit Huffman code, most significant bit first.
    pub fn code(&mut self, code: u64, n: u32) {
        let mut reversed = 0;
        for i in 0..n {
            reversed = (reversed << 1) | ((code >> i) & 1);
        }
        self.bits(reversed, n);
    }

    /// Write `n` zero bits; whole bytes in bulk, so billions of bits stay cheap.
    pub fn zero_bits(&mut self, n: u64) {
        let head = n.min(u64::from((8 - self.count) % 8));
        self.bits(0, head as u32);
        let rest = n - head;
        if self.count == 0 {
            let bytes = (rest / 8) as usize;
            self.out.resize(self.out.len() + bytes, 0);
            self.bits(0, (rest % 8) as u32);
        }
    }

    /// Pad with zero bits to the next byte boundary.
    pub fn align(&mut self) {
        if self.count > 0 {
            self.out.push((self.acc & 0xff) as u8);
            self.acc = 0;
            self.count = 0;
        }
    }

    /// Append whole bytes; only valid on a byte boundary.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Pad to a byte boundary and return the bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}

/// StoredDeflate: stored blocks of at most 65535 bytes; empty data is one empty final block.
pub fn stored_deflate(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload.len() / STORED_BLOCK_LIMIT * 5 + 5);
    let mut pos = 0;
    loop {
        let n = (payload.len() - pos).min(STORED_BLOCK_LIMIT);
        let last = pos + n == payload.len();
        let len = n as u16;
        out.push(u8::from(last));
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&payload[pos..pos + n]);
        pos += n;
        if pos >= payload.len() {
            return out;
        }
    }
}

/// ZerosDeflate: one dynamic Huffman block decoding to `1 + 258 * matches` zero bytes.
pub fn zeros_deflate(matches: u64) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.bits(1, 1); // BFINAL
    w.bits(2, 2); // BTYPE 10: dynamic Huffman codes
    w.bits(29, 5); // HLIT: 286 literal/length symbols
    w.bits(1, 5); // HDIST: 2 distance symbols
    w.bits(14, 4); // HCLEN: 18 code-length code lengths
    for length in [0u64, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2] {
        w.bits(length, 3);
    }
    let zero_run = |w: &mut BitWriter, count: u64| {
        w.code(0b0, 1);
        w.bits(count - 11, 7);
    };
    w.code(0b11, 2); // literal 0: length 2
    zero_run(&mut w, 138); // symbols 1..138 unused
    zero_run(&mut w, 117); // symbols 139..255 unused
    w.code(0b11, 2); // symbol 256, end of block: length 2
    zero_run(&mut w, 28); // symbols 257..284 unused
    w.code(0b10, 2); // symbol 285 (length 258): length 1
    w.code(0b10, 2); // distance symbol 0: length 1
    w.code(0b10, 2); // distance symbol 1: length 1
    w.code(0b10, 2); // literal 0
    w.zero_bits(2 * matches); // per match: length symbol 285 = '0', distance symbol 0 = '0'
    w.code(0b11, 2); // end of block
    w.finish()
}

/// The decoded size of `zeros_deflate(matches)`.
pub fn zeros_decoded_size(matches: u64) -> u64 {
    1 + MAX_MATCH * matches
}

const CRC_POLY: u32 = 0xedb8_8320;

/// CRC-32 (IEEE) of `payload`.
pub fn crc32(payload: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ CRC_POLY } else { c >> 1 };
        }
        *slot = c;
    }
    let mut crc = !0u32;
    for &b in payload {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Multiplication modulo the CRC polynomial in the reflected domain (zlib's `multmodp`).
fn multmodp(a: u32, mut b: u32) -> u32 {
    let mut m = 1u32 << 31;
    let mut p = 0u32;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ CRC_POLY } else { b >> 1 };
    }
    p
}

/// The CRC-32 of `n` zero bytes, in O(log n): feeding zeros multiplies the register by x^8 per byte.
pub fn crc32_of_zeros(n: u64) -> u32 {
    let mut powers = [0u32; 32];
    let mut p = 1u32 << 30; // x^1
    powers[0] = p;
    for slot in powers.iter_mut().skip(1) {
        p = multmodp(p, p);
        *slot = p;
    }
    // x^(8n) = x^(2^3 * n)
    let mut result = 1u32 << 31; // x^0
    let mut k = 3usize;
    let mut rest = n;
    while rest != 0 {
        if rest & 1 != 0 {
            result = multmodp(powers[k & 31], result);
        }
        rest >>= 1;
        k += 1;
    }
    !multmodp(result, !0u32)
}

/// The Adler-32 of n zero bytes: a stays 1, b counts the bytes.
pub fn adler32_of_zeros(n: u64) -> u32 {
    (((n % 65521) as u32) << 16) | 1
}

/// Adler-32 (RFC 1950).
pub fn adler32(payload: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in payload.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// A gzip member around a raw DEFLATE stream; `crc` and `size` describe the decoded data.
pub fn gzip_member(deflate: &[u8], crc: u32, size: u64) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    out.extend_from_slice(deflate);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out
}

/// A zlib stream around a raw DEFLATE stream.
pub fn zlib_wrap(deflate: &[u8], adler: u32) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    out.extend_from_slice(deflate);
    out.extend_from_slice(&adler.to_be_bytes());
    out
}

/// gzip around stored blocks.
pub fn gzip_stored(payload: &[u8]) -> Vec<u8> {
    gzip_member(&stored_deflate(payload), crc32(payload), payload.len() as u64)
}

/// zlib around stored blocks.
pub fn zlib_stored(payload: &[u8]) -> Vec<u8> {
    zlib_wrap(&stored_deflate(payload), adler32(payload))
}

// -- brotli (RFC 7932) ---------------------------------------------------------------------------------

/// The largest brotli meta-block this generator writes.
pub const BROTLI_METABLOCK_MAX: u64 = 1 << 24;
const BROTLI_MIN_COMMAND_BYTES: u64 = 4 + 2118;

fn brotli_window_bits(w: &mut BitWriter, wbits: u32) -> Result<(), GenError> {
    match wbits {
        16 => w.bits(0, 1),
        17 => {
            w.bits(1, 1);
            w.bits(0, 3);
            w.bits(0, 3);
        }
        18..=24 => {
            w.bits(1, 1);
            w.bits(u64::from(wbits - 17), 3);
        }
        10..=15 => {
            w.bits(1, 1);
            w.bits(0, 3);
            w.bits(u64::from(wbits - 8), 3);
        }
        _ => return fail("brotli window bits must be in 10..24"),
    }
    Ok(())
}

fn brotli_mlen(w: &mut BitWriter, mlen: u64) {
    let value = mlen - 1;
    w.bits(0, 1); // ISLAST
    if value < 1 << 16 {
        w.bits(0, 2);
        w.bits(value, 16);
    } else if value < 1 << 20 {
        w.bits(1, 2);
        w.bits(value, 20);
    } else {
        w.bits(2, 2);
        w.bits(value, 24);
    }
}

fn brotli_end(w: &mut BitWriter) {
    w.bits(1, 1); // ISLAST
    w.bits(1, 1); // ISLASTEMPTY
}

fn brotli_zeros_metablock(w: &mut BitWriter, mlen: u64) {
    brotli_mlen(w, mlen);
    w.bits(0, 1); // ISUNCOMPRESSED
    w.bits(0, 3); // NBLTYPESL, NBLTYPESI, NBLTYPESD = 1
    w.bits(0, 2); // NPOSTFIX
    w.bits(0, 4); // NDIRECT
    w.bits(0, 2); // context mode of the one literal block type
    w.bits(0, 2); // NTREESL = 1, NTREESD = 1
    for (symbol, symbol_bits) in [(0u64, 8u32), (423, 10), (0, 6)] {
        w.bits(1, 2); // HSKIP = 1: simple prefix code
        w.bits(0, 2); // NSYM - 1
        w.bits(symbol, symbol_bits);
    }
    w.bits(mlen - 4 - 2118, 24); // extra bits of copy length code 23
}

/// BrotliZeros: `size` zero bytes in a few bytes per 16 MiB meta-block.
pub fn brotli_zeros(size: u64, wbits: u32) -> Result<Vec<u8>, GenError> {
    let mut w = BitWriter::new();
    brotli_window_bits(&mut w, wbits)?;
    let mut left = size;
    while left > 0 {
        let mut chunk = left.min(BROTLI_METABLOCK_MAX);
        let remainder = left - chunk;
        if remainder > 0 && remainder < BROTLI_MIN_COMMAND_BYTES {
            chunk -= BROTLI_MIN_COMMAND_BYTES;
        }
        brotli_zeros_metablock(&mut w, chunk);
        left -= chunk;
    }
    brotli_end(&mut w);
    Ok(w.finish())
}

/// BrotliStored: uncompressed meta-blocks around `payload`.
pub fn brotli_stored(payload: &[u8], wbits: u32) -> Result<Vec<u8>, GenError> {
    let mut w = BitWriter::new();
    brotli_window_bits(&mut w, wbits)?;
    for chunk in payload.chunks(BROTLI_METABLOCK_MAX as usize) {
        brotli_mlen(&mut w, chunk.len() as u64);
        w.bits(1, 1); // ISUNCOMPRESSED
        w.align();
        w.raw(chunk);
    }
    brotli_end(&mut w);
    Ok(w.finish())
}

/// The reserved WBITS pattern 1000001 that announces a large-window stream.
pub fn brotli_large_window_prefix() -> Vec<u8> {
    vec![0x11, 0x00, 0x00, 0x00]
}

// -- zstd (RFC 8878) -----------------------------------------------------------------------------------

/// The largest zstd block.
pub const ZSTD_BLOCK_MAX: u64 = 128 * 1024;

/// Magic, descriptor and window descriptor of a frame without content size, dictionary or checksum.
pub fn zstd_header(window_log: u32) -> Result<Vec<u8>, GenError> {
    if !(10..=41).contains(&window_log) {
        return fail("zstd window log must be in 10..41");
    }
    Ok(vec![0x28, 0xb5, 0x2f, 0xfd, 0, ((window_log - 10) << 3) as u8])
}

fn zstd_block_header(last: bool, kind: u32, size: u64) -> [u8; 3] {
    let value = ((size as u32) << 3) | (kind << 1) | u32::from(last);
    [
        (value & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
    ]
}

/// The block size limit of a frame with this window log.
pub fn zstd_block_max(window_log: u32) -> u64 {
    if window_log >= 17 {
        ZSTD_BLOCK_MAX
    } else {
        1 << window_log
    }
}

/// RLE blocks of up to `block_max` bytes: 4 bytes per block, 32768:1 at 128 KiB.
pub fn zstd_rle_blocks(size: u64, block_max: u64, value: u8, last: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut left = size;
    loop {
        let chunk = left.min(block_max);
        left -= chunk;
        out.extend_from_slice(&zstd_block_header(last && left == 0, 1, chunk));
        out.push(value);
        if left == 0 {
            return out;
        }
    }
}

/// Raw blocks of up to `block_max` bytes.
pub fn zstd_raw_blocks(payload: &[u8], block_max: u64, last: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let end = payload.len().min(pos + block_max as usize);
        out.extend_from_slice(&zstd_block_header(last && end >= payload.len(), 0, (end - pos) as u64));
        out.extend_from_slice(&payload[pos..end]);
        pos = end;
        if pos >= payload.len() {
            return out;
        }
    }
}

/// ZstdZeros: `size` zero bytes in RLE blocks.
pub fn zstd_zeros(size: u64, window_log: u32) -> Result<Vec<u8>, GenError> {
    let mut out = zstd_header(window_log)?;
    out.extend(zstd_rle_blocks(size, zstd_block_max(window_log), 0, true));
    Ok(out)
}

/// ZstdStored: `payload` in raw blocks.
pub fn zstd_stored(payload: &[u8], window_log: u32) -> Result<Vec<u8>, GenError> {
    let mut out = zstd_header(window_log)?;
    out.extend(zstd_raw_blocks(payload, zstd_block_max(window_log), true));
    Ok(out)
}

/// A skippable frame with `n` zero bytes of payload.
pub fn zstd_skippable(n: u32) -> Vec<u8> {
    let mut out = vec![0x50, 0x2a, 0x4d, 0x18];
    out.extend_from_slice(&n.to_le_bytes());
    out.resize(out.len() + n as usize, 0);
    out
}

// -- generator specs -----------------------------------------------------------------------------------

fn zeros_stream(codec: &str, matches: u64) -> Result<Vec<u8>, GenError> {
    let size = zeros_decoded_size(matches);
    let deflate = zeros_deflate(matches);
    match codec {
        "gzip" => Ok(gzip_member(&deflate, crc32_of_zeros(size), size)),
        "zlib" => Ok(zlib_wrap(&deflate, adler32_of_zeros(size))),
        "raw" => Ok(deflate),
        other => fail(format!("zeros generator for codec {other}")),
    }
}

fn wrap_once(codec: &str, payload: &[u8], window: u32) -> Result<Vec<u8>, GenError> {
    match codec {
        "br" => brotli_stored(payload, window),
        "zstd" => zstd_stored(payload, window),
        "gzip" => Ok(gzip_stored(payload)),
        "zlib" => Ok(zlib_stored(payload)),
        "raw" => Ok(stored_deflate(payload)),
        other => fail(format!("wrap generator for codec {other}")),
    }
}

/// Build the compressed stream a generator spec describes.
pub fn generate(spec: &Spec) -> Result<Vec<u8>, GenError> {
    match spec {
        Spec::Zeros {
            codec,
            matches,
            size,
            window,
        } => match codec.as_str() {
            "br" => brotli_zeros(*size, *window),
            "zstd" => zstd_zeros(*size, *window),
            other => zeros_stream(other, *matches),
        },
        Spec::Data {
            codec,
            seed,
            size,
            window,
        } => {
            let size = usize::try_from(*size).or_else(|_| fail("data size too large"))?;
            wrap_once(codec, &data(*seed, size), *window)
        }
        Spec::Wrap {
            codec,
            times,
            inner,
            window,
        } => {
            let mut stream = generate(inner)?;
            for _ in 0..*times {
                stream = wrap_once(codec, &stream, *window)?;
            }
            Ok(stream)
        }
    }
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_of_zeros_matches_the_table_crc() {
        for n in [0u64, 1, 2, 7, 8, 255, 256, 1000, 65537, 1 << 20] {
            assert_eq!(crc32_of_zeros(n), crc32(&vec![0u8; n as usize]), "n = {n}");
        }
    }

    #[test]
    fn known_checksums() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(adler32_of_zeros(10), adler32(&[0u8; 10]));
    }

    #[test]
    fn the_manifest_hashes_match() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
        let text = std::fs::read_to_string(root.join("manifest.json")).expect("manifest");
        let manifest: serde_json::Value = serde_json::from_str(&text).expect("json");
        let vectors = manifest["vectors"].as_array().expect("vectors");
        let (mut checked, mut bad) = (0, Vec::new());
        for vector in vectors {
            let id = vector["id"].as_str().expect("id");
            let input = &vector["input"];
            let want = input["sha256"].as_str().expect("sha256");
            let stream = match input.get("generator") {
                Some(g) => {
                    let spec = json_spec::parse(g).expect("spec");
                    generate(&spec).expect("generate")
                }
                None => std::fs::read(root.join(input["file"].as_str().expect("file"))).expect("file"),
            };
            checked += 1;
            if sha256_hex(&stream) != want {
                bad.push(id.to_string());
            }
        }
        println!("manifest inputs checked: {checked}, mismatches: {bad:?}");
        assert!(bad.is_empty(), "mismatching inputs: {bad:?}");
    }
}
