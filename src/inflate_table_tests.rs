//! Tests of the decoding tables of the DEFLATE decoder: a structured generator of dynamic-block
//! streams (hand-written encoder, length-limited codes up to 15 bits, every run-length code),
//! long codes through the slow path at every bit alignment, and the CPU cost of building tables
//! (many empty dynamic blocks with depth-15 codes). The reference is flate2.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{BufRead, Read};

use super::*;

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64).max(1)) as usize
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
    fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

/// A bit writer (least significant bit first).
struct BitW {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitW {
    fn new() -> BitW {
        BitW {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }
    fn put(&mut self, value: u32, n: u32) {
        self.acc |= u64::from(value) << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    /// A Huffman code: most significant bit first.
    fn code(&mut self, value: u32, n: u32) {
        assert!(n > 0, "a symbol without a code");
        let reversed = value.reverse_bits() >> (32 - n);
        self.put(reversed, n);
    }
    fn align(&mut self) {
        if self.n > 0 {
            self.out.push(self.acc as u8);
            self.acc = 0;
            self.n = 0;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}

fn canonical_codes(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 17];
    for &l in lengths {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 17];
    let mut code = 0;
    for l in 1..=15 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            if l == 0 {
                0
            } else {
                let c = next[usize::from(l)];
                next[usize::from(l)] += 1;
                c
            }
        })
        .collect()
}

/// The lengths of a random complete prefix code with `n` leaves, none deeper than `limit`. Half of
/// the splits go to the deepest leaf, so deep (chain-like) shapes are common.
fn random_complete_lengths(rng: &mut Rng, n: usize, limit: u8) -> Vec<u8> {
    let mut limit = limit;
    while (1usize << limit) < n {
        limit += 1;
    }
    if n == 1 {
        return vec![1];
    }
    let mut leaves = vec![0u8];
    while leaves.len() < n {
        let candidates: Vec<usize> = (0..leaves.len()).filter(|&i| leaves[i] < limit).collect();
        let index = if rng.chance(1, 2) {
            *candidates.iter().max_by_key(|&&i| leaves[i]).unwrap()
        } else {
            candidates[rng.below(candidates.len())]
        };
        let depth = leaves.swap_remove(index);
        leaves.push(depth + 1);
        leaves.push(depth + 1);
    }
    rng.shuffle(&mut leaves);
    leaves
}

/// Code lengths for an alphabet of `size` symbols with the given used symbols.
fn lengths_for(rng: &mut Rng, size: usize, used: &[usize], limit: u8) -> Vec<u8> {
    let mut lengths = vec![0u8; size];
    if used.is_empty() {
        return lengths;
    }
    let shape = random_complete_lengths(rng, used.len(), limit);
    for (&symbol, &length) in used.iter().zip(shape.iter()) {
        lengths[symbol] = length;
    }
    lengths
}

fn choose(rng: &mut Rng, size: usize, n: usize, must: Option<usize>) -> Vec<usize> {
    let mut all: Vec<usize> = (0..size).filter(|&s| Some(s) != must).collect();
    rng.shuffle(&mut all);
    let mut used: Vec<usize> = must.into_iter().collect();
    used.extend(all.into_iter().take(n - used.len()));
    used
}

#[derive(Clone, Copy, Debug)]
enum Tok {
    Lit(u8),
    Match {
        lcode: usize,
        lextra: u32,
        dcode: usize,
        dextra: u32,
    },
}

/// Draw `count` tokens that use only symbols with a code; `out` is the data produced so far (the
/// reference model: it is extended by every token).
fn gen_tokens(rng: &mut Rng, out: &mut Vec<u8>, lit: &[u8], dist: &[u8], count: usize) -> Vec<Tok> {
    let lit_syms: Vec<usize> = (0..lit.len().min(286)).filter(|&s| s != 256 && lit[s] != 0).collect();
    let dist_syms: Vec<usize> = (0..dist.len().min(30)).filter(|&s| dist[s] != 0).collect();
    let mut toks = Vec::new();
    for _ in 0..count {
        if lit_syms.is_empty() {
            break;
        }
        let sym = lit_syms[rng.below(lit_syms.len())];
        if sym < 256 {
            out.push(sym as u8);
            toks.push(Tok::Lit(sym as u8));
            continue;
        }
        let lcode = sym - 257;
        if lcode >= 29 {
            continue;
        }
        let possible: Vec<usize> = dist_syms
            .iter()
            .copied()
            .filter(|&d| usize::from(DISTANCE_BASE[d]) <= out.len())
            .collect();
        if possible.is_empty() {
            continue;
        }
        let dcode = possible[rng.below(possible.len())];
        let dmax = (1usize << DISTANCE_EXTRA_BITS[dcode]) - 1;
        let dextra = rng.below(dmax.min(out.len() - usize::from(DISTANCE_BASE[dcode])) + 1) as u32;
        let lmax = if lcode == 27 {
            30
        } else {
            (1usize << LENGTH_EXTRA_BITS[lcode]) - 1
        };
        let lextra = rng.below(lmax + 1) as u32;
        let len = usize::from(LENGTH_BASE[lcode]) + lextra as usize;
        let distance = usize::from(DISTANCE_BASE[dcode]) + dextra as usize;
        for _ in 0..len {
            let b = out[out.len() - distance];
            out.push(b);
        }
        toks.push(Tok::Match {
            lcode,
            lextra,
            dcode,
            dextra,
        });
    }
    toks
}

fn emit_tokens(w: &mut BitW, lit: &[u8], dist: &[u8], toks: &[Tok]) {
    let lit_codes = canonical_codes(lit);
    let dist_codes = canonical_codes(dist);
    for tok in toks {
        match *tok {
            Tok::Lit(b) => w.code(lit_codes[usize::from(b)], u32::from(lit[usize::from(b)])),
            Tok::Match {
                lcode,
                lextra,
                dcode,
                dextra,
            } => {
                let s = 257 + lcode;
                w.code(lit_codes[s], u32::from(lit[s]));
                w.put(lextra, u32::from(LENGTH_EXTRA_BITS[lcode]));
                w.code(dist_codes[dcode], u32::from(dist[dcode]));
                w.put(dextra, u32::from(DISTANCE_EXTRA_BITS[dcode]));
            }
        }
    }
    w.code(lit_codes[256], u32::from(lit[256]));
}

/// One run-length token of the code length sequence.
#[derive(Clone, Copy)]
struct Rle {
    symbol: usize,
    extra: u32,
    extra_bits: u32,
}

/// Run-length code `seq` at random with every code (16 repeats the previous length, including
/// the zero a run of 17/18 or a plain 0 left behind).
fn random_rle(rng: &mut Rng, seq: &[u8]) -> Vec<Rle> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < seq.len() {
        let v = seq[i];
        let run = seq[i..].iter().take(138).take_while(|&&x| x == v).count();
        let mut options: Vec<(usize, usize)> = Vec::new(); // (symbol, count)
        if v == 0 && run >= 11 {
            options.push((18, rng.range(11, run)));
        }
        if v == 0 && run >= 3 {
            options.push((17, rng.range(3, run.min(10))));
        }
        if i > 0 && seq[i - 1] == v && run >= 3 {
            options.push((16, rng.range(3, run.min(6))));
        }
        if !options.is_empty() && rng.chance(4, 5) {
            let (symbol, count) = options[rng.below(options.len())];
            let (extra, extra_bits) = match symbol {
                16 => (count - 3, 2),
                17 => (count - 3, 3),
                _ => (count - 11, 7),
            };
            out.push(Rle {
                symbol,
                extra: extra as u32,
                extra_bits,
            });
            i += count;
        } else {
            out.push(Rle {
                symbol: usize::from(v),
                extra: 0,
                extra_bits: 0,
            });
            i += 1;
        }
    }
    out
}

/// A dynamic block with the given literal/length and distance code lengths (`lit.len()` is HLIT,
/// `dist.len()` is HDIST).
fn write_dynamic(w: &mut BitW, rng: &mut Rng, last: bool, lit: &[u8], dist: &[u8], toks: &[Tok]) {
    let mut seq = lit.to_vec();
    seq.extend_from_slice(dist);
    let rle = random_rle(rng, &seq);
    let mut used: Vec<usize> = Vec::new();
    for t in &rle {
        if !used.contains(&t.symbol) {
            used.push(t.symbol);
        }
    }
    while used.len() < 2 {
        let s = rng.below(19);
        if !used.contains(&s) {
            used.push(s);
        }
    }
    let cl = lengths_for(rng, 19, &used, 7);
    let cl_codes = canonical_codes(&cl);
    let last_used = CODE_LENGTH_ORDER
        .iter()
        .rposition(|&s| cl[usize::from(s)] != 0)
        .unwrap();
    let hclen = (last_used + 1).max(4) + rng.below(19 - (last_used + 1).max(4) + 1);
    w.put(u32::from(last), 1);
    w.put(2, 2);
    w.put((lit.len() - 257) as u32, 5);
    w.put((dist.len() - 1) as u32, 5);
    w.put((hclen - 4) as u32, 4);
    for &s in CODE_LENGTH_ORDER.iter().take(hclen) {
        w.put(u32::from(cl[usize::from(s)]), 3);
    }
    for t in &rle {
        w.code(cl_codes[t.symbol], u32::from(cl[t.symbol]));
        w.put(t.extra, t.extra_bits);
    }
    emit_tokens(w, lit, dist, toks);
}

fn fixed_lengths() -> (Vec<u8>, Vec<u8>) {
    let mut lit = vec![8u8; 288];
    lit[144..256].fill(9);
    lit[256..280].fill(7);
    (lit, vec![5u8; 30])
}

/// A random stream of stored, fixed and dynamic blocks. Returns it with the data it decodes to.
fn gen_stream(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    let mut w = BitW::new();
    let mut out: Vec<u8> = Vec::new();
    let blocks = rng.range(1, 5);
    for b in 0..blocks {
        let last = b + 1 == blocks;
        match rng.below(6) {
            0 => {
                w.put(u32::from(last), 1);
                w.put(0, 2);
                w.align();
                let n = rng.below(300);
                let data: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                w.put(n as u32, 16);
                w.put(!(n as u32) & 0xffff, 16);
                for &byte in &data {
                    w.put(u32::from(byte), 8);
                }
                out.extend_from_slice(&data);
            }
            1 => {
                let (lit, dist) = fixed_lengths();
                let count = rng.below(300);
                let toks = gen_tokens(rng, &mut out, &lit[..286], &dist, count);
                w.put(u32::from(last), 1);
                w.put(1, 2);
                emit_tokens(&mut w, &lit, &dist, &toks);
            }
            _ => {
                let hlit = rng.range(257, 286);
                let hdist = rng.range(1, 30);
                let n_lit = if rng.chance(1, 2) {
                    rng.range(1, 24.min(hlit))
                } else {
                    rng.range(1, hlit)
                };
                let limit = if rng.chance(2, 3) { 15 } else { rng.range(6, 15) as u8 };
                let used = choose(rng, hlit, n_lit, Some(256));
                let lit = lengths_for(rng, hlit, &used, limit);
                let dist_cap = if rng.chance(1, 2) { 8 } else { 30 };
                let n_dist = rng.range(0, hdist.min(dist_cap));
                let used = choose(rng, hdist, n_dist, None);
                let dist = lengths_for(rng, hdist, &used, limit);
                let count = rng.below(400);
                let toks = gen_tokens(rng, &mut out, &lit, &dist, count);
                write_dynamic(&mut w, rng, last, &lit, &dist, &toks);
            }
        }
    }
    (w.finish(), out)
}

/// A `BufRead` offering at most `chunk` bytes at a time that fails on over-consumption.
struct Slice<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
    avail: usize,
}

impl Read for Slice<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = {
            let rest = self.fill_buf()?;
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Slice<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let end = self.pos.saturating_add(self.chunk).min(self.data.len());
        self.avail = end - self.pos;
        Ok(&self.data[self.pos..end])
    }
    fn consume(&mut self, amount: usize) {
        assert!(amount <= self.avail, "consumed more than offered");
        self.avail -= amount;
        self.pos += amount;
    }
}

/// Decode with our inflater. Returns the outcome (the error as text) and the bytes consumed.
fn ours(data: &[u8], chunk: usize, read_size: usize) -> (Result<Vec<u8>, String>, usize) {
    let mut input = Slice {
        data,
        pos: 0,
        chunk,
        avail: 0,
    };
    let mut inflater = Inflater::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; read_size];
    let result = loop {
        match inflater.read(&mut input, &mut buf) {
            Ok(0) => break Ok(out),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                assert!(out.len() < 1 << 26, "runaway output");
            }
            Err(e) => break Err(e.to_string()),
        }
    };
    (result, input.pos)
}

fn reference(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut out)
        .map(|_| out)
        .map_err(|e| e.to_string())
}

fn rounds() -> usize {
    std::env::var("SPILLGATE_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 1500 } else { 20_000 })
}

const CHUNKS: [usize; 6] = [1, 2, 3, 7, 64, usize::MAX];
const READ_SIZES: [usize; 6] = [1, 2, 5, 64, 4096, 70_000];

fn mutate(rng: &mut Rng, stream: &[u8]) -> Vec<u8> {
    let mut m = stream.to_vec();
    for _ in 0..rng.range(1, 3) {
        if m.is_empty() {
            break;
        }
        let i = rng.below(m.len());
        match rng.below(6) {
            0 | 1 => m[i] ^= 1 << rng.below(8),
            2 => m[i] = rng.next() as u8,
            3 => m.truncate(i),
            4 => {
                m.remove(i);
            }
            _ => m.insert(i, rng.next() as u8),
        }
    }
    m
}

// ---------------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------------

#[test]
fn generated_dynamic_streams_match_the_model_and_flate2_and_mutants_agree_with_flate2() {
    let mut accepted_mutants = 0usize;
    let mut far_back = 0usize;
    for round in 0..rounds() {
        let mut rng = Rng::new(round as u64 + 1);
        let (stream, expected) = gen_stream(&mut rng);
        assert_eq!(
            reference(&stream).as_ref(),
            Ok(&expected),
            "round {round}: generator and flate2 disagree"
        );
        let mut data = stream.clone();
        data.extend_from_slice(&[0xa5, 0x5a, 0x33]);
        for _ in 0..3 {
            let chunk = CHUNKS[rng.below(CHUNKS.len())];
            let read_size = READ_SIZES[rng.below(READ_SIZES.len())];
            let (result, consumed) = ours(&data, chunk, read_size);
            assert_eq!(
                result.as_ref(),
                Ok(&expected),
                "round {round} chunk {chunk} read {read_size}"
            );
            assert_eq!(consumed, stream.len(), "round {round} chunk {chunk}: leftover");
        }
        for _ in 0..2 {
            let m = mutate(&mut rng, &stream);
            let chunk = CHUNKS[rng.below(CHUNKS.len())];
            let read_size = READ_SIZES[rng.below(READ_SIZES.len())];
            let (a, _) = ours(&m, chunk, read_size);
            let (b, _) = ours(&m, usize::MAX, 70_000);
            assert_eq!(a, b, "round {round}: a mutant decodes differently with other chunking");
            let r = reference(&m);
            match (&a, &r) {
                (Ok(x), Ok(y)) => {
                    assert_eq!(x, y, "round {round}: mutant output differs from flate2");
                    accepted_mutants += 1;
                }
                (Err(_), Err(_)) => {}
                (Err(e), Ok(_)) => {
                    assert!(
                        e.contains("distance too far back"),
                        "round {round}: only we reject: {e}"
                    );
                    far_back += 1;
                }
                (Ok(_), Err(e)) => panic!("round {round}: only flate2 rejects ({e}); mutant {m:02x?}"),
            }
        }
    }
    eprintln!("mutants accepted by both: {accepted_mutants}, distance-before-start differences: {far_back}");
}

/// Build a stream with `prefix` 9-bit literals (a fixed block) first so the dynamic block starts at
/// bit offset (2 + prefix) % 8, then the dynamic block with the given codes.
fn long_code_stream(rng: &mut Rng, prefix: usize, lit: &[u8], dist: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut w = BitW::new();
    let mut out = Vec::new();
    w.put(0, 1);
    w.put(1, 2);
    for _ in 0..prefix {
        w.code(0x190, 9); // literal 144
    }
    out.extend(std::iter::repeat_n(144u8, prefix));
    w.code(0, 7); // end of block
    let toks = gen_tokens(rng, &mut out, lit, dist, 3000);
    write_dynamic(&mut w, rng, true, lit, dist, &toks);
    (w.finish(), out)
}

#[test]
fn long_codes_decode_at_every_alignment_and_in_one_byte_chunks() {
    // Chain trees: lengths 1, 2, ..., 14, 15, 15 over 16 symbols (every length 11..15 occurs).
    let chain: Vec<u8> = (1..=15).chain(std::iter::once(15)).collect();
    for round in 0..40 {
        let mut rng = Rng::new(1000 + round);
        // literal/length: end of block, 8 literals and 7 length symbols in random order
        let mut syms: Vec<usize> = vec![
            256, 257, 258, 259, 260, 261, 262, 263, 10, 20, 30, 200, 201, 202, 203, 255,
        ];
        rng.shuffle(&mut syms);
        let mut lit = vec![0u8; 264];
        for (&s, &l) in syms.iter().zip(chain.iter()) {
            lit[s] = l;
        }
        let mut dsyms: Vec<usize> = (0..16).collect();
        rng.shuffle(&mut dsyms);
        let mut dist = vec![0u8; 16];
        for (&s, &l) in dsyms.iter().zip(chain.iter()) {
            dist[s] = l;
        }
        for prefix in 0..8 {
            let (stream, expected) = long_code_stream(&mut rng, prefix, &lit, &dist);
            assert_eq!(reference(&stream).as_ref(), Ok(&expected));
            let mut data = stream.clone();
            data.extend_from_slice(&[0xff, 0x00]);
            for (chunk, read_size) in [(1, 1), (1, 4096), (3, 7), (usize::MAX, 70_000), (usize::MAX, 1)] {
                let (result, consumed) = ours(&data, chunk, read_size);
                assert_eq!(
                    result.as_ref(),
                    Ok(&expected),
                    "prefix {prefix} chunk {chunk} read {read_size}"
                );
                assert_eq!(consumed, stream.len());
            }
        }
    }
}

#[test]
fn long_code_tables_resolve_every_symbol_directly() {
    // The table itself: every code of a deep tree decodes to its symbol with exactly its length,
    // for any bits that follow, and a too short bit count asks for more input.
    let mut rng = Rng::new(77);
    for _ in 0..200 {
        let n = rng.range(2, 286);
        let used = choose(&mut rng, 286, n, None);
        let lengths = lengths_for(&mut rng, 286, &used, 15);
        let codes = canonical_codes(&lengths);
        let mut table = Table::new(LIT_ROOT_BITS);
        assert!(table.build(&lengths, true));
        for s in 0..286 {
            let l = u32::from(lengths[s]);
            if l == 0 {
                continue;
            }
            let reversed = u64::from(codes[s].reverse_bits() >> (32 - l));
            for tail in [0u64, 0x7fff, 0x2a5a] {
                let bitbuf = reversed | (tail << l);
                let entry = table.decode(bitbuf, 15);
                assert_eq!(entry, ((s as u32) << 4) | l);
                if l > 1 {
                    // one bit short of the code: no complete shorter code can be found in it
                    let e = table.decode(bitbuf & ((1 << (l - 1)) - 1), l - 1);
                    assert!(e == NEED_MORE || (e & 15) > l - 1, "short read gave {e:#x}");
                }
            }
        }
    }
}

#[test]
fn identical_code_lengths_skip_the_rebuild_but_changes_are_seen() {
    let mut table = Table::new(LIT_ROOT_BITS);
    let a = [1u8, 2, 3, 3];
    let b = [2u8, 2, 2, 2];
    assert!(table.build(&a, false));
    let first = table.decode(0b1, 15);
    assert!(table.build(&a, false));
    assert_eq!(table.decode(0b1, 15), first);
    assert!(table.build(&b, false));
    assert_ne!(table.decode(0b1, 15), first);
    assert!(!table.build(&[1u8, 1, 1], false), "oversubscribed");
    assert!(!table.build(&[1u8, 1, 1], false), "still rejected, not cached");
    assert!(!table.build(&[2u8, 2], true), "incomplete except one code of length 1");
    assert!(table.build(&[1u8], true));
    assert!(!table.build(&[1u8], false));
    assert!(table.build(&a, false));
}

/// `n` random symbols of `lo..=hi` (and `must`).
fn clustered(rng: &mut Rng, lo: usize, hi: usize, n: usize, must: Option<usize>) -> Vec<usize> {
    let mut pool: Vec<usize> = (lo..=hi).filter(|&s| Some(s) != must).collect();
    rng.shuffle(&mut pool);
    let mut used: Vec<usize> = must.into_iter().collect();
    used.extend(pool.into_iter().take(n - used.len()));
    used
}

/// `blocks` empty dynamic blocks whose literal/length and distance codes are depth 15 (a chain),
/// with a different symbol assignment per block (so no block repeats the previous lengths), then an
/// empty final fixed block.
fn worst_case_stream(blocks: usize) -> Vec<u8> {
    let chain: Vec<u8> = (1..=15).chain(std::iter::once(15)).collect();
    let mut rng = Rng::new(5);
    let mut w = BitW::new();
    for _ in 0..blocks {
        let used = clustered(&mut rng, 250, 270, 16, Some(256));
        let mut lit = vec![0u8; 286];
        for (&s, &l) in used.iter().zip(chain.iter()) {
            lit[s] = l;
        }
        let used = clustered(&mut rng, 0, 19, 16, None);
        let mut dist = vec![0u8; 30];
        for (&s, &l) in used.iter().zip(chain.iter()) {
            dist[s] = l;
        }
        write_dynamic(&mut w, &mut rng, false, &lit, &dist, &[]);
    }
    w.put(1, 1);
    w.put(1, 2);
    w.code(0, 7);
    w.finish()
}

#[test]
fn many_empty_dynamic_blocks_with_depth_15_codes_are_cheap() {
    let perf = std::env::var("SPILLGATE_PERF").is_ok_and(|v| !["", "0"].contains(&v.as_str()));
    let timed = perf || !cfg!(debug_assertions);
    let blocks = if timed { 200_000 } else { 3_000 };
    let stream = worst_case_stream(blocks);
    let started = std::time::Instant::now();
    let (result, consumed) = ours(&stream, usize::MAX, 65_536);
    let secs = started.elapsed().as_secs_f64();
    assert_eq!(result, Ok(Vec::new()));
    assert_eq!(consumed, stream.len());
    eprintln!(
        "{blocks} empty depth-15 blocks, {} input bytes ({:.1} per block): {secs:.3} s, {:.3} us per input byte",
        stream.len(),
        stream.len() as f64 / blocks as f64,
        secs * 1e6 / stream.len() as f64
    );
    if timed {
        assert!(secs < 1.5, "table building is a CPU amplifier again: {secs:.2} s");
    }
}
