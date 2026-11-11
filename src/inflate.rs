//! A resumable raw-DEFLATE decoder (RFC 1951) with exact input accounting.
//!
//! The decoder works like zlib's `inflate()`: the caller passes an input window and an output
//! buffer of any size, it stops when either is exhausted and remembers where it was. Memory is a
//! 32 KiB window and five small code tables (about 10 KiB), whatever the data (SG-R-MEM-01). Nothing is
//! sized from a value in the stream (SG-R-CDC-07).
//!
//! Input accounting: bytes are pulled into a bit buffer, but at the end of every step the whole
//! bytes the stream did not need yet are handed back (they are simply not consumed from the
//! `BufRead`). So after the final block exactly the bytes of the stream are consumed and the
//! trailer of a gzip or zlib stream starts at the next byte of the input.

use std::io::BufRead;

use crate::error::{Error, ErrorKind};

const WINDOW_SIZE: usize = 1 << 15;
const WINDOW_MASK: usize = WINDOW_SIZE - 1;
const MAX_BITS: u32 = 15;
/// Length extra (5) + distance code (15) + distance extra (13).
const FAST_MATCH_BITS: u32 = 33;
/// Largest literal/length symbol count (HLIT + 257) and distance symbol count (HDIST + 1).
const MAX_LIT_SYMBOLS: usize = 286;
const MAX_DIST_SYMBOLS: usize = 30;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];
const CODE_LENGTH_ORDER: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    BlockHeader,
    StoredLength,
    StoredComplement,
    StoredCopy,
    DynCounts,
    DynCodeLengths,
    DynSymbols,
    DynRepeat,
    Symbol,
    LengthExtra,
    DistSymbol,
    DistExtra,
    Copy,
    Finished,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    NeedInput,
    OutputFull,
    Done,
}

/// Returned by [`Table::decode`] when too few bits are buffered to resolve the code yet.
const NEED_MORE: u32 = 1 << 31;
/// Root table widths (bits resolved by one lookup) for literal/length, distance and code-length codes.
const LIT_ROOT_BITS: u32 = 10;
const DIST_ROOT_BITS: u32 = 8;
const CL_ROOT_BITS: u32 = 7;
/// Largest alphabet of any table (fixed literal/length: 288).
const MAX_SYMBOLS: usize = 288;

/// A decoding table. `root[bits & mask]` is `symbol << 4 | length` for every code of at most
/// `root_bits` bits and 0 otherwise. Longer codes are resolved bit by bit from the canonical-code
/// bookkeeping (count per length, symbols sorted by code), as in zlib's `puff.c`. Building costs
/// O(symbols + 2^root_bits), whatever the longest code length (SG-R-CDC-07).
struct Table {
    root: Vec<u16>,
    root_bits: u32,
    mask: usize,
    /// The length of the longest code. A root miss is invalid once that many bits are real.
    bits: u32,
    counts: [u16; MAX_BITS as usize + 1],
    sorted: [u16; MAX_SYMBOLS],
    /// The code lengths this table was built from, and whether that build succeeded: an identical
    /// set is not rebuilt.
    built: [u8; MAX_SYMBOLS],
    built_len: usize,
    built_incomplete_ok: bool,
    valid: bool,
}

impl Table {
    fn new(root_bits: u32) -> Table {
        Table {
            root: vec![0; 1usize << root_bits],
            root_bits,
            mask: (1usize << root_bits) - 1,
            bits: 0,
            counts: [0; MAX_BITS as usize + 1],
            sorted: [0; MAX_SYMBOLS],
            built: [0; MAX_SYMBOLS],
            built_len: 0,
            built_incomplete_ok: false,
            valid: false,
        }
    }

    /// The entry for the code at the bottom of `bitbuf` (`bitcount` real bits): `symbol << 4 | length`
    /// (the length may exceed `bitcount`: the caller checks), 0 for an invalid code, `NEED_MORE`
    /// if more bits are needed to tell.
    #[inline(always)]
    fn decode(&self, bitbuf: u64, bitcount: u32) -> u32 {
        // `mask` is below the size of `root`; a miss would read as an unassigned slot.
        let entry = u32::from(self.root.get((bitbuf as usize) & self.mask).copied().unwrap_or(0));
        if entry != 0 {
            return entry;
        }
        self.decode_slow(bitbuf, bitcount)
    }

    /// A root miss: a code longer than the root (continue bit by bit) or an unassigned one.
    #[cold]
    #[inline(never)]
    fn decode_slow(&self, bitbuf: u64, bitcount: u32) -> u32 {
        if self.bits <= self.root_bits {
            // Every code fits the root, so the slot is unassigned: invalid once all bits are real.
            return if bitcount >= self.bits { 0 } else { NEED_MORE };
        }
        // Canonical decoding, first stream bit = most significant code bit.
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0u32;
        for length in 1..=self.bits {
            if length > bitcount {
                return NEED_MORE;
            }
            code |= ((bitbuf >> (length - 1)) & 1) as u32;
            let count = u32::from(self.counts.get(length as usize).copied().unwrap_or(0));
            if code < first + count {
                let symbol = self.sorted.get((index + code - first) as usize).copied().unwrap_or(0);
                return (u32::from(symbol) << 4) | length;
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        0
    }

    /// Build a canonical Huffman decoding table from code lengths (RFC 1951 section 3.2.2).
    /// Returns false for an over-subscribed set, and for an incomplete one unless it is the single
    /// code of length 1 that zlib also accepts (`allow_incomplete`), or there are no codes at all.
    fn build(&mut self, lengths: &[u8], allow_incomplete: bool) -> bool {
        if self.valid
            && self.built_incomplete_ok == allow_incomplete
            && self.built.get(..self.built_len) == Some(lengths)
        {
            return true; // the same code lengths as the previous block: the table is current
        }
        self.valid = false;
        if lengths.len() > MAX_SYMBOLS {
            return false;
        }
        let mut per_length = [0u16; MAX_BITS as usize + 1];
        let mut max_length = 0u32;
        for &length in lengths {
            match per_length.get_mut(usize::from(length)) {
                Some(count) => *count += 1,
                None => return false,
            }
            max_length = max_length.max(u32::from(length));
        }
        per_length[0] = 0;
        self.counts = per_length;
        self.bits = max_length;
        self.root.fill(0);
        if max_length > 0 {
            let mut left: i32 = 1;
            for &count in per_length.iter().skip(1) {
                left = (left << 1) - i32::from(count);
                if left < 0 {
                    return false; // over-subscribed
                }
            }
            if left > 0 && !(allow_incomplete && max_length == 1) {
                return false; // incomplete
            }
            let mut next_code = [0u32; MAX_BITS as usize + 2];
            let mut offsets = [0u16; MAX_BITS as usize + 2];
            let mut code = 0u32;
            let mut offset = 0u16;
            for length in 1..=MAX_BITS as usize {
                let before = per_length.get(length - 1).copied().unwrap_or(0);
                code = (code + u32::from(before)) << 1;
                offset += before;
                if let Some(slot) = next_code.get_mut(length) {
                    *slot = code;
                }
                if let Some(slot) = offsets.get_mut(length) {
                    *slot = offset;
                }
            }
            let root_size = 1usize << self.root_bits;
            for (symbol, &length) in lengths.iter().enumerate() {
                if length == 0 {
                    continue;
                }
                let l = usize::from(length);
                if let Some(off) = offsets.get_mut(l) {
                    if let Some(slot) = self.sorted.get_mut(usize::from(*off)) {
                        *slot = symbol as u16;
                    }
                    *off += 1;
                }
                if u32::from(length) > self.root_bits {
                    continue;
                }
                let Some(next) = next_code.get_mut(l) else {
                    return false;
                };
                let value = *next;
                *next += 1;
                // DEFLATE packs Huffman codes most significant bit first into a least-significant-first stream.
                let reversed = (value as u16).reverse_bits() >> (16 - u32::from(length));
                let entry = ((symbol as u16) << 4) | u16::from(length);
                let step = 1usize << length;
                let mut index = usize::from(reversed);
                while index < root_size {
                    if let Some(slot) = self.root.get_mut(index) {
                        *slot = entry;
                    }
                    index += step;
                }
            }
        }
        if let Some(dst) = self.built.get_mut(..lengths.len()) {
            dst.copy_from_slice(lengths);
        }
        self.built_len = lengths.len();
        self.built_incomplete_ok = allow_incomplete;
        self.valid = true;
        true
    }
}

/// The resumable decoder. One value serves any number of streams (call [`Inflater::reset`]).
pub(crate) struct Inflater {
    state: State,
    final_block: bool,
    use_fixed: bool,
    bitbuf: u64,
    bitcount: u32,

    window: Vec<u8>,
    window_pos: usize,
    window_filled: usize,

    stored_left: usize,

    lengths: [u8; MAX_LIT_SYMBOLS + MAX_DIST_SYMBOLS],
    code_length_lengths: [u8; 19],
    literal_count: usize,
    distance_count: usize,
    code_length_count: usize,
    code_length_index: usize,
    length_index: usize,
    repeat_symbol: u32,
    previous_length: u8,
    /// An error to return on the next call, after the bytes written before it were delivered.
    deferred: Option<Error>,

    code_length_table: Table,
    literal_table: Table,
    distance_table: Table,
    fixed_literal_table: Table,
    fixed_distance_table: Table,

    match_length: usize,
    match_distance: usize,
    symbol_code: usize,
}

fn corrupt(what: &str) -> Error {
    Error::corrupt(format!("deflate: {what}"))
}

impl Inflater {
    pub(crate) fn new() -> Inflater {
        let mut fixed_lengths = [8u8; 288 + 32];
        if let Some(s) = fixed_lengths.get_mut(144..256) {
            s.fill(9);
        }
        if let Some(s) = fixed_lengths.get_mut(256..280) {
            s.fill(7);
        }
        if let Some(s) = fixed_lengths.get_mut(288..) {
            s.fill(5); // 32 distance codes; symbols 30 and 31 are invalid when decoded
        }
        let mut fixed_literal_table = Table::new(LIT_ROOT_BITS);
        let mut fixed_distance_table = Table::new(DIST_ROOT_BITS);
        if let (Some(lit), Some(dist)) = (fixed_lengths.get(..288), fixed_lengths.get(288..)) {
            // Both sets are complete by construction.
            let _ = fixed_literal_table.build(lit, false);
            let _ = fixed_distance_table.build(dist, false);
        }
        Inflater {
            state: State::BlockHeader,
            final_block: false,
            use_fixed: false,
            bitbuf: 0,
            bitcount: 0,
            window: vec![0; WINDOW_SIZE],
            window_pos: 0,
            window_filled: 0,
            stored_left: 0,
            lengths: [0; MAX_LIT_SYMBOLS + MAX_DIST_SYMBOLS],
            code_length_lengths: [0; 19],
            literal_count: 0,
            distance_count: 0,
            code_length_count: 0,
            code_length_index: 0,
            length_index: 0,
            repeat_symbol: 0,
            previous_length: 0,
            deferred: None,
            code_length_table: Table::new(CL_ROOT_BITS),
            literal_table: Table::new(LIT_ROOT_BITS),
            distance_table: Table::new(DIST_ROOT_BITS),
            fixed_literal_table,
            fixed_distance_table,
            match_length: 0,
            match_distance: 0,
            symbol_code: 0,
        }
    }

    /// Start a new stream with the same memory (the next gzip member): no allocation.
    pub(crate) fn reset(&mut self) {
        self.state = State::BlockHeader;
        self.final_block = false;
        self.use_fixed = false;
        self.bitbuf = 0;
        self.bitcount = 0;
        self.window_pos = 0;
        self.window_filled = 0;
        self.stored_left = 0;
        self.deferred = None;
    }

    /// True once the final block has ended.
    #[cfg(test)]
    pub(crate) fn finished(&self) -> bool {
        self.state == State::Finished
    }

    /// An error found after `op` bytes were already written in this call: the bytes are delivered
    /// first and the error follows on the next call, so what is delivered before an error does not
    /// depend on the read size (SG-R-RDR-01).
    fn fail_after(&mut self, op: usize, error: Error) -> Result<usize, Error> {
        if op > 0 {
            self.deferred = Some(error);
            Ok(op)
        } else {
            Err(error)
        }
    }

    /// Decode into `out`. Returns the number of bytes written (at least 1 unless the stream
    /// ended); `Ok(0)` for a non-empty `out` means the final block ended and every byte of the
    /// stream, and none after it, has been consumed from `input`. A stream that ends early is
    /// `corrupt`.
    pub(crate) fn read(&mut self, input: &mut dyn BufRead, out: &mut [u8]) -> Result<usize, Error> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state {
                State::Finished => return Ok(0),
                State::Failed => {
                    return Err(self
                        .deferred
                        .take()
                        .unwrap_or_else(|| corrupt("the stream is already known to be invalid")));
                }
                _ => {}
            }
            let buf = input.fill_buf().map_err(Error::from_input)?;
            let at_end = buf.is_empty();
            let mut ip = 0usize;
            let mut op = 0usize;
            let result = self.run(buf, &mut ip, out, &mut op);
            let status = match result {
                Ok(status) => status,
                Err(e) => {
                    self.state = State::Failed;
                    input.consume(ip);
                    return self.fail_after(op, e);
                }
            };
            if status != Status::NeedInput {
                if let Err(e) = self.give_back(&mut ip, status == Status::Done) {
                    self.state = State::Failed;
                    input.consume(ip);
                    return self.fail_after(op, e);
                }
            }
            input.consume(ip);
            if op > 0 {
                return Ok(op);
            }
            match status {
                Status::Done => return Ok(0),
                Status::NeedInput => {
                    if at_end {
                        self.state = State::Failed;
                        return Err(corrupt("the stream ends too early"));
                    }
                    if ip == 0 {
                        self.state = State::Failed;
                        return Err(Error::new(ErrorKind::Internal, "deflate: no progress"));
                    }
                }
                Status::OutputFull => {
                    self.state = State::Failed;
                    return Err(Error::new(
                        ErrorKind::Internal,
                        "deflate: no progress with room in the output",
                    ));
                }
            }
        }
    }

    /// Hand the whole bytes the stream did not use back to the input: they are not consumed.
    fn give_back(&mut self, ip: &mut usize, done: bool) -> Result<(), Error> {
        let whole = (self.bitcount / 8) as usize;
        let k = whole.min(*ip);
        *ip -= k;
        self.bitcount -= (k as u32) * 8;
        self.bitbuf &= (1u64 << self.bitcount) - 1;
        if done {
            // What is left is the padding of the last byte.
            if self.bitcount >= 8 {
                return Err(Error::new(ErrorKind::Internal, "deflate: input accounting broke"));
            }
            self.bitbuf = 0;
            self.bitcount = 0;
        }
        Ok(())
    }

    // -- bit input ---------------------------------------------------------------------------

    /// Top the bit buffer up to at least 56 bits if the input allows.
    #[inline(always)]
    fn refill(&mut self, input: &[u8], ip: &mut usize) {
        let end = ip.saturating_add(8);
        if let Some(chunk) = input.get(*ip..end) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            let w = u64::from_le_bytes(word);
            self.bitbuf |= w << self.bitcount;
            let n = (63 - self.bitcount) >> 3;
            *ip += n as usize;
            self.bitcount += n * 8;
            self.bitbuf &= (1u64 << self.bitcount) - 1;
        } else {
            while self.bitcount < 56 {
                match input.get(*ip) {
                    Some(&b) => {
                        self.bitbuf |= u64::from(b) << self.bitcount;
                        self.bitcount += 8;
                        *ip += 1;
                    }
                    None => break,
                }
            }
        }
    }

    /// Make `n` bits (n <= 32) available if the input allows.
    #[inline(always)]
    fn ensure(&mut self, input: &[u8], ip: &mut usize, n: u32) -> bool {
        if self.bitcount < n {
            self.refill(input, ip);
        }
        self.bitcount >= n
    }

    #[inline(always)]
    fn take(&mut self, n: u32) -> u32 {
        let value = (self.bitbuf & ((1u64 << n) - 1)) as u32;
        self.bitbuf >>= n;
        self.bitcount -= n;
        value
    }

    // -- the state machine -------------------------------------------------------------------

    fn run(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize) -> Result<Status, Error> {
        loop {
            match self.state {
                State::BlockHeader => {
                    if self.final_block {
                        self.state = State::Finished;
                        continue;
                    }
                    if !self.ensure(inp, ip, 3) {
                        return Ok(Status::NeedInput);
                    }
                    self.final_block = self.take(1) == 1;
                    match self.take(2) {
                        0 => self.state = State::StoredLength,
                        1 => {
                            self.use_fixed = true;
                            self.state = State::Symbol;
                        }
                        2 => self.state = State::DynCounts,
                        _ => return Err(corrupt("invalid block type")),
                    }
                }
                State::StoredLength => {
                    let skip = self.bitcount & 7;
                    self.take(skip); // padding to the byte boundary
                    if !self.ensure(inp, ip, 16) {
                        return Ok(Status::NeedInput);
                    }
                    self.stored_left = self.take(16) as usize;
                    self.state = State::StoredComplement;
                }
                State::StoredComplement => {
                    if !self.ensure(inp, ip, 16) {
                        return Ok(Status::NeedInput);
                    }
                    if (self.stored_left as u32 ^ self.take(16)) != 0xffff {
                        return Err(corrupt("invalid stored block lengths"));
                    }
                    self.state = State::StoredCopy;
                }
                State::StoredCopy => {
                    // Whole bytes still in the bit buffer first (bitcount is a multiple of 8 here).
                    while self.stored_left > 0 && self.bitcount >= 8 {
                        if *op >= out.len() {
                            return Ok(Status::OutputFull);
                        }
                        let byte = self.take(8) as u8;
                        if let Some(slot) = out.get_mut(*op) {
                            *slot = byte;
                        }
                        *op += 1;
                        self.push_window_byte(byte);
                        self.stored_left -= 1;
                    }
                    if self.stored_left > 0 {
                        let room = out.len().saturating_sub(*op);
                        if room == 0 {
                            return Ok(Status::OutputFull);
                        }
                        let available = inp.len().saturating_sub(*ip);
                        let n = self.stored_left.min(available).min(room);
                        if n == 0 {
                            return Ok(Status::NeedInput);
                        }
                        let (Some(src), Some(dst)) = (inp.get(*ip..*ip + n), out.get_mut(*op..*op + n)) else {
                            return Err(Error::new(ErrorKind::Internal, "deflate: stored copy out of range"));
                        };
                        dst.copy_from_slice(src);
                        self.push_window_bytes(src);
                        *ip += n;
                        *op += n;
                        self.stored_left -= n;
                        if self.stored_left > 0 {
                            continue;
                        }
                    }
                    self.state = State::BlockHeader;
                }
                State::DynCounts => {
                    if !self.ensure(inp, ip, 14) {
                        return Ok(Status::NeedInput);
                    }
                    self.literal_count = self.take(5) as usize + 257;
                    self.distance_count = self.take(5) as usize + 1;
                    self.code_length_count = self.take(4) as usize + 4;
                    if self.literal_count > MAX_LIT_SYMBOLS || self.distance_count > MAX_DIST_SYMBOLS {
                        return Err(corrupt("too many length or distance symbols"));
                    }
                    self.lengths.fill(0);
                    self.code_length_lengths.fill(0);
                    self.code_length_index = 0;
                    self.state = State::DynCodeLengths;
                }
                State::DynCodeLengths => {
                    while self.code_length_index < self.code_length_count {
                        if !self.ensure(inp, ip, 3) {
                            return Ok(Status::NeedInput);
                        }
                        let value = self.take(3) as u8;
                        let order = CODE_LENGTH_ORDER.get(self.code_length_index).copied().unwrap_or(0);
                        if let Some(slot) = self.code_length_lengths.get_mut(usize::from(order)) {
                            *slot = value;
                        }
                        self.code_length_index += 1;
                    }
                    if !self.code_length_table.build(&self.code_length_lengths, false) {
                        return Err(corrupt("invalid code lengths set"));
                    }
                    self.length_index = 0;
                    self.previous_length = 0;
                    self.state = State::DynSymbols;
                }
                State::DynSymbols => {
                    let total = self.literal_count + self.distance_count;
                    let mut repeat = false;
                    while self.length_index < total {
                        self.ensure(inp, ip, 7); // fewer bits are fine if the code is short
                        let entry = self.code_length_table.decode(self.bitbuf, self.bitcount);
                        if entry == NEED_MORE {
                            return Ok(Status::NeedInput);
                        }
                        let length = entry & 15;
                        if length == 0 {
                            return Err(corrupt("invalid code length code"));
                        }
                        if length > self.bitcount {
                            return Ok(Status::NeedInput);
                        }
                        let symbol = entry >> 4;
                        self.take(length);
                        if symbol < 16 {
                            if let Some(slot) = self.lengths.get_mut(self.length_index) {
                                *slot = symbol as u8;
                            }
                            self.length_index += 1;
                            self.previous_length = symbol as u8;
                        } else {
                            self.repeat_symbol = symbol;
                            self.state = State::DynRepeat;
                            repeat = true;
                            break;
                        }
                    }
                    if !repeat {
                        self.finish_dynamic_tables()?;
                    }
                }
                State::DynRepeat => {
                    let symbol = self.repeat_symbol;
                    let extra_bits = match symbol {
                        16 => 2,
                        17 => 3,
                        _ => 7,
                    };
                    if !self.ensure(inp, ip, extra_bits) {
                        return Ok(Status::NeedInput);
                    }
                    let extra = self.take(extra_bits) as usize;
                    let (count, value) = match symbol {
                        16 => {
                            if self.length_index == 0 {
                                return Err(corrupt("repeat with no previous length"));
                            }
                            (3 + extra, self.previous_length)
                        }
                        17 => (3 + extra, 0),
                        _ => (11 + extra, 0),
                    };
                    let end = self.length_index + count;
                    if end > self.literal_count + self.distance_count {
                        return Err(corrupt("too many code lengths"));
                    }
                    if let Some(slots) = self.lengths.get_mut(self.length_index..end) {
                        slots.fill(value);
                    }
                    self.length_index = end;
                    // A later "repeat previous" (16) repeats the last length written: after 17 or 18, zero.
                    self.previous_length = value;
                    self.state = State::DynSymbols;
                }
                State::Symbol => {
                    // Literals in a tight loop; anything else leaves it. The symbol is peeked: a
                    // literal that cannot be written yet is not consumed.
                    loop {
                        if self.bitcount < MAX_BITS {
                            self.refill(inp, ip);
                        }
                        let entry = if self.use_fixed {
                            self.fixed_literal_table.decode(self.bitbuf, self.bitcount)
                        } else {
                            self.literal_table.decode(self.bitbuf, self.bitcount)
                        };
                        if entry == NEED_MORE {
                            return Ok(Status::NeedInput);
                        }
                        let length = entry & 15;
                        if length == 0 {
                            return Err(corrupt("invalid literal/length code"));
                        }
                        if length > self.bitcount {
                            return Ok(Status::NeedInput);
                        }
                        let symbol = entry >> 4;
                        if symbol < 256 {
                            let Some(slot) = out.get_mut(*op) else {
                                return Ok(Status::OutputFull);
                            };
                            self.bitbuf >>= length;
                            self.bitcount -= length;
                            *slot = symbol as u8;
                            *op += 1;
                            self.push_window_byte(symbol as u8);
                        } else if symbol == 256 {
                            self.bitbuf >>= length;
                            self.bitcount -= length;
                            self.state = State::BlockHeader;
                            break;
                        } else {
                            if symbol > 285 {
                                return Err(corrupt("invalid length symbol"));
                            }
                            self.bitbuf >>= length;
                            self.bitcount -= length;
                            let code = (symbol - 257) as usize;
                            if self.bitcount < FAST_MATCH_BITS {
                                self.refill(inp, ip);
                            }
                            if self.bitcount >= FAST_MATCH_BITS {
                                // The whole match is buffered: no state changes in between.
                                self.decode_match_rest(code)?;
                                let room = out.len().saturating_sub(*op);
                                let n = self.match_length.min(room);
                                self.copy_match(out, *op, n);
                                *op += n;
                                self.match_length -= n;
                                if self.match_length > 0 {
                                    self.state = State::Copy;
                                    return Ok(Status::OutputFull);
                                }
                                continue;
                            }
                            self.symbol_code = code;
                            self.state = State::LengthExtra;
                            break;
                        }
                    }
                }
                State::LengthExtra => {
                    let extra_bits = u32::from(LENGTH_EXTRA_BITS.get(self.symbol_code).copied().unwrap_or(0));
                    if !self.ensure(inp, ip, extra_bits) {
                        return Ok(Status::NeedInput);
                    }
                    let base = usize::from(LENGTH_BASE.get(self.symbol_code).copied().unwrap_or(3));
                    self.match_length = base + self.take(extra_bits) as usize;
                    self.state = State::DistSymbol;
                }
                State::DistSymbol => {
                    if self.bitcount < MAX_BITS {
                        self.refill(inp, ip);
                    }
                    let entry = if self.use_fixed {
                        self.fixed_distance_table.decode(self.bitbuf, self.bitcount)
                    } else {
                        self.distance_table.decode(self.bitbuf, self.bitcount)
                    };
                    if entry == NEED_MORE {
                        return Ok(Status::NeedInput);
                    }
                    let length = entry & 15;
                    if length == 0 {
                        return Err(corrupt("invalid distance code"));
                    }
                    if length > self.bitcount {
                        return Ok(Status::NeedInput);
                    }
                    let symbol = entry >> 4;
                    if symbol > 29 {
                        return Err(corrupt("invalid distance symbol"));
                    }
                    self.take(length);
                    self.symbol_code = symbol as usize;
                    self.state = State::DistExtra;
                }
                State::DistExtra => {
                    let extra_bits = u32::from(DISTANCE_EXTRA_BITS.get(self.symbol_code).copied().unwrap_or(0));
                    if !self.ensure(inp, ip, extra_bits) {
                        return Ok(Status::NeedInput);
                    }
                    let base = usize::from(DISTANCE_BASE.get(self.symbol_code).copied().unwrap_or(1));
                    self.match_distance = base + self.take(extra_bits) as usize;
                    if self.match_distance > self.window_filled {
                        return Err(corrupt("distance too far back"));
                    }
                    self.state = State::Copy;
                }
                State::Copy => {
                    let room = out.len().saturating_sub(*op);
                    let n = self.match_length.min(room);
                    self.copy_match(out, *op, n);
                    *op += n;
                    self.match_length -= n;
                    if self.match_length > 0 {
                        return Ok(Status::OutputFull);
                    }
                    self.state = State::Symbol;
                }
                State::Finished => return Ok(Status::Done),
                State::Failed => {
                    return Err(self
                        .deferred
                        .take()
                        .unwrap_or_else(|| corrupt("the stream is already known to be invalid")));
                }
            }
        }
    }

    /// With `FAST_MATCH_BITS` bits buffered: the length extra bits, the distance code and its extra
    /// bits of a match whose length code is `code`. Sets `match_length` and `match_distance`.
    #[inline(always)]
    fn decode_match_rest(&mut self, code: usize) -> Result<(), Error> {
        let extra_bits = u32::from(LENGTH_EXTRA_BITS.get(code).copied().unwrap_or(0));
        let base = usize::from(LENGTH_BASE.get(code).copied().unwrap_or(3));
        self.match_length = base + self.take(extra_bits) as usize;
        let entry = if self.use_fixed {
            self.fixed_distance_table.decode(self.bitbuf, self.bitcount)
        } else {
            self.distance_table.decode(self.bitbuf, self.bitcount)
        };
        let length = entry & 15;
        let symbol = (entry >> 4) as usize;
        if length == 0 {
            return Err(corrupt("invalid distance code"));
        }
        if symbol > 29 {
            return Err(corrupt("invalid distance symbol"));
        }
        self.take(length);
        let extra_bits = u32::from(DISTANCE_EXTRA_BITS.get(symbol).copied().unwrap_or(0));
        let base = usize::from(DISTANCE_BASE.get(symbol).copied().unwrap_or(1));
        self.match_distance = base + self.take(extra_bits) as usize;
        if self.match_distance > self.window_filled {
            return Err(corrupt("distance too far back"));
        }
        Ok(())
    }

    fn finish_dynamic_tables(&mut self) -> Result<(), Error> {
        if self.lengths.get(256).copied().unwrap_or(0) == 0 {
            return Err(corrupt("missing end-of-block code"));
        }
        let lit = self.lengths.get(..self.literal_count).unwrap_or(&[]);
        if !self.literal_table.build(lit, true) {
            return Err(corrupt("invalid literal/length code lengths"));
        }
        let dist = self
            .lengths
            .get(self.literal_count..self.literal_count + self.distance_count)
            .unwrap_or(&[]);
        if !self.distance_table.build(dist, true) {
            return Err(corrupt("invalid distance code lengths"));
        }
        self.use_fixed = false;
        self.state = State::Symbol;
        Ok(())
    }

    // -- window ------------------------------------------------------------------------------

    #[inline(always)]
    fn push_window_byte(&mut self, byte: u8) {
        if let Some(slot) = self.window.get_mut(self.window_pos) {
            *slot = byte;
        }
        self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
        if self.window_filled < WINDOW_SIZE {
            self.window_filled += 1;
        }
    }

    fn push_window_bytes(&mut self, mut bytes: &[u8]) {
        // At most the last window of the chunk matters.
        let skipped = bytes.len().saturating_sub(WINDOW_SIZE);
        self.window_pos = (self.window_pos + skipped) & WINDOW_MASK;
        self.window_filled = (self.window_filled + skipped).min(WINDOW_SIZE);
        bytes = bytes.get(skipped..).unwrap_or(&[]);
        while !bytes.is_empty() {
            let room = WINDOW_SIZE - self.window_pos;
            let n = room.min(bytes.len());
            let (head, rest) = bytes.split_at(n);
            if let Some(dst) = self.window.get_mut(self.window_pos..self.window_pos + n) {
                dst.copy_from_slice(head);
            }
            self.window_pos = (self.window_pos + n) & WINDOW_MASK;
            self.window_filled = (self.window_filled + n).min(WINDOW_SIZE);
            bytes = rest;
        }
    }

    /// Copy `n` bytes of the current match (distance `match_distance`, validated against the
    /// filled window) into `out` at `op` and into the window.
    fn copy_match(&mut self, out: &mut [u8], op: usize, n: usize) {
        let distance = self.match_distance;
        let mut done = 0usize;
        while done < n {
            let dst = self.window_pos;
            let src = dst.wrapping_sub(distance) & WINDOW_MASK;
            let mut chunk = (n - done).min(WINDOW_SIZE - dst);
            let out_range = op + done..op + done + chunk;
            if distance == 1 {
                let byte = self.window.get(src).copied().unwrap_or(0);
                if let Some(w) = self.window.get_mut(dst..dst + chunk) {
                    w.fill(byte);
                }
                if let Some(o) = out.get_mut(out_range) {
                    o.fill(byte);
                }
            } else if distance < 16 {
                // Short distances overlap with themselves: byte by byte.
                for i in 0..chunk {
                    let byte = self
                        .window
                        .get((dst + i).wrapping_sub(distance) & WINDOW_MASK)
                        .copied()
                        .unwrap_or(0);
                    if let Some(slot) = self.window.get_mut(dst + i) {
                        *slot = byte;
                    }
                    if let Some(slot) = out.get_mut(op + done + i) {
                        *slot = byte;
                    }
                }
            } else {
                // `chunk <= distance` keeps source and destination from overlapping in a way that
                // matters; `chunk <= WINDOW_SIZE - src` keeps the source from wrapping.
                chunk = chunk.min(WINDOW_SIZE - src).min(distance);
                let out_range = op + done..op + done + chunk;
                if src + chunk <= WINDOW_SIZE && dst + chunk <= WINDOW_SIZE {
                    self.window.copy_within(src..src + chunk, dst);
                }
                if let (Some(w), Some(o)) = (self.window.get(dst..dst + chunk), out.get_mut(out_range)) {
                    o.copy_from_slice(w);
                }
            }
            self.window_pos = (dst + chunk) & WINDOW_MASK;
            done += chunk;
        }
        self.window_filled = (self.window_filled + n).min(WINDOW_SIZE);
    }
}

#[cfg(test)]
#[path = "inflate_tests.rs"]
mod inflate_tests;

#[cfg(test)]
#[path = "inflate_table_tests.rs"]
mod inflate_table_tests;
