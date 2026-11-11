//! Huffman-coded literals (RFC 8878 section 4.2).

use super::bits::BackwardBits;
use super::fse::read_table;
use crate::error::Error;

const MAX_HUFFMAN_BITS: u32 = 11;

/// A decoding table: `entries[bits & mask]` is `symbol << 4 | length`.
#[derive(Clone)]
pub(crate) struct HuffmanTable {
    max_bits: u32,
    entries: Vec<u16>,
}

fn err(message: &'static str) -> Error {
    Error::corrupt(message)
}

/// Read a Huffman tree description (RFC 8878 4.2.1) from the start of `bytes`.
///
/// Returns the table and the number of bytes the description used.
pub(crate) fn read_huffman_table(bytes: &[u8]) -> Result<(HuffmanTable, usize), Error> {
    let Some((&header, rest)) = bytes.split_first() else {
        return Err(err("zstd: an empty Huffman tree description"));
    };
    let mut weights: Vec<u8> = Vec::new();
    let used;
    if header >= 128 {
        // direct representation: header - 127 weights of 4 bits each, two per byte (high nibble first)
        let count = usize::from(header) - 127;
        let payload = count.div_ceil(2);
        used = 1 + payload;
        let packed = rest
            .get(..payload)
            .ok_or_else(|| err("zstd: a Huffman tree description ends too early"))?;
        for i in 0..count {
            let byte = packed.get(i / 2).copied().unwrap_or(0);
            weights.push(if i % 2 == 0 { byte >> 4 } else { byte & 15 });
        }
    } else {
        // FSE-compressed weights, `header` bytes
        let size = usize::from(header);
        used = 1 + size;
        if size == 0 {
            return Err(err("zstd: a Huffman tree description ends too early"));
        }
        let compressed = rest
            .get(..size)
            .ok_or_else(|| err("zstd: a Huffman tree description ends too early"))?;
        decode_weights(compressed, &mut weights)?;
    }
    if weights.len() > 255 {
        return Err(err("zstd: too many Huffman weights"));
    }

    // the last weight is implied: the sum of 2**(w-1) must reach a power of two
    let total: u64 = weights.iter().filter(|&&w| w > 0).map(|&w| 1u64 << (w - 1)).sum();
    if total == 0 {
        return Err(err("zstd: a Huffman tree has no codes"));
    }
    let max_bits = 64 - total.leading_zeros(); // smallest b with 2**b > total
    let power = 1u64 << max_bits;
    let remainder = power - total;
    if !remainder.is_power_of_two() {
        return Err(err("zstd: Huffman weights do not complete a tree"));
    }
    weights.push(remainder.trailing_zeros() as u8 + 1); // log2(rest) + 1
    if max_bits > MAX_HUFFMAN_BITS {
        return Err(err("zstd: a Huffman code is too long"));
    }
    Ok((build_huffman(&weights, max_bits)?, used))
}

/// FSE-compressed weights: two interleaved states over a backward bit stream.
fn decode_weights(bytes: &[u8], weights: &mut Vec<u8>) -> Result<(), Error> {
    let (table, used) = read_table(bytes, 6, 15)?;
    let stream = bytes
        .get(used..)
        .ok_or_else(|| err("zstd: a Huffman tree description ends too early"))?;
    let mut bits = BackwardBits::new(stream)?;
    let mut state1 = bits.read(table.accuracy_log);
    let mut state2 = bits.read(table.accuracy_log);
    loop {
        let e1 = table.entry(state1)?;
        weights.push(e1.symbol);
        state1 = u64::from(e1.baseline) + bits.read(u32::from(e1.nb_bits));
        if bits.remaining < 0 {
            weights.push(table.entry(state2)?.symbol);
            return Ok(());
        }
        let e2 = table.entry(state2)?;
        weights.push(e2.symbol);
        state2 = u64::from(e2.baseline) + bits.read(u32::from(e2.nb_bits));
        if bits.remaining < 0 {
            weights.push(table.entry(state1)?.symbol);
            return Ok(());
        }
        if weights.len() > 255 {
            return Err(err("zstd: too many Huffman weights"));
        }
    }
}

fn build_huffman(weights: &[u8], max_bits: u32) -> Result<HuffmanTable, Error> {
    let size = 1usize << max_bits;
    let mut entries = vec![0u16; size];
    // canonical codes, shortest codes take the highest bit patterns (RFC 8878 4.2.1: symbols sorted by weight)
    let mut next = 0usize;
    for w in 1..=max_bits {
        for (symbol, &weight) in weights.iter().enumerate() {
            if u32::from(weight) != w {
                continue;
            }
            let length = max_bits + 1 - w;
            let span = 1usize << (max_bits - length);
            let value =
                u16::try_from((symbol << 4) | length as usize).map_err(|_| err("zstd: a Huffman symbol is invalid"))?;
            let end = next
                .checked_add(span)
                .ok_or_else(|| err("zstd: a Huffman tree is not complete"))?;
            entries
                .get_mut(next..end)
                .ok_or_else(|| err("zstd: a Huffman tree is not complete"))?
                .fill(value);
            next = end;
        }
    }
    if next != size {
        return Err(err("zstd: a Huffman tree is not complete"));
    }
    Ok(HuffmanTable { max_bits, entries })
}

/// Decode `out.len()` literals from one backward-coded stream.
pub(crate) fn decode_stream(table: &HuffmanTable, stream: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let mut bits = BackwardBits::new(stream)?;
    for slot in out.iter_mut() {
        let index = usize::try_from(bits.peek(table.max_bits)).unwrap_or(0);
        let entry = table
            .entries
            .get(index)
            .copied()
            .ok_or_else(|| err("zstd: a Huffman code is invalid"))?;
        bits.remaining -= i64::from(entry & 15);
        *slot = (entry >> 4) as u8;
    }
    if bits.remaining != 0 {
        return Err(err("zstd: a Huffman stream was not consumed exactly"));
    }
    Ok(())
}
