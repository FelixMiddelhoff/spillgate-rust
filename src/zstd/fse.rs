//! Finite State Entropy tables (RFC 8878 section 4.1).

use super::bits::ForwardBits;
use crate::error::Error;

/// One state of a decoding table.
#[derive(Clone, Copy, Default)]
pub(crate) struct FseEntry {
    pub(crate) symbol: u8,
    pub(crate) nb_bits: u8,
    pub(crate) baseline: u32,
}

#[derive(Clone)]
pub(crate) struct FseTable {
    pub(crate) accuracy_log: u32,
    pub(crate) entries: Vec<FseEntry>,
}

impl FseTable {
    pub(crate) fn entry(&self, state: u64) -> Result<FseEntry, Error> {
        usize::try_from(state)
            .ok()
            .and_then(|i| self.entries.get(i))
            .copied()
            .ok_or_else(|| Error::corrupt("zstd: a table state is out of range"))
    }
}

fn bad_sum() -> Error {
    Error::corrupt("zstd: the probabilities of a table do not add up")
}

/// `normalized[s]` is the probability of symbol s in units of 1/2**accuracy_log; -1 means "less than one".
pub(crate) fn build_table(normalized: &[i32], accuracy_log: u32) -> Result<FseTable, Error> {
    if accuracy_log > 9 {
        return Err(Error::corrupt("zstd: a table asks for too large an accuracy"));
    }
    let size = 1usize << accuracy_log;
    let mut entries = vec![FseEntry::default(); size];
    let mut next = vec![0u32; normalized.len()];

    // symbols with probability "less than one" take the highest states
    let mut high = size;
    for (s, &p) in normalized.iter().enumerate() {
        if p == -1 {
            high = high.checked_sub(1).ok_or_else(bad_sum)?;
            entries.get_mut(high).ok_or_else(bad_sum)?.symbol = u8::try_from(s).map_err(|_| bad_sum())?;
            *next.get_mut(s).ok_or_else(bad_sum)? = 1;
        } else {
            *next.get_mut(s).ok_or_else(bad_sum)? = u32::try_from(p.max(0)).map_err(|_| bad_sum())?;
        }
    }
    // `high` is now the first of the reserved states; the others are spread over 0..high with a fixed stride
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut position = 0usize;
    for (s, &p) in normalized.iter().enumerate() {
        let symbol = u8::try_from(s).map_err(|_| bad_sum())?;
        for _ in 0..p.max(0) {
            entries.get_mut(position).ok_or_else(bad_sum)?.symbol = symbol;
            let mut guard = 0usize;
            loop {
                position = (position + step) & mask;
                if position < high {
                    break;
                }
                guard += 1;
                if guard > size {
                    return Err(bad_sum());
                }
            }
        }
    }
    if position != 0 {
        return Err(bad_sum());
    }

    for entry in entries.iter_mut() {
        let slot = next.get_mut(usize::from(entry.symbol)).ok_or_else(bad_sum)?;
        let next_state = *slot;
        *slot = next_state.checked_add(1).ok_or_else(bad_sum)?;
        let top = next_state.checked_ilog2().ok_or_else(bad_sum)?;
        let bits = accuracy_log.checked_sub(top).ok_or_else(bad_sum)?;
        entry.nb_bits = u8::try_from(bits).map_err(|_| bad_sum())?;
        let shifted = next_state.checked_shl(bits).ok_or_else(bad_sum)?;
        entry.baseline = shifted
            .checked_sub(u32::try_from(size).map_err(|_| bad_sum())?)
            .ok_or_else(bad_sum)?;
    }
    Ok(FseTable { accuracy_log, entries })
}

/// Read a table description from the start of `bytes` (RFC 8878 4.1.1).
///
/// Returns the table and the number of bytes the description used.
pub(crate) fn read_table(bytes: &[u8], max_accuracy_log: u32, max_symbol: usize) -> Result<(FseTable, usize), Error> {
    let mut bits = ForwardBits::new(bytes);
    let accuracy_log = bits.read(4) + 5;
    if accuracy_log > max_accuracy_log {
        return Err(Error::corrupt("zstd: a table asks for too large an accuracy"));
    }
    let total = 1u32 << accuracy_log;
    let mut normalized: Vec<i32> = Vec::new();
    let mut sum = 0u32;
    let too_many = || Error::corrupt("zstd: a table has too many symbols");
    while sum < total {
        let max_value = total - sum + 1; // the number of values still possible
        let bit_count = 32 - max_value.leading_zeros();
        let raw = bits.read(bit_count);
        let low_threshold = (1u32 << bit_count) - 1 - max_value;
        let mask = (1u32 << (bit_count - 1)) - 1;
        let small = raw & mask;
        let value = if small < low_threshold {
            bits.unread(1);
            small
        } else if raw > mask {
            raw - low_threshold
        } else {
            raw
        };
        let probability = i32::try_from(value).map_err(|_| bad_sum())? - 1;
        sum += if probability < 0 { 1 } else { probability as u32 };
        normalized.push(probability);
        if normalized.len() > max_symbol + 1 {
            return Err(too_many());
        }
        if probability == 0 {
            // a run of unused symbols
            loop {
                let repeat = bits.read(2);
                normalized.extend(std::iter::repeat_n(0, repeat as usize));
                if normalized.len() > max_symbol + 1 {
                    return Err(too_many());
                }
                if repeat != 3 {
                    break;
                }
            }
        }
        if bits.overrun() {
            return Err(Error::corrupt("zstd: a table description ends too early"));
        }
    }
    if sum != total {
        return Err(bad_sum());
    }
    let used = bits.bytes_used();
    Ok((build_table(&normalized, accuracy_log)?, used))
}

/// A table that always yields `symbol` (the RLE mode of the sequence section).
pub(crate) fn rle_table(symbol: u8) -> FseTable {
    FseTable {
        accuracy_log: 0,
        entries: vec![FseEntry {
            symbol,
            nb_bits: 0,
            baseline: 0,
        }],
    }
}
