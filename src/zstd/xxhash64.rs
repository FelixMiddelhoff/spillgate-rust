//! XXH64, the hash behind the zstd content checksum (the low 32 bits of the digest are stored).

const P1: u64 = 11400714785074694791;
const P2: u64 = 14029467366897019727;
const P3: u64 = 1609587929392839161;
const P4: u64 = 9650029242287828579;
const P5: u64 = 2870177450012600261;

fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn merge(acc: u64, value: u64) -> u64 {
    (acc ^ round(0, value)).wrapping_mul(P1).wrapping_add(P4)
}

fn le64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (k, &b) in bytes.iter().take(8).enumerate() {
        value |= u64::from(b) << (8 * k);
    }
    value
}

fn le32(bytes: &[u8]) -> u64 {
    le64(bytes.get(..4).unwrap_or(bytes)) & 0xffff_ffff
}

/// Streaming XXH64 with seed 0.
pub(crate) struct Xxh64 {
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    tail: [u8; 32],
    tail_len: usize,
    total: u64,
}

impl Xxh64 {
    pub(crate) fn new() -> Xxh64 {
        Xxh64 {
            v1: P1.wrapping_add(P2),
            v2: P2,
            v3: 0,
            v4: 0u64.wrapping_sub(P1),
            tail: [0; 32],
            tail_len: 0,
            total: 0,
        }
    }

    fn stripe(&mut self, stripe: &[u8]) {
        let mut lanes = stripe.chunks_exact(8).map(le64);
        if let (Some(a), Some(b), Some(c), Some(d)) = (lanes.next(), lanes.next(), lanes.next(), lanes.next()) {
            self.v1 = round(self.v1, a);
            self.v2 = round(self.v2, b);
            self.v3 = round(self.v3, c);
            self.v4 = round(self.v4, d);
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.tail_len > 0 {
            let take = (32 - self.tail_len).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.tail.get_mut(self.tail_len..self.tail_len + take) {
                dst.copy_from_slice(head);
            }
            self.tail_len += take;
            data = rest;
            if self.tail_len < 32 {
                return;
            }
            let full = self.tail;
            self.stripe(&full);
            self.tail_len = 0;
        }
        let mut stripes = data.chunks_exact(32);
        for s in stripes.by_ref() {
            self.stripe(s);
        }
        let rest = stripes.remainder();
        if let Some(dst) = self.tail.get_mut(..rest.len()) {
            dst.copy_from_slice(rest);
        }
        self.tail_len = rest.len();
    }

    /// The full 64-bit digest.
    pub(crate) fn digest(&self) -> u64 {
        let mut h = if self.total >= 32 {
            let h = self
                .v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18));
            merge(merge(merge(merge(h, self.v1), self.v2), self.v3), self.v4)
        } else {
            P5
        };
        h = h.wrapping_add(self.total);
        let mut rest = self.tail.get(..self.tail_len).unwrap_or(&[]);
        while rest.len() >= 8 {
            h = (h ^ round(0, le64(rest)))
                .rotate_left(27)
                .wrapping_mul(P1)
                .wrapping_add(P4);
            rest = rest.get(8..).unwrap_or(&[]);
        }
        if rest.len() >= 4 {
            h = (h ^ le32(rest).wrapping_mul(P1))
                .rotate_left(23)
                .wrapping_mul(P2)
                .wrapping_add(P3);
            rest = rest.get(4..).unwrap_or(&[]);
        }
        for &b in rest {
            h = (h ^ u64::from(b).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^ (h >> 32)
    }

    /// The low 32 bits of the digest: what a zstd frame stores.
    pub(crate) fn digest32(&self) -> u32 {
        (self.digest() & 0xffff_ffff) as u32
    }
}
