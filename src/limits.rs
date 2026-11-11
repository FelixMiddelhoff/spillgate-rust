//! The limits a decoder enforces (SPEC section 3).

use crate::error::{Error, ErrorKind};

/// Default for `max_layers` (SG-R-LIM-03).
pub const DEFAULT_MAX_LAYERS: u32 = 5;
/// Default for `max_ratio` (SG-R-LIM-04).
pub const DEFAULT_MAX_RATIO: u64 = 1000;
/// Default for `ratio_grace` in bytes (SG-R-LIM-05).
pub const DEFAULT_RATIO_GRACE: u64 = 64 * 1024;
/// Largest valid `max_layers` (SG-R-LIM-03).
pub const HARD_MAX_LAYERS: u32 = 16;
/// Largest valid `max_ratio` (SG-R-LIM-04).
pub const HARD_MAX_RATIO: u64 = (1 << 31) - 1;
/// Largest valid byte limit, 2^63-1 (SG-R-LIM-02).
pub const MAX_BYTES: u64 = i64::MAX as u64;

/// What a decoder enforces. Build one with [`Limits::new`] and the chained setters; it is
/// validated completely when the [`Decoder`](crate::Decoder) is constructed (SG-R-LIM-08) and
/// copied then (SG-R-LIM-09).
///
/// `max_output` has no default and no "unlimited" value. Zero and values above 2^63-1 are
/// `invalid_limits`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    max_output: u64,
    max_layers: Option<u32>,
    max_ratio: Option<u64>,
    ratio_grace: Option<u64>,
    max_input: Option<u64>,
    disable_ratio_limit: bool,
}

impl Limits {
    /// Limits with the required output bound: the bytes one layer may produce, `1 ..= 2^63-1`.
    pub fn new(max_output: u64) -> Limits {
        Limits {
            max_output,
            max_layers: None,
            max_ratio: None,
            ratio_grace: None,
            max_input: None,
            disable_ratio_limit: false,
        }
    }

    /// The longest chain of non-identity encodings, `1 ..= 16`. Default 5. An explicit 0 is invalid.
    #[must_use]
    pub fn max_layers(mut self, layers: u32) -> Limits {
        self.max_layers = Some(layers);
        self
    }

    /// Output bytes per consumed input byte, `1 ..= 2^31-1`. Default 1000. Cannot be combined with
    /// [`disable_ratio_limit`](Limits::disable_ratio_limit).
    #[must_use]
    pub fn max_ratio(mut self, ratio: u64) -> Limits {
        self.max_ratio = Some(ratio);
        self
    }

    /// Output size in bytes below which the ratio is not checked. Default 64 KiB; 0 checks from
    /// the first produced byte.
    #[must_use]
    pub fn ratio_grace(mut self, bytes: u64) -> Limits {
        self.ratio_grace = Some(bytes);
        self
    }

    /// An optional cap on the compressed bytes taken from the source, `1 ..= 2^63-1`. Zero is
    /// invalid and does not mean unlimited.
    #[must_use]
    pub fn max_input(mut self, bytes: u64) -> Limits {
        self.max_input = Some(bytes);
        self
    }

    /// The one named opt-out of the ratio check (SG-R-LIM-04). `max_output`, `max_layers` and
    /// `max_input` stay in force.
    #[must_use]
    pub fn disable_ratio_limit(mut self) -> Limits {
        self.disable_ratio_limit = true;
        self
    }
}

/// The limits with defaults filled in and every value checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    /// Bytes one layer may produce.
    pub max_output: u64,
    /// Longest chain of non-identity layers.
    pub max_layers: u32,
    /// Output bytes per consumed input byte; 0 means the ratio check is off.
    pub max_ratio: u64,
    /// Output size below which the ratio is not checked.
    pub ratio_grace: u64,
    /// Compressed bytes the source may deliver; 0 means no cap.
    pub max_input: u64,
}

fn invalid(message: String) -> Error {
    Error::new(ErrorKind::InvalidLimits, message)
}

impl EffectiveLimits {
    /// Validate `limits` completely.
    pub fn from_limits(limits: &Limits) -> Result<EffectiveLimits, Error> {
        if limits.max_output < 1 || limits.max_output > MAX_BYTES {
            return Err(invalid(format!(
                "max_output must be in 1..={MAX_BYTES}, got {}",
                limits.max_output
            )));
        }
        let max_layers = match limits.max_layers {
            None => DEFAULT_MAX_LAYERS,
            Some(n) if (1..=HARD_MAX_LAYERS).contains(&n) => n,
            Some(n) => return Err(invalid(format!("max_layers must be in 1..={HARD_MAX_LAYERS}, got {n}"))),
        };
        if limits.disable_ratio_limit && limits.max_ratio.is_some() {
            return Err(invalid(
                "max_ratio contradicts disable_ratio_limit; set only one".into(),
            ));
        }
        let max_ratio = if limits.disable_ratio_limit {
            0
        } else {
            match limits.max_ratio {
                None => DEFAULT_MAX_RATIO,
                Some(n) if (1..=HARD_MAX_RATIO).contains(&n) => n,
                Some(n) => return Err(invalid(format!("max_ratio must be in 1..={HARD_MAX_RATIO}, got {n}"))),
            }
        };
        let ratio_grace = match limits.ratio_grace {
            None => DEFAULT_RATIO_GRACE,
            Some(n) if n <= MAX_BYTES => n,
            Some(n) => return Err(invalid(format!("ratio_grace must be at most {MAX_BYTES}, got {n}"))),
        };
        let max_input = match limits.max_input {
            None => 0,
            Some(n) if (1..=MAX_BYTES).contains(&n) => n,
            Some(n) => return Err(invalid(format!("max_input must be in 1..={MAX_BYTES}, got {n}"))),
        };
        Ok(EffectiveLimits {
            max_output: limits.max_output,
            max_layers,
            max_ratio,
            ratio_grace,
            max_input,
        })
    }

    /// SG-R-RAT-01: `produced > max_ratio * max(consumed, 1)`, past the grace, in arithmetic that
    /// cannot overflow.
    pub fn ratio_exceeded(&self, produced: u64, consumed: u64) -> bool {
        if self.max_ratio == 0 || produced <= self.ratio_grace {
            return false;
        }
        let allowed = u128::from(self.max_ratio) * u128::from(consumed.max(1));
        u128::from(produced) > allowed
    }
}
