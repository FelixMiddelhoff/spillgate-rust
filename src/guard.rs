//! The layer guard: everything the specification demands of one layer.
//!
//! Whatever the codec does, the guard never hands out more than `max_output` bytes in total
//! (SG-I-01), never turns a limit hit into a clean end (SG-I-02), keeps failing with the same
//! error once one occurred (SG-I-03) and contains panics of the codec (SG-I-05).

use std::io::{self, BufRead};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::codec::CodecReader;
use crate::error::{Error, ErrorKind};
use crate::limits::EffectiveLimits;
use crate::meter::MeterHandle;

/// The most a guard asks a codec for in one call (64 KiB). It bounds the memory of one step
/// (SG-R-MEM-02) whatever the size of the caller's buffer; callers get short reads, which every
/// reader contract allows. It is also the tolerance of SG-R-RAT-02: the ratio is judged once per
/// step.
pub(crate) const MAX_STEP: usize = 64 * 1024;

/// The state of a layer or a reader once it is terminal.
#[derive(Debug)]
pub(crate) enum Outcome {
    Running,
    End,
    Failed(Error),
}

impl Outcome {
    /// What every read returns once the outcome is terminal; `None` while running.
    pub(crate) fn replay(&self) -> Option<Result<usize, Error>> {
        match self {
            Outcome::Running => None,
            Outcome::End => Some(Ok(0)),
            Outcome::Failed(e) => Some(Err(e.duplicate())),
        }
    }

    pub(crate) fn failed(&self) -> bool {
        matches!(self, Outcome::Failed(_))
    }
}

/// The codec of an identity-only chain: bytes pass through (SG-R-CDC-10).
pub(crate) struct Passthrough<'a> {
    input: Box<dyn BufRead + 'a>,
}

impl<'a> Passthrough<'a> {
    pub(crate) fn new(input: Box<dyn BufRead + 'a>) -> Passthrough<'a> {
        Passthrough { input }
    }
}

impl CodecReader for Passthrough<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = {
            let available = self.input.fill_buf().map_err(Error::from_input)?;
            let n = available.len().min(buf.len());
            if let (Some(to), Some(from)) = (buf.get_mut(..n), available.get(..n)) {
                to.copy_from_slice(from);
            }
            n
        };
        self.input.consume(n);
        Ok(n)
    }
}

/// One layer: a codec behind the limiter, the ratio meter and the panic shield.
pub(crate) struct LayerGuard<'a> {
    codec: Box<dyn CodecReader + 'a>,
    meter: MeterHandle,
    layer: usize,
    limits: EffectiveLimits,
    produced: u64,
    outcome: Outcome,
}

impl<'a> LayerGuard<'a> {
    pub(crate) fn new(
        codec: Box<dyn CodecReader + 'a>,
        meter: MeterHandle,
        layer: usize,
        limits: EffectiveLimits,
    ) -> LayerGuard<'a> {
        LayerGuard {
            codec,
            meter,
            layer,
            limits,
            produced: 0,
            outcome: Outcome::Running,
        }
    }

    /// True once the layer has a terminal error (a clean end is not a failure).
    pub(crate) fn failed(&self) -> bool {
        self.outcome.failed()
    }

    /// Up to `buf.len()` decoded bytes (one step at most); `Ok(0)` is the clean end of a
    /// non-empty request.
    pub(crate) fn read_step(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(replayed) = self.outcome.replay() {
            return replayed;
        }
        if buf.is_empty() {
            return Ok(0); // SG-R-RDR-02: a zero-length read changes nothing
        }
        let remaining = self.limits.max_output.saturating_sub(self.produced);
        if remaining == 0 {
            return self.probe();
        }
        let step = u64::try_from(buf.len())
            .unwrap_or(u64::MAX)
            .min(remaining)
            .min(MAX_STEP as u64);
        let (chunk, _) = buf.split_at_mut(usize::try_from(step).unwrap_or(MAX_STEP));
        let n = self.call(chunk)?;
        if n == 0 {
            self.outcome = Outcome::End;
            return Ok(0);
        }
        self.produced = self.produced.saturating_add(n as u64);
        // The bytes that broke the ratio were produced first, so they are still delivered; the
        // error follows on the next read (SG-R-LAY-07).
        if self.limits.ratio_exceeded(self.produced, self.meter.consumed()) {
            let error = Error::new(
                ErrorKind::RatioLimit,
                format!(
                    "output of {} bytes from {} input bytes",
                    self.produced,
                    self.meter.consumed()
                ),
            )
            .with_limit(self.limits.max_ratio)
            .with_layer(self.layer);
            self.outcome = Outcome::Failed(error);
        }
        Ok(n)
    }

    /// The budget is used up: is there one more byte? (SG-R-LAY-03) If the codec yields one, the
    /// limit is exceeded and the byte is thrown away. If the stream ends cleanly, the output was
    /// exactly at the limit and all is well. The codec's own validation, such as a trailer
    /// checksum, still runs inside this call and can still report corruption.
    fn probe(&mut self) -> Result<usize, Error> {
        let mut one = [0u8; 1];
        if self.call(&mut one)? == 0 {
            self.outcome = Outcome::End;
            return Ok(0);
        }
        let error = Error::new(
            ErrorKind::OutputLimit,
            format!("the layer would produce more than {} bytes", self.limits.max_output),
        )
        .with_limit(self.limits.max_output)
        .with_layer(self.layer);
        self.outcome = Outcome::Failed(error.duplicate());
        Err(error)
    }

    /// One codec read with its failures contained (SG-R-CDC-08). An error makes the layer
    /// terminal.
    fn call(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let wanted = buf.len();
        let result = catch_unwind(AssertUnwindSafe(|| self.codec.read(buf)));
        let error = match result {
            Ok(Ok(n)) if n <= wanted => return Ok(n),
            Ok(Ok(_)) => Error::new(ErrorKind::Internal, "codec returned more bytes than requested"),
            Ok(Err(error)) => error,
            Err(payload) => {
                // Dropping a hostile payload can panic again.
                let _ = catch_unwind(AssertUnwindSafe(move || drop(payload)));
                Error::new(ErrorKind::Internal, "codec panicked")
            }
        };
        // A source failure is reported as such, whatever the codec made of it (SG-R-RDR-05).
        let error = self.meter.failure().unwrap_or(error).with_layer(self.layer);
        self.outcome = Outcome::Failed(error.duplicate());
        Err(error)
    }
}

/// A guarded layer is the source of the next layer.
impl io::Read for LayerGuard<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_step(buf).map_err(io::Error::from)
    }
}
