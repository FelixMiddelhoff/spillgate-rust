//! The reader returned to the caller: the last layer plus the end-to-end ratio check.

use std::fmt;
use std::io::{self, Read};

use crate::error::{Error, ErrorKind};
use crate::guard::{LayerGuard, Outcome, MAX_STEP};
use crate::limits::EffectiveLimits;
use crate::meter::MeterHandle;

/// The decoded bytes of a source, read through [`std::io::Read`].
///
/// Reading can deliver bytes and then fail: treat any error as failure of the whole body
/// (SG-R-LAY-06). A failure is an [`io::Error`] wrapping a spillgate [`Error`]; get the typed error
/// with [`Error::from_io`]. Errors are sticky: every later read fails with an error of the same
/// kind (SG-R-LAY-05), and a clean end is sticky too. A single `read` returns at most 64 KiB.
///
/// Closing does not touch the caller's source (it is dropped with the reader if it was passed by
/// value, which for `&mut` sources is a no-op). A reader is not meant to be shared between threads
/// (SG-R-RDR-07).
pub struct SpillgateReader<'a> {
    top: Option<LayerGuard<'a>>,
    source: MeterHandle,
    limits: EffectiveLimits,
    produced: u64,
    outcome: Outcome,
}

impl fmt::Debug for SpillgateReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpillgateReader")
            .field("produced", &self.produced)
            .field("consumed", &self.source.consumed())
            .field("closed", &self.top.is_none())
            .finish()
    }
}

impl<'a> SpillgateReader<'a> {
    pub(crate) fn new(top: LayerGuard<'a>, source: MeterHandle, limits: EffectiveLimits) -> SpillgateReader<'a> {
        SpillgateReader {
            top: Some(top),
            source,
            limits,
            produced: 0,
            outcome: Outcome::Running,
        }
    }

    /// Release all codec state. Idempotent; the caller's source is not closed (SG-R-RDR-06). Reads
    /// after `close` fail.
    pub fn close(&mut self) {
        self.top = None;
    }

    /// `Ok(0)` is the clean end for a non-empty `buf`.
    pub(crate) fn read_typed(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(replayed) = self.outcome.replay() {
            return replayed;
        }
        let Some(top) = self.top.as_mut() else {
            return Err(Error::new(ErrorKind::Internal, "the reader is closed"));
        };
        if buf.is_empty() {
            return Ok(0);
        }
        let wanted = buf.len().min(MAX_STEP);
        let (chunk, _) = buf.split_at_mut(wanted);
        match top.read_step(chunk) {
            Ok(0) => {
                self.outcome = Outcome::End;
                Ok(0)
            }
            Ok(n) => {
                self.produced = self.produced.saturating_add(n as u64);
                // SG-R-RAT-03: the same ratio test, end to end. The error follows these bytes. A
                // layer that already failed has the more specific error, so it wins.
                if !top.failed() && self.limits.ratio_exceeded(self.produced, self.source.consumed()) {
                    let error = Error::new(ErrorKind::RatioLimit, "end-to-end expansion over the whole chain")
                        .with_limit(self.limits.max_ratio);
                    self.outcome = Outcome::Failed(error);
                }
                Ok(n)
            }
            Err(error) => {
                self.outcome = Outcome::Failed(error.duplicate());
                Err(error)
            }
        }
    }

    /// Read to the end. Memory grows with the bytes produced, never with a limit (SG-R-MEM-02).
    pub(crate) fn read_all(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut chunk = vec![0u8; MAX_STEP];
        loop {
            let n = self.read_typed(&mut chunk)?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }
}

impl Read for SpillgateReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.top.is_none() {
            return Err(io::Error::other("spillgate: the reader is closed"));
        }
        self.read_typed(buf).map_err(io::Error::from)
    }
}
