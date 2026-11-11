//! The input meter: counts what a codec takes and guards the source.
//!
//! A codec never talks to the caller's source directly. It takes its compressed bytes from an
//! [`InputMeter`], which
//!
//! - counts the bytes the codec actually *consumes* (not the bytes it fetched from the source), so
//!   a read-ahead buffer never gives free ratio credit (SG-R-RAT-02);
//! - fetches at most [`BUFFER_SIZE`] bytes at a time, far below the 64 KiB look-ahead tolerance;
//! - enforces the optional `max_input` cap with one probe byte (SG-R-INP-01, SG-R-INP-02);
//! - defends against misbehaving sources: one that reports more than it was asked for is `internal`
//!   (SG-R-RDR-04), one that is interrupted without progress 100 times in a row is `internal`
//!   (SG-R-RDR-03), one that fails is `source_error` (SG-R-RDR-05);
//! - never reads the source again after the first terminal condition (SG-R-LAY-09).

use std::cell::{Cell, RefCell};
use std::io::{self, BufRead, Read};
use std::rc::Rc;

use crate::error::{Error, ErrorKind};

/// Bytes fetched from the source at a time.
pub(crate) const BUFFER_SIZE: usize = 4096;
/// SG-R-RDR-03: this many fruitless reads in a row are "no progress".
pub(crate) const MAX_EMPTY_READS: u32 = 100;

/// The part of a meter that the layer guard and the reader look at.
#[derive(Debug, Default)]
struct MeterState {
    consumed: Cell<u64>,
    failure: RefCell<Option<Error>>,
}

/// Read access to the counters of an [`InputMeter`] that a codec owns.
#[derive(Debug, Clone, Default)]
pub(crate) struct MeterHandle(Rc<MeterState>);

impl MeterHandle {
    /// Bytes the codec has consumed so far (the `C(k)` of the specification).
    pub(crate) fn consumed(&self) -> u64 {
        self.0.consumed.get()
    }

    /// The terminal error the meter raised, if any: a source failure, the input limit, a lower
    /// layer's error.
    pub(crate) fn failure(&self) -> Option<Error> {
        self.0.failure.borrow().as_ref().map(Error::duplicate)
    }
}

/// Counts and guards the input of one layer.
pub(crate) struct InputMeter<R> {
    source: R,
    buf: Vec<u8>,
    pos: usize,
    filled: usize,
    /// End of the part of the buffer the codec was shown by the last `fill_buf`.
    visible: usize,
    fetched: u64,
    max_input: u64,
    layer: usize,
    ended: bool,
    state: MeterHandle,
    cancel: Option<crate::cancel::CancelToken>,
}

impl<R: Read> InputMeter<R> {
    /// `max_input` 0 means no cap. `layer` is the 1-based index used on errors.
    pub(crate) fn new(source: R, max_input: u64, layer: usize) -> InputMeter<R> {
        InputMeter {
            source,
            buf: vec![0; BUFFER_SIZE],
            pos: 0,
            filled: 0,
            visible: 0,
            fetched: 0,
            max_input,
            layer,
            ended: false,
            state: MeterHandle::default(),
            cancel: None,
        }
    }

    /// Fail every later fetch once `token` is canceled (SG-R-API-04).
    pub(crate) fn with_cancel(mut self, token: Option<crate::cancel::CancelToken>) -> InputMeter<R> {
        self.cancel = token;
        self
    }

    pub(crate) fn handle(&self) -> MeterHandle {
        self.state.clone()
    }

    fn fail(&mut self, error: Error) -> io::Error {
        let error = error.with_layer(self.layer);
        *self.state.0.failure.borrow_mut() = Some(error.duplicate());
        io::Error::from(error)
    }

    fn input_limit(&self) -> Error {
        Error::new(
            ErrorKind::InputLimit,
            format!("the stream needs more than {} input bytes", self.max_input),
        )
        .with_limit(self.max_input)
    }

    /// How much to ask the source for: with a cap never beyond `max_input + 1` bytes in total.
    fn fetch_size(&self) -> usize {
        if self.max_input == 0 {
            return BUFFER_SIZE;
        }
        match self.max_input.checked_sub(self.fetched) {
            None => 0,
            Some(room) => usize::try_from(room.saturating_add(1)).map_or(BUFFER_SIZE, |n| n.min(BUFFER_SIZE)),
        }
    }

    /// Fetch the next chunk from the source into the (empty) buffer.
    fn refill(&mut self) -> Result<(), Error> {
        self.pos = 0;
        self.filled = 0;
        if self.ended {
            return Ok(());
        }
        let want = self.fetch_size();
        if want == 0 {
            return Err(self.input_limit());
        }
        let mut interrupted = 0;
        loop {
            let Some(window) = self.buf.get_mut(..want) else {
                return Err(Error::new(ErrorKind::Internal, "input buffer too small"));
            };
            match self.source.read(window) {
                Ok(0) => {
                    self.ended = true;
                    return Ok(());
                }
                Ok(n) if n > want => {
                    return Err(Error::new(
                        ErrorKind::Internal,
                        "the source returned more bytes than requested",
                    ));
                }
                Ok(n) => {
                    self.filled = n;
                    self.fetched = self.fetched.saturating_add(n as u64);
                    return Ok(());
                }
                // A canceled lower layer is also reported as Interrupted; only a foreign
                // Interrupted is retried.
                Err(e) if e.kind() == io::ErrorKind::Interrupted && Error::from_io(&e).is_none() => {
                    interrupted += 1;
                    if interrupted >= MAX_EMPTY_READS {
                        return Err(Error::new(ErrorKind::Internal, "the source made no progress"));
                    }
                }
                Err(e) => return Err(Error::from_input(e)),
            }
        }
    }
}

impl<R: Read> Read for InputMeter<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let n = {
            let available = self.fill_buf()?;
            let n = available.len().min(out.len());
            if let (Some(to), Some(from)) = (out.get_mut(..n), available.get(..n)) {
                to.copy_from_slice(from);
            }
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl<R: Read> BufRead for InputMeter<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if let Some(error) = self.state.failure() {
            return Err(io::Error::from(error));
        }
        if self.cancel.as_ref().is_some_and(|token| token.is_canceled()) {
            return Err(self.fail(Error::new(ErrorKind::Canceled, "the reader was canceled")));
        }
        if self.pos >= self.filled {
            if let Err(error) = self.refill() {
                return Err(self.fail(error));
            }
        }
        let mut end = self.filled;
        if self.max_input > 0 && self.pos < self.filled {
            let allowance = self.max_input.saturating_sub(self.state.consumed());
            if allowance == 0 {
                // The probe byte exists: a MaxInput+1-th byte is being taken (SG-R-INP-01).
                let error = self.input_limit();
                return Err(self.fail(error));
            }
            let allowance = usize::try_from(allowance).unwrap_or(usize::MAX);
            end = end.min(self.pos.saturating_add(allowance));
        }
        self.visible = end;
        Ok(self.buf.get(self.pos..end).unwrap_or(&[]))
    }

    fn consume(&mut self, amount: usize) {
        // A codec must not consume more than it was shown; clamp so that the cap cannot be
        // bypassed and the count stays exact.
        let shown = self.visible.saturating_sub(self.pos);
        let amount = amount.min(shown);
        self.pos += amount;
        let consumed = self.state.0.consumed.get().saturating_add(amount as u64);
        self.state.0.consumed.set(consumed);
    }
}
