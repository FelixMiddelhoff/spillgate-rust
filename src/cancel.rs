//! Cooperative cancellation (SG-R-API-04).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A flag that stops readers. Clone it, hand one clone to
/// [`Decoder::reader_with_cancel`](crate::Decoder::reader_with_cancel) and call
/// [`cancel`](CancelToken::cancel) from anywhere, for example from another thread.
///
/// A canceled reader fails with [`ErrorKind::Canceled`](crate::ErrorKind::Canceled), sticky. The
/// flag is looked at on every `read` call and every time a layer fetches more input, so at least
/// once per 4 KiB of compressed input and once per read. It is not a hard CPU bound: a single
/// codec step of at most 64 KiB of output still runs to its end.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token that is not canceled.
    pub fn new() -> CancelToken {
        CancelToken::default()
    }

    /// Cancel every reader that holds this token. Idempotent and safe to call from any thread.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether [`cancel`](CancelToken::cancel) was called.
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
