//! Errors returned by spillgate.
//!
//! Every refusal is an [`Error`] whose [`kind`](Error::kind) is one of the outcome classes of the
//! specification (section 2). Messages never contain more than 32 bytes of attacker-controlled
//! data, quoted and escaped (SG-R-HDR-13): use [`quote_untrusted`] for any such text.

use std::fmt;
use std::io;

/// The outcome classes of SPEC section 2 (`ok` is the absence of an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A limit parameter is missing, out of range or contradicts another one.
    InvalidLimits,
    /// A decoder option is invalid: an extension codec name is ill-formed, reserved or taken
    /// (SG-R-CDC-09).
    InvalidOption,
    /// A layer would have produced more than `max_output` bytes.
    OutputLimit,
    /// A layer (or the whole chain) expanded its input by more than `max_ratio`.
    RatioLimit,
    /// The `Content-Encoding` chain has too many layers or elements.
    LayerLimit,
    /// More than `max_input` compressed bytes were requested from the source.
    InputLimit,
    /// A codec would need more memory (window) than its cap allows.
    MemoryLimit,
    /// A well-formed token that no registered codec handles.
    UnsupportedEncoding,
    /// The `Content-Encoding` header itself is malformed.
    MalformedEncoding,
    /// The compressed data is invalid or truncated.
    Corrupt,
    /// A bug: a codec panicked or broke its contract, or a source made no progress.
    Internal,
    /// The reader was canceled.
    Canceled,
    /// The caller's source returned an error; it is available through [`Error::source`](std::error::Error::source).
    SourceError,
}

impl ErrorKind {
    /// The name used by the specification and the conformance corpus, e.g. `"output_limit"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::InvalidLimits => "invalid_limits",
            ErrorKind::InvalidOption => "invalid_option",
            ErrorKind::OutputLimit => "output_limit",
            ErrorKind::RatioLimit => "ratio_limit",
            ErrorKind::LayerLimit => "layer_limit",
            ErrorKind::InputLimit => "input_limit",
            ErrorKind::MemoryLimit => "memory_limit",
            ErrorKind::UnsupportedEncoding => "unsupported_encoding",
            ErrorKind::MalformedEncoding => "malformed_encoding",
            ErrorKind::Corrupt => "corrupt",
            ErrorKind::Internal => "internal",
            ErrorKind::Canceled => "canceled",
            ErrorKind::SourceError => "source_error",
        }
    }

    /// The HTTP status a server should answer for this outcome when decoding a request body:
    /// 413 for output, ratio, input and layer limits; 415 for an unsupported encoding; 400 for a
    /// malformed header, corrupt data and a failed read; 503 for the memory limit and cancellation;
    /// 500 otherwise.
    pub fn http_status(self) -> u16 {
        match self {
            ErrorKind::OutputLimit | ErrorKind::RatioLimit | ErrorKind::InputLimit | ErrorKind::LayerLimit => 413,
            ErrorKind::UnsupportedEncoding => 415,
            ErrorKind::MalformedEncoding | ErrorKind::Corrupt | ErrorKind::SourceError => 400,
            ErrorKind::MemoryLimit | ErrorKind::Canceled => 503,
            ErrorKind::InvalidLimits | ErrorKind::InvalidOption | ErrorKind::Internal => 500,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal of the data (or of the configuration).
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    layer: usize,
    limit: u64,
    cause: Option<io::Error>,
}

impl Error {
    /// A new error of `kind` with a message. The message must not contain unquoted untrusted data.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Error {
        Error {
            kind,
            message: message.into(),
            layer: 0,
            limit: 0,
            cause: None,
        }
    }

    /// The error for a stream that is invalid or truncated.
    pub fn corrupt(message: impl Into<String>) -> Error {
        Error::new(ErrorKind::Corrupt, message)
    }

    /// The error for a source failure; `cause` is returned by `source()`.
    pub fn source_error(cause: io::Error) -> Error {
        Error {
            kind: ErrorKind::SourceError,
            message: "the source failed".into(),
            layer: 0,
            limit: 0,
            cause: Some(cause),
        }
    }

    /// Attach the limit that was exceeded.
    #[must_use]
    pub fn with_limit(mut self, limit: u64) -> Error {
        self.limit = limit;
        self
    }

    /// Name the failing layer (1-based, layer 1 reads from the source) if none is named yet; the
    /// lowest layer wins.
    #[must_use]
    pub fn with_layer(mut self, layer: usize) -> Error {
        if self.layer == 0 && layer > 0 {
            self.layer = layer;
        }
        self
    }

    /// The outcome class.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// 1-based index of the failing layer, 0 if none.
    pub fn layer(&self) -> usize {
        self.layer
    }

    /// The limit that was exceeded, 0 if the kind has none.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// The human-readable message (no more than 32 bytes of attacker-controlled data).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// A copy without the cause, for sticky errors that are returned again on every later read.
    pub(crate) fn duplicate(&self) -> Error {
        Error {
            kind: self.kind,
            message: self.message.clone(),
            layer: self.layer,
            limit: self.limit,
            cause: self.cause.as_ref().map(|c| io::Error::new(c.kind(), c.to_string())),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spillgate: {}", self.kind)?;
        if self.layer > 0 {
            write!(f, " in layer {}", self.layer)?;
        }
        if self.limit > 0 {
            write!(f, " (limit {})", self.limit)?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|c| c as &(dyn std::error::Error + 'static))
    }
}

impl From<Error> for io::Error {
    /// `Read` implementations return spillgate errors wrapped in an `io::Error`; get the typed
    /// error back with [`Error::from_io`].
    fn from(error: Error) -> io::Error {
        let kind = match error.kind {
            ErrorKind::Corrupt | ErrorKind::MalformedEncoding => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, error)
    }
}

impl Error {
    /// Turn an `io::Error` met while reading codec input into an [`Error`]: a spillgate error
    /// (from the input meter or a lower layer) is returned as it is, anything else is the
    /// caller's source failing and becomes `source_error`.
    pub fn from_input(error: io::Error) -> Error {
        if error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = error.into_inner() {
                if let Ok(typed) = inner.downcast::<Error>() {
                    return *typed;
                }
            }
            return Error::new(ErrorKind::Internal, "an error went missing while it was unwrapped");
        }
        Error::source_error(error)
    }

    /// The spillgate error inside an `io::Error` returned by a spillgate reader, if there is one.
    pub fn from_io(error: &io::Error) -> Option<&Error> {
        error.get_ref().and_then(|inner| inner.downcast_ref::<Error>())
    }
}

/// Quote at most 32 bytes of untrusted text for use in a message: control and non-ASCII bytes are
/// escaped, quotes and backslashes too, and a longer text is cut and marked with `...`
/// (SG-R-HDR-13).
pub fn quote_untrusted(bytes: &[u8]) -> String {
    const MAX: usize = 32;
    let mut out = String::from("\"");
    for &b in bytes.iter().take(MAX) {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    if bytes.len() > MAX {
        out.push_str("...");
    }
    out.push('"');
    out
}
