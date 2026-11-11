//! The public entry points: [`Decoder`], [`DecoderBuilder`] and [`decode_all`].

use std::collections::HashMap;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::codec::{Codec, CodecReader};
use crate::deflate::DeflateCodec;
use crate::error::{quote_untrusted, Error, ErrorKind};
use crate::guard::{LayerGuard, Passthrough};
use crate::gzip::GzipCodec;
use crate::header::{is_token, parse_content_encoding, resolve_layers, IDENTITY};
use crate::limits::{EffectiveLimits, Limits};
use crate::meter::InputMeter;
use crate::reader::SpillgateReader;

/// Names an extension codec may not take (SG-R-CDC-09).
const RESERVED_NAMES: [&str; 4] = [IDENTITY, "gzip", "deflate", "x-gzip"];

/// Turns `Content-Encoding` chains into bounded readers.
///
/// A decoder is immutable after construction and `Send + Sync`; share one per process. The readers
/// it returns are independent of each other and not meant to be shared between threads
/// (SG-R-RDR-07). Every check that depends only on the limits and options happens in
/// [`build`](DecoderBuilder::build), before any byte is read (SG-R-LIM-08).
pub struct Decoder {
    limits: EffectiveLimits,
    codecs: HashMap<String, Box<dyn Codec>>,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&String> = self.codecs.keys().collect();
        names.sort();
        f.debug_struct("Decoder")
            .field("limits", &self.limits)
            .field("codecs", &names)
            .finish()
    }
}

/// Collects options for a [`Decoder`]. Errors surface in [`build`](DecoderBuilder::build).
pub struct DecoderBuilder {
    limits: Limits,
    strict_zlib: bool,
    codecs: Vec<(String, Box<dyn Codec>)>,
}

impl DecoderBuilder {
    /// Refuse `deflate` data without a zlib header instead of trying raw DEFLATE (SG-R-CDC-03).
    #[must_use]
    pub fn strict_zlib(mut self, on: bool) -> DecoderBuilder {
        self.strict_zlib = on;
        self
    }

    /// Register an extension codec under `name` (SG-R-CDC-09), for example brotli or zstd. The
    /// name must be a lower-case token (SG-R-HDR-04), must not be `identity`, `gzip`, `deflate` or
    /// `x-gzip`, and must not be registered twice; otherwise [`build`](DecoderBuilder::build)
    /// fails with [`ErrorKind::InvalidOption`].
    #[must_use]
    pub fn codec(mut self, name: &str, codec: impl Codec + 'static) -> DecoderBuilder {
        self.codecs.push((name.to_string(), Box::new(codec)));
        self
    }

    /// Validate everything and capture it by value (SG-R-LIM-08, SG-R-LIM-09).
    ///
    /// # Errors
    /// [`ErrorKind::InvalidLimits`] for bad limits, [`ErrorKind::InvalidOption`] for a bad codec
    /// registration.
    pub fn build(self) -> Result<Decoder, Error> {
        let limits = EffectiveLimits::from_limits(&self.limits)?;
        let mut codecs: HashMap<String, Box<dyn Codec>> = HashMap::new();
        codecs.insert("gzip".to_string(), Box::new(GzipCodec));
        codecs.insert("deflate".to_string(), Box::new(DeflateCodec::new(self.strict_zlib)));
        for (name, codec) in self.codecs {
            if !is_token(name.as_bytes()) || name.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(Error::new(
                    ErrorKind::InvalidOption,
                    format!(
                        "codec name {} must be a lower-case token (SG-R-HDR-04)",
                        quote_untrusted(name.as_bytes())
                    ),
                ));
            }
            if RESERVED_NAMES.contains(&name.as_str()) {
                return Err(Error::new(
                    ErrorKind::InvalidOption,
                    format!("codec name \"{name}\" is reserved for a built-in encoding"),
                ));
            }
            if codecs.contains_key(&name) {
                return Err(Error::new(
                    ErrorKind::InvalidOption,
                    format!("codec \"{name}\" is registered twice"),
                ));
            }
            codecs.insert(name, codec);
        }
        Ok(Decoder { limits, codecs })
    }
}

impl Decoder {
    /// A decoder with the built-in codecs (`identity`, `gzip`, `deflate`) under `limits`.
    /// Shorthand for `Decoder::builder(limits).build()`.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidLimits`] if the limits are invalid.
    pub fn new(limits: Limits) -> Result<Decoder, Error> {
        Decoder::builder(limits).build()
    }

    /// Start building a decoder; limits are mandatory (SG-R-API-01).
    pub fn builder(limits: Limits) -> DecoderBuilder {
        DecoderBuilder {
            limits,
            strict_zlib: false,
            codecs: Vec::new(),
        }
    }

    /// A reader of the decoded bytes of `source`. `content_encoding` holds the header field values
    /// as received, e.g. `&["gzip, br", "zstd"]`. Every check that depends only on the header
    /// happens here, before the source is touched (SG-R-HDR-09, SG-R-API-03).
    ///
    /// # Errors
    /// [`ErrorKind::MalformedEncoding`], [`ErrorKind::LayerLimit`] or
    /// [`ErrorKind::UnsupportedEncoding`] if the header is refused.
    pub fn reader<'a, R: Read + 'a>(&self, source: R, content_encoding: &[&str]) -> Result<SpillgateReader<'a>, Error> {
        let elements = parse_content_encoding(content_encoding)?;
        let layers = resolve_layers(elements, |name| self.codecs.contains_key(name), self.limits.max_layers)?;
        self.build_chain(Box::new(source), &layers, None)
    }

    /// Like [`reader`](Decoder::reader), and the reader stops with [`ErrorKind::Canceled`] (sticky)
    /// once `token` is canceled. See [`CancelToken`](crate::CancelToken) for what is and is not
    /// interrupted (SG-R-API-04).
    ///
    /// # Errors
    /// As [`reader`](Decoder::reader).
    pub fn reader_with_cancel<'a, R: Read + 'a>(
        &self,
        source: R,
        content_encoding: &[&str],
        token: &crate::cancel::CancelToken,
    ) -> Result<SpillgateReader<'a>, Error> {
        let elements = parse_content_encoding(content_encoding)?;
        let layers = resolve_layers(elements, |name| self.codecs.contains_key(name), self.limits.max_layers)?;
        self.build_chain(Box::new(source), &layers, Some(token.clone()))
    }

    /// Decode `source` completely: the whole body, or an error and no data (SG-R-API-02). The
    /// buffer grows with the bytes produced, never from `max_output` (SG-R-MEM-02).
    ///
    /// # Errors
    /// Any [`Error`] of [`reader`](Decoder::reader) or of reading.
    pub fn decode_all<R: Read>(&self, source: R, content_encoding: &[&str]) -> Result<Vec<u8>, Error> {
        let mut reader = self.reader(source, content_encoding)?;
        let result = reader.read_all();
        reader.close();
        result
    }

    fn build_chain<'a>(
        &self,
        source: Box<dyn Read + 'a>,
        layers: &[String],
        cancel: Option<crate::cancel::CancelToken>,
    ) -> Result<SpillgateReader<'a>, Error> {
        let mut current = source;
        let mut first = None;
        let count = layers.len().max(1);
        for index in 1..=count {
            // The input cap applies to the chain's source only (SG-R-INP-01).
            let cap = if index == 1 { self.limits.max_input } else { 0 };
            let meter = InputMeter::new(current, cap, index).with_cancel(cancel.clone());
            let handle = meter.handle();
            let first_handle = first.get_or_insert_with(|| handle.clone()).clone();
            let input: Box<dyn std::io::BufRead + 'a> = Box::new(meter);
            let codec_reader: Box<dyn CodecReader + 'a> = match layers.get(index - 1) {
                // identity-only chain: bytes pass through the guard
                None => Box::new(Passthrough::new(input)),
                Some(name) => self.new_codec_reader(name, input, index)?,
            };
            let guard = LayerGuard::new(codec_reader, handle, index, self.limits);
            if index == count {
                return Ok(SpillgateReader::new(guard, first_handle, self.limits).with_cancel(cancel));
            }
            current = Box::new(guard);
        }
        Err(Error::new(ErrorKind::Internal, "empty layer chain"))
    }

    fn new_codec_reader<'a>(
        &self,
        name: &str,
        input: Box<dyn std::io::BufRead + 'a>,
        layer: usize,
    ) -> Result<Box<dyn CodecReader + 'a>, Error> {
        let Some(codec) = self.codecs.get(name) else {
            return Err(Error::new(ErrorKind::Internal, "codec table changed").with_layer(layer));
        };
        // A codec that panics while it is constructed is contained like one that panics later.
        catch_unwind(AssertUnwindSafe(|| codec.new_reader(input))).map_err(|payload| {
            let _ = catch_unwind(AssertUnwindSafe(move || drop(payload)));
            Error::new(
                ErrorKind::Internal,
                format!("creating the {} decoder failed", quote_untrusted(name.as_bytes())),
            )
            .with_layer(layer)
        })
    }
}

/// Decode `source` completely under `limits`: the whole body, or an error (SG-R-API-02). No call
/// omits the limits (SG-R-API-01).
///
/// # Errors
/// Any [`Error`]; see [`Decoder::decode_all`].
pub fn decode_all<R: Read>(source: R, content_encoding: &[&str], limits: Limits) -> Result<Vec<u8>, Error> {
    Decoder::new(limits)?.decode_all(source, content_encoding)
}
