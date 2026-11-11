# spillgate specification

Version: 0.1-draft. Normative for all spillgate implementations in every language.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

Every normative rule has an ID of the form `SG-R-<AREA>-<nn>` and sits on its own bullet starting with that ID in bold. Invariants have IDs `SG-I-<nn>`. Each rule and each invariant MUST be covered by at least one conformance vector or one test that names the ID (see `conformance/SCHEMA.md`).

## 1. Purpose and scope

spillgate decodes untrusted compressed data (HTTP `Content-Encoding` chains and raw gzip, deflate, brotli and zstd streams) under mandatory limits, so that a hostile input can cause at most a clean, typed error and bounded resource use.

In scope: output size, expansion ratio, chain length, header handling, decoder memory caps, stream validity, streaming behavior.
Out of scope: archive formats (zip, tar, 7z), encryption, network timeouts, bounding the size of the compressed input beyond the optional `MaxInput`, vulnerabilities inside third-party codecs beyond what the limiter can contain.

## 2. Terms

- **Source**: the caller's byte stream of compressed (or uncompressed) data. Owned by the caller.
- **Layer**: one decoding step for one non-identity `Content-Encoding` token.
- **Layer 1** is the first layer applied, i.e. the **last** token in the header; it reads from the source. Layer *n* is the last layer applied; its output is what the caller reads.
- **Produced bytes** *P(k)*: bytes layer *k*'s codec has emitted so far.
- **Consumed bytes** *C(k)*: bytes layer *k*'s codec has taken from its input so far (see SG-R-RAT-02).
- **Terminal condition**: clean end, or an error. After it, no further bytes are produced.
- **Outcome class**: one of `ok`, `output_limit`, `ratio_limit`, `layer_limit`, `input_limit`, `memory_limit`, `unsupported_encoding`, `malformed_encoding`, `invalid_limits`, `corrupt`, `internal`, `canceled`, `source_error`.

## 3. Parameters

| Parameter | Type | Default | Valid |
|-----------|------|---------|-------|
| MaxOutput | signed 64-bit integer (bytes) | none, required | 1 .. 2^63-1 |
| MaxLayers | integer | 5 | 1 .. 16 |
| MaxRatio | positive integer (output bytes per consumed input byte) | 1000 (provisional) | 1 .. 2^31-1, or the named opt-out |
| RatioGrace | non-negative integer (bytes) | 65536 (provisional) | 0 .. 2^63-1 |
| MaxInput | positive integer (bytes), optional | absent | 1 .. 2^63-1 |

- **SG-R-LIM-01** MaxOutput has no default. An unset, zero, negative or non-integer MaxOutput MUST fail with `invalid_limits` before any byte is read from the source.
- **SG-R-LIM-02** An implementation MUST support MaxOutput up to 2^63-1 without arithmetic overflow. Platforms whose native integers are narrower (for example JavaScript numbers) MUST either use arbitrary-width integers or reject larger values with `invalid_limits`, and MUST document the maximum.
- **SG-R-LIM-03** MaxLayers defaults to 5 when unset. Values outside 1..16 (including 0 given explicitly) MUST fail with `invalid_limits`. A binding whose zero value cannot be told apart from "unset" (for example Go structs) maps zero to the default for MaxLayers, MaxRatio and RatioGrace and documents it. It MUST NOT do so for MaxOutput.
- **SG-R-LIM-04** MaxRatio defaults to 1000 when unset. Explicit values outside 1..2^31-1 MUST fail with `invalid_limits`. The ratio check can be disabled only by one distinct, explicit opt-out (for example a dedicated boolean); no numeric value of MaxRatio, including zero and negatives, disables it. Supplying both a MaxRatio and the opt-out is `invalid_limits`.
- **SG-R-LIM-05** RatioGrace defaults to 65536 when unset. Negative values MUST fail with `invalid_limits`. Zero is valid where the binding can express it and means the ratio is checked from the first produced byte; a binding that maps zero to the default documents that a grace of 1 byte has the same effect.
- **SG-R-LIM-06** MaxInput is absent by default (no input cap). If supplied it MUST be greater than zero, else `invalid_limits`. Zero MUST NOT mean "unlimited".
- **SG-R-LIM-07** No value of MaxOutput or MaxLayers disables or weakens the corresponding limit. The only opt-outs that exist are the named ratio opt-out and the absence of MaxInput.
- **SG-R-LIM-08** All parameters MUST be validated completely at construction, before any byte is read from the source and before any codec state is allocated.
- **SG-R-LIM-09** Parameters are captured by value at construction. Later mutation of the caller's data structure MUST NOT change a constructed decoder.

## 4. Header processing

Input is a sequence of zero or more `Content-Encoding` field values, as separate strings, in the order received.

Evaluation order is normative and decides the outcome class when several faults are present: (1) total length, (2) element splitting and per-element grammar, left to right, first fault wins, (3) element count, (4) alias resolution and support check over all elements, (5) layer count against MaxLayers.

- **SG-R-HDR-01** The field values are joined in order with `,` into one list. A sequence of zero values is the empty chain (identity only).
- **SG-R-HDR-02** If the joined list is longer than 1024 bytes the result is `malformed_encoding`.
- **SG-R-HDR-03** The list is split at `,`. Space and horizontal tab around each element are trimmed. Empty elements (a leading, trailing or doubled comma, or a field value that is empty or only whitespace) are ignored, as RFC 9110 section 5.6.1.2 requires of recipients, and do not count as elements. Their number is bounded by the 1024-byte cap of SG-R-HDR-02. A list with no non-empty element is the empty chain.
- **SG-R-HDR-04** Each trimmed element MUST match `[A-Za-z0-9][A-Za-z0-9._-]{0,31}`. Anything else (parameters, quotes, semicolons, control characters, non-ASCII bytes, longer tokens) is `malformed_encoding`.
- **SG-R-HDR-05** Token comparison is ASCII case-insensitive. No Unicode normalization or folding is performed.
- **SG-R-HDR-06** More than 16 non-empty elements, counting `identity`, is `layer_limit`, independent of MaxLayers.
- **SG-R-HDR-07** The only alias is `x-gzip` for `gzip` (RFC 9110 section 8.4.1.3). `x-compress` is treated like `compress`: unsupported.
- **SG-R-HDR-08** Supported tokens are `identity`, `gzip`, `deflate`, plus `br` and `zstd` when the corresponding codec is available, plus tokens of explicitly registered extension codecs (SG-R-CDC-09). Any other well-formed token (for example `compress`, `dcb`, `dcz`, `aes128gcm`, `snappy`, `deflate64`) is `unsupported_encoding`.
- **SG-R-HDR-09** Support is checked for the whole list at construction. A chain with any unsupported element MUST NOT be partially decoded, and MUST NOT start reading the source.
- **SG-R-HDR-10** `identity` is a no-op (RFC 9110 discourages sending it but allows it). It does not count as a layer for MaxLayers but counts toward the 16-element cap of SG-R-HDR-06.
- **SG-R-HDR-11** The number of non-identity layers greater than MaxLayers is `layer_limit`, reported at construction.
- **SG-R-HDR-12** Decoding order is the reverse of the listed order (the last listed token is layer 1).
- **SG-R-HDR-13** Error messages MUST NOT contain more than 32 bytes of attacker-controlled data, and any such data MUST be quoted and escaped so it cannot inject control characters or forge log lines.
- **SG-R-HDR-14** Equivalent presentations MUST yield the same result: one comma-separated value and several field values with the same elements in the same order are identical; case variants of a token are identical; inserted empty elements and whitespace change nothing.

## 5. Layer semantics

- **SG-R-LAY-01** Every layer has its own output budget equal to MaxOutput. This includes intermediate layers and the identity-only chain. An intermediate layer exceeding MaxOutput is `output_limit` even if later layers would shrink the data.
- **SG-R-LAY-02** A layer MUST NOT deliver more than MaxOutput bytes to its consumer, under any read pattern, any input and any chain position.
- **SG-R-LAY-03** Exactly MaxOutput produced bytes followed by a valid clean end of the stream is success. Production of a MaxOutput+1-th byte is `output_limit`. The implementation MUST detect the extra byte without delivering it, and MUST NOT report success before the stream has been validated up to its end marker and trailer.
- **SG-R-LAY-04** A limit hit MUST surface as a typed error. It MUST NOT surface as end-of-stream, and data MUST NOT be silently truncated.
- **SG-R-LAY-05** Terminal errors are sticky: every later read returns the same outcome class. A terminal clean end is sticky too.
- **SG-R-LAY-06** In streaming mode bytes may be delivered before a later error. Consumers MUST treat any error as failure of the whole body. The whole-body convenience function MUST return no data when any error occurs (SG-R-API-02).
- **SG-R-LAY-07** Conditions are evaluated in stream order as bytes are produced; the first condition that becomes true decides the outcome. In particular, corruption detected before the MaxOutput+1-th byte is `corrupt`; a bad trailer after exactly MaxOutput bytes is `corrupt`; a stream longer than MaxOutput is `output_limit` even if its trailer would have been bad.
- **SG-R-LAY-08** Only bytes actually produced by a codec are counted. Sizes declared in headers or trailers are never counted (SG-R-CDC-07).
- **SG-R-LAY-09** After a terminal condition the implementation MUST NOT read further from the source. Lookahead of the codec is bounded by 64 KiB beyond what the codec needed.

## 6. Ratio

- **SG-R-RAT-01** For each layer *k*: when *P(k)* > RatioGrace and *P(k)* > MaxRatio × max(*C(k)*, 1), the result is `ratio_limit`. The comparison MUST be done in arithmetic that cannot overflow (widen or saturate).
- **SG-R-RAT-02** *C(k)* counts bytes at the point where the codec takes them, not where the source is read. Read-ahead buffers MUST NOT give credit: the credit for look-ahead is at most 64 KiB (the tolerance *T*). Implementations may therefore differ by at most *T* input bytes in when the ratio fires.
- **SG-R-RAT-03** The same check is applied end to end: final output against bytes consumed from the source.
- **SG-R-RAT-04** The named ratio opt-out disables SG-R-RAT-01 and SG-R-RAT-03 only. MaxOutput, MaxLayers and MaxInput stay in force.
- **SG-R-RAT-05** Conformance vectors for the ratio keep at least a factor 2 margin from the threshold plus *T*, so that correct implementations agree.

## 7. Input limit

- **SG-R-INP-01** If MaxInput is set, a codec taking a MaxInput+1-th byte from the source is `input_limit`. It applies to the chain's source (layer 1 input), also for identity-only chains. A stream that fits in MaxInput bytes is unaffected even if the source holds more bytes after it.
- **SG-R-INP-02** With MaxInput set the implementation MUST NOT request more than MaxInput+1 bytes from the source in total; the one extra byte is the probe that detects the violation.

## 8. Codecs

- **SG-R-CDC-01** All codecs, including extension codecs, MUST go through the same limiter, ratio meter and input meter. No codec has a private path around them.
- **SG-R-CDC-02** gzip (RFC 1952): multiple concatenated members are decoded and share one budget. The following are `corrupt`: a member that does not start with the bytes 0x1f 0x8b 0x08; reserved flag bits set (RFC 1952 requires an error); a wrong header CRC (FHCRC); a FNAME or FCOMMENT that is not terminated within 512 bytes including the terminator (RFC 1952 sets no limit; this bound is deliberate and equals the Go standard library's); a CRC32 or ISIZE mismatch at the end of any member; and any bytes after a complete member that do not start a valid member, including zero padding. ISIZE is compared modulo 2^32 and never used as an allowance. A truncated member is `corrupt` (SG-R-CDC-06).
- **SG-R-CDC-03** deflate in HTTP means the zlib format (RFC 1950 wrapping RFC 1951), per RFC 9110 section 8.4.1.2, which also notes that some senders omit the wrapper. Detection: if the first two bytes form a valid zlib header (CM = 8, CINFO ≤ 7, CMF×256+FLG a multiple of 31) the stream is zlib, otherwise it is raw deflate. A zlib stream with FDICT set is `corrupt` (it is not retried as raw). For zlib the Adler-32 is verified and bytes after it are `corrupt`; for raw deflate bytes after the final block are `corrupt`. A raw stream that happens to begin with a valid-looking zlib header is therefore treated as zlib and fails with `corrupt`; it is never misread as data. An option `strict_zlib` disables the raw fallback; without a valid zlib header the stream is then `corrupt`.
- **SG-R-CDC-04** brotli (RFC 7932): the format allows window sizes up to 2^24-16 bytes (WBITS 24); that is the default cap. Any stream needing a larger window is `memory_limit`. Large-window brotli is not part of the RFC; it announces itself with the reserved WBITS pattern 1000001, and an implementation that does not support it MUST report `memory_limit` for such a stream whatever the cap is (an implementation that does support it applies its cap to the window the stream declares). The window is read from the first byte(s) of the stream, before any decoding. Bytes after the last meta-block are `corrupt` (the RFC is silent; fail closed).
- **SG-R-CDC-05** zstd (RFC 8878, RFC 9659): the default window cap is 8 MiB (8388608 bytes), which is at least the 8 MB that RFC 9659 requires decoders to support. A frame whose window size exceeds the cap is `memory_limit`; for single-segment frames the window size equals the declared content size, so the cap applies to it as well. A frame that needs a dictionary (non-zero Dictionary_ID) is `corrupt`. Concatenated frames and skippable frames are allowed; skippable frames count as consumed input only. A present content checksum is verified. A declared content size that contradicts the produced size SHOULD be reported as `corrupt`; vectors do not depend on this because produced bytes are always counted. (Implementations may detect the mismatch as soon as the output exceeds the declared size, which can come before the output limit; either refusal is correct, and never more than MaxOutput bytes are delivered.) The checks of this rule happen on the frame header, before the frame is decoded; a block larger than 128 KiB and the reserved block type are `corrupt`. Trailing bytes that are not a valid frame start are `corrupt`.
- **SG-R-CDC-06** A stream that ends before its end marker or trailer is `corrupt`, never a clean end, for every codec.
- **SG-R-CDC-07** Declared sizes (gzip ISIZE, zstd frame content size, any length field in any header) MUST NOT be used for any decision, early rejection, or allowance, and MUST NOT size an allocation. The single exception is the decoder window of SG-R-CDC-04 and SG-R-CDC-05, which is a memory declaration and is checked against the cap.
- **SG-R-CDC-08** A codec that panics, throws unexpectedly, violates its read contract, or returns more bytes than requested ends the stream with `internal`. The failure MUST NOT escape the library as a crash of the host.
- **SG-R-CDC-09** Extension codecs are registered explicitly on a decoder instance. There is no process-global registry and no registration at import time. Registration MUST NOT replace or alias the built-in names `identity`, `gzip`, `deflate` and `x-gzip`; the optional codecs `br` and `zstd` are supplied through registration by their modules. The name MUST satisfy SG-R-HDR-04 and be lowercase; registering a name twice is an error.
- **SG-R-CDC-10** `identity` passes bytes through the limiter, so unencoded bodies are bounded by MaxOutput too.

## 9. Reader contract

- **SG-R-RDR-01** For the same input and parameters, the concatenation of delivered bytes and the final outcome class are independent of the sequence of read sizes used by the caller (1 byte, 1 MiB, larger than MaxOutput, mixed). The bytes delivered are always a prefix of the same decoded stream. One difference is allowed: when the outcome is `ratio_limit`, the length of the delivered prefix may depend on the read sizes, because the ratio is judged once per codec step and a larger read can take a larger step (and, when the stream's own ratio is close to MaxRatio, the check can flip on single input bytes, so the gap is not bounded by a fixed number of steps). The outcome class is the same, and MaxOutput still bounds what is delivered. For every other outcome class the delivered bytes are exactly the same.
- **SG-R-RDR-02** A zero-length read does not consume input and does not change state. It MAY return the sticky terminal condition.
- **SG-R-RDR-03** A source that returns zero bytes without error 100 times in a row yields `internal` (no progress).
- **SG-R-RDR-04** A source that reports more bytes than requested yields `internal`.
- **SG-R-RDR-05** An error from the source is propagated as `source_error` carrying the original error; it is not reported as `corrupt`. A source that ends early is `corrupt` (SG-R-CDC-06).
- **SG-R-RDR-06** Close is idempotent, releases all codec state and background workers, and does not close the caller's source. A read after Close fails with a closed error.
- **SG-R-RDR-07** Distinct readers are independent. A decoder configuration object is immutable and safe for concurrent use; a reader is not safe for concurrent use unless the language binding documents otherwise.

## 10. Memory

- **SG-R-MEM-01** No allocation may be sized from an untrusted value (declared sizes, header values, lengths in streams) beyond a fixed bound of 64 KiB per value, except decoder windows within their caps. (The gzip extra field, at most 65535 bytes by format, is the one case that needs the allowance.)
- **SG-R-MEM-02** Apart from codec windows within their caps, memory use is bounded by a fixed constant (documented per binding, at most 4 MiB per layer) plus, for whole-body functions, the bytes produced so far. Whole-body functions grow their buffer incrementally and never preallocate from MaxOutput.
- **SG-R-MEM-03** Each binding documents the peak memory bound per codec and per layer, and tests it (resource tests).

## 11. API shape (language neutral)

- **SG-R-API-01** There is no entry point that decodes without Limits. A binding MUST NOT expose a convenience that omits MaxOutput.
- **SG-R-API-02** The whole-body function returns either the complete body or an error, never partial data.
- **SG-R-API-03** Validation failures (`invalid_limits`, `malformed_encoding`, `unsupported_encoding`, `layer_limit` from the header) surface at construction, not on first read.
- **SG-R-API-04** If cancellation is supported, it is observed at least once per read call and at least once per 64 KiB consumed. Cancellation yields `canceled`, sticky. It is not a hard CPU bound inside one codec call and is documented as such.
- **SG-R-API-05** Failures carry the outcome class in a machine-checkable form (typed error, error code, or exception class) and optionally the layer index and the limit value.

## 12. Invariants

Each invariant MUST have at least three independent checks (unit test, conformance vector, fuzz or property test).

- **SG-I-01** A layer never delivers more than MaxOutput bytes (SG-R-LAY-02, SG-R-LAY-03, SG-R-RDR-01).
- **SG-I-02** Exceeding any limit yields a typed error, never end-of-stream and never silent truncation (SG-R-LAY-04, SG-R-RAT-01, SG-R-INP-01).
- **SG-I-03** Terminal conditions are sticky (SG-R-LAY-05).
- **SG-I-04** Declared sizes never raise an allowance and never size an allocation (SG-R-CDC-07, SG-R-MEM-01).
- **SG-I-05** No panic or exception from any input escapes (SG-R-CDC-08).
- **SG-I-06** Unknown, unsupported and malformed encodings never produce partial passthrough (SG-R-HDR-09, SG-R-API-03).
- **SG-I-07** Chain depth, element count and header length are bounded (SG-R-HDR-02, SG-R-HDR-06, SG-R-HDR-11).
- **SG-I-08** Peak memory is bounded independently of the output size (SG-R-MEM-01, SG-R-MEM-02).
- **SG-I-09** Results do not depend on read sizes or source chunking (SG-R-RDR-01).
- **SG-I-10** Nothing outlives Close: no worker, handle or retained buffer (SG-R-RDR-06).

## 13. Appendix A: verification log and deliberate deviations

Verified against the primary texts on 2026-11-06 (unless marked): RFC 1950 (CM, CINFO, FCHECK, FDICT, Adler-32), RFC 1952 (magic, CM = 8, reserved flags MUST error, no length limit on FNAME/FCOMMENT, no statement about trailing data, ISIZE modulo 2^32), RFC 7932 section 2 (WBITS 10..24, window 2^WBITS-16; no statement about bytes after the stream), RFC 9659 section 3 (decoders MUST support Window_Size up to 8 MB, encoders MUST NOT exceed it, oversized frames are to be rejected), RFC 8878 (window formula, single-segment window equals content size, Frame_Content_Size optional, Dictionary_ID, checksum), RFC 9110 sections 8.4 and 8.4.1 (list grammar `#content-coding`, tokens carry no parameters, deflate is zlib-wrapped, `x-gzip` equivalent to gzip, order of application, identity discouraged) and the Go 1.26.1 standard library (`compress/gzip` ends names at 512 bytes and ignores reserved flag bits).
Verified from a summary only, to be re-read when the tests are written: RFC 9110 section 5.6.1.2 (empty list elements), RFC 8878 skippable-frame magic range 0x184D2A50..0x184D2A5F.

Deliberate deviations from the RFCs (all fail closed): bytes after a gzip member, zlib stream, brotli stream or zstd frame sequence are errors; gzip names and comments are bounded to 512 bytes; header tokens are restricted to a stricter alphabet than RFC 9110 `token`; the zstd window cap is 8 MiB.

## 14. Conformance

An implementation conforms if it passes every vector of the released conformance corpus for the codecs it supports and has tests for every rule that vectors cannot express (header error text, resource bounds, close behavior). Vectors compare outcome class, delivered length and SHA-256 of delivered bytes; error texts are not compared. See `conformance/SCHEMA.md`.
