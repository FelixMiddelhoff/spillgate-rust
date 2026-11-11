# Conformance generators

The conformance corpus (`conformance/manifest.json`) describes large inputs by a generator specification instead of a file. Generation is deterministic and independent of any compression library, so every implementation, in any language, can reproduce the bytes and check them against the SHA-256 in the manifest. The Go implementation is `internal/corpus`.

A spec is `{"kind": "...", "params": {...}}`.

## Building blocks

**Bit packing.** DEFLATE fields are written starting at the least significant bit of each byte. Huffman codes are written most significant bit first.

**Data(seed, size).** xorshift64 over 64-bit unsigned arithmetic: `state = seed * 0x9e3779b97f4a7c15 + 1`; for each output byte: `state ^= state << 13; state ^= state >> 7; state ^= state << 17; byte = (state >> 24) & 0xff`. The bytes do not compress.

**StoredDeflate(data).** Stored blocks of at most 65535 bytes each: one header byte (BFINAL in bit 0, BTYPE 00), LEN and NLEN (little-endian), then the bytes. The last block has BFINAL set. Empty data is one empty final block.

**ZerosDeflate(matches).** One dynamic Huffman block that decodes to `1 + 258 * matches` zero bytes at about 1032:1:

| Field | Value |
|-------|-------|
| BFINAL, BTYPE | 1, 2 (dynamic) |
| HLIT, HDIST, HCLEN | 29, 1, 14 |
| code-length code lengths, order 16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1 | 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 2 0 2 |
| literal/length lengths | symbol 0: 2, symbol 256: 2, symbol 285: 1, all others 0 |
| distance lengths | symbol 0: 1, symbol 1: 1 |
| data | literal 0 (`10`), then `matches` times: length symbol 285 (`0`) and distance symbol 0 (`0`), then end of block (`11`) |

The literal/length and distance code lengths are written with the code-length alphabet: symbol 18 = `0` (7 extra bits, repeat count minus 11), symbol 1 = `10`, symbol 2 = `11`. The sequence is: 2; zero run 138; zero run 117; 2; zero run 28; 1; then the distance lengths 1, 1.

**gzip member.** Header `1f 8b 08 00 00 00 00 00 00 ff`, the raw DEFLATE stream, CRC-32 and size modulo 2^32 (both little-endian) of the decoded data. Optional header fields (FEXTRA, FNAME, FCOMMENT, FHCRC) follow RFC 1952.

**zlib stream.** Header `78 01`, the raw DEFLATE stream, Adler-32 of the decoded data (big-endian).

**Brotli (RFC 7932).** The stream starts with the WBITS field (`0` for 16; `1` plus 3 bits for 18..24 as `wbits-17`; `1`, `000`, `000` for 17; `1`, `000` plus 3 bits as `wbits-8` for 10..15). Meta-blocks follow, each starting with ISLAST `0`, MNIBBLES (`00` for 4 nibbles when MLEN-1 < 2^16, `01` for 5 when < 2^20, otherwise `10` for 6), and MLEN-1 in that many nibbles.
- *Zeros meta-block* (MLEN between 2122 and 2^24): ISUNCOMPRESSED `0`; NBLTYPESL, NBLTYPESI, NBLTYPESD = 1 (three `0` bits); NPOSTFIX 0 (2 bits); NDIRECT 0 (4 bits); one literal context mode 0 (2 bits); NTREESL = 1 and NTREESD = 1 (two `0` bits). Then three simple prefix codes, each written as HSKIP `1` (2 bits), NSYM-1 = `0` (2 bits) and one symbol: literal alphabet symbol 0 (8 bits), insert-and-copy alphabet symbol 423 (10 bits; insert length code 4, copy length code 23), distance alphabet symbol 0 (6 bits). Because every code has one symbol, symbols cost no bits. The data is one command whose copy length code 23 carries `MLEN - 4 - 2118` in 24 extra bits; the 4 inserted literals and the copy at distance 4 yield MLEN zero bytes. A stream of size S uses meta-blocks of 2^24 bytes plus one for the remainder (if the remainder is below 2122 it is merged into the previous block).
- *Stored meta-block*: ISUNCOMPRESSED `1`, padding to a byte boundary, then MLEN raw bytes (at most 2^24 per block).
- The stream ends with the empty last meta-block: ISLAST `1`, ISLASTEMPTY `1`, then padding.
- *Large-window marker*: the byte `0x11` (WBITS pattern 1000001) followed by anything.

**Zstandard (RFC 8878).** A frame is the magic `28 b5 2f fd`, a frame header descriptor byte (bits: FCS flag 7-6, single segment 5, reserved 3, checksum 2, dictionary flag 1-0), a window descriptor byte unless single-segment (`(windowLog - 10) << 3 | mantissa`), the dictionary id (0, 1, 2 or 4 bytes) and the frame content size (flag 0: 1 byte for single-segment frames, none otherwise; flag 1: 2 bytes holding size - 256; flag 2: 4 bytes; flag 3: 8 bytes). Blocks follow, each with a 3-byte little-endian header `size << 3 | type << 1 | last`. *Zeros*: RLE blocks (type 1) of up to 128 KiB, one byte `00` each: 4 bytes per 128 KiB, a ratio of 32768:1. *Stored*: raw blocks (type 0). A *skippable frame* is the magic `50 2a 4d 18`, a 4-byte size and that many bytes.

## Kinds

| Kind | Params | Result |
|------|--------|--------|
| `zeros` | `codec` (`gzip`, `zlib`, `raw`), `matches` | ZerosDeflate wrapped by the codec; decodes to `1 + 258 * matches` zeros |
| `zeros` | `codec` (`br`, `zstd`), `size`, `window` | zeros stream of `size` bytes; `window` is the brotli window bits (10..24) or the zstd window log (10..41) |
| `data` | `codec`, `seed`, `size` (and `window` for `br`, `zstd`) | the stored construction of Data(seed, size) wrapped by the codec |
| `wrap` | `codec`, `times`, `inner` (a spec; `window` for `br`, `zstd`) | the output of `inner`, wrapped `times` times in a stored stream of `codec` |

`raw` means no wrapper (a raw DEFLATE stream).
