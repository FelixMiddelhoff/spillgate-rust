//! Retained-memory sanity checks with a counting allocator (SG-R-MEM-02, SG-R-MEM-03, SG-I-08).
//!
//! The main crate forbids unsafe code even in its tests, so this lives in its own workspace.
//! One test function runs all scenarios in sequence: the allocator counters are global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{self, BufRead, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

use spillgate::{Codec, CodecReader, Decoder, Error, ErrorKind, Limits};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = CURRENT.fetch_add(by, Ordering::SeqCst) + by;
    PEAK.fetch_max(now, Ordering::SeqCst);
}

// SAFETY: forwards every call to the system allocator and only adds bookkeeping.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Peak bytes allocated above the level at the start of `f`.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    let peak = PEAK.load(Ordering::SeqCst);
    (out, peak.saturating_sub(base))
}

// -- test codecs ------------------------------------------------------------------------------------------

/// A bomb: `total` zero bytes from nothing.
struct Zeros(u64);
struct ZerosReader(u64);
impl CodecReader for ZerosReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = buf.len().min(usize::try_from(self.0).unwrap_or(usize::MAX));
        buf[..n].fill(0);
        self.0 -= n as u64;
        Ok(n)
    }
}
impl Codec for Zeros {
    fn new_reader<'a>(&self, _input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(ZerosReader(self.0))
    }
}

struct Pass;
struct PassReader<'a>(Box<dyn BufRead + 'a>);
impl CodecReader for PassReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = {
            let avail = self.0.fill_buf().map_err(Error::from_input)?;
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            n
        };
        self.0.consume(n);
        Ok(n)
    }
}
impl Codec for Pass {
    fn new_reader<'a>(&self, input: Box<dyn BufRead + 'a>) -> Box<dyn CodecReader + 'a> {
        Box::new(PassReader(input))
    }
}

struct Sink;
impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const MIB: usize = 1 << 20;

#[test]
fn memory_is_bounded_independently_of_the_output_size() {
    // Covers: SG-R-MEM-02 SG-R-MEM-03 SG-I-08 SG-R-CDC-07 SG-R-MEM-01

    // 1. A 4 GiB bomb against max_output 100 MiB: output_limit after 100 MiB, constant memory.
    let decoder = Decoder::builder(Limits::new(100 * MIB as u64).disable_ratio_limit())
        .codec("zeros", Zeros(4 << 30))
        .codec("pass", Pass)
        .build()
        .unwrap();
    let (result, peak) = peak_during(|| {
        let mut reader = decoder.reader(io::empty(), &["zeros"]).unwrap();
        io::copy(&mut reader, &mut Sink)
    });
    let e = result.unwrap_err();
    assert_eq!(Error::from_io(&e).unwrap().kind(), ErrorKind::OutputLimit);
    assert!(peak < 512 * 1024, "bomb peak {peak} bytes");

    // 2. The same through a chain of 16 pass-through layers: still constant, a few buffers per layer.
    let decoder16 = Decoder::builder(Limits::new(50 * MIB as u64).disable_ratio_limit().max_layers(16))
        .codec("zeros", Zeros(4 << 30))
        .codec("pass", Pass)
        .build()
        .unwrap();
    let header = format!("{}, zeros", vec!["pass"; 15].join(", "));
    let (result, peak) = peak_during(|| {
        let mut reader = decoder16.reader(io::empty(), &[&header]).unwrap();
        io::copy(&mut reader, &mut Sink)
    });
    assert_eq!(
        Error::from_io(&result.unwrap_err()).unwrap().kind(),
        ErrorKind::OutputLimit
    );
    assert!(peak < 2 * MIB, "16 layer peak {peak} bytes");

    // 3. One-byte reads cost the same constant memory.
    let (n, peak) = peak_during(|| {
        let mut reader = decoder.reader(io::empty(), &["zeros"]).unwrap();
        let mut one = [0u8; 1];
        let mut n = 0u64;
        while n < 2_000_000 {
            n += reader.read(&mut one).unwrap() as u64;
        }
        n
    });
    assert_eq!(n, 2_000_000);
    assert!(peak < 256 * 1024, "1-byte read peak {peak} bytes");

    // 4. decode_all grows with the output it produced, never with max_output.
    let huge = Decoder::builder(Limits::new((1 << 63) - 1).disable_ratio_limit())
        .codec("zeros", Zeros(3 * MIB as u64))
        .build()
        .unwrap();
    let (out, peak) = peak_during(|| huge.decode_all(io::empty(), &["zeros"]).unwrap());
    assert_eq!(out.len(), 3 * MIB);
    assert!(
        peak <= 2 * out.len() + MIB,
        "decode_all peak {peak} for {} output bytes",
        out.len()
    );
    drop(out);
    let (out, peak) = peak_during(|| huge.decode_all(&b"tiny"[..], &[]).unwrap());
    assert_eq!(out, b"tiny");
    assert!(
        peak < 256 * 1024,
        "decode_all of 4 bytes with max_output 2^63-1 peaked at {peak}"
    );

    // 5. A failed decode_all does not keep the partial output.
    let small = Decoder::builder(Limits::new(10 * MIB as u64).disable_ratio_limit())
        .codec("zeros", Zeros(1 << 40))
        .build()
        .unwrap();
    let ((), after) = {
        let before = CURRENT.load(Ordering::SeqCst);
        let e = small.decode_all(io::empty(), &["zeros"]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::OutputLimit);
        ((), CURRENT.load(Ordering::SeqCst).saturating_sub(before))
    };
    assert!(
        after < 64 * 1024,
        "{after} bytes are still allocated after the failed call"
    );

    // 6. Nothing is retained after close: the buffers of all layers are released.
    let before = CURRENT.load(Ordering::SeqCst);
    {
        let mut reader = decoder16.reader(io::empty(), &[&header]).unwrap();
        let mut buf = [0u8; 100];
        assert!(reader.read(&mut buf).unwrap() > 0);
        assert!(CURRENT.load(Ordering::SeqCst) > before);
        reader.close();
        let held = CURRENT.load(Ordering::SeqCst).saturating_sub(before);
        assert!(held < 16 * 1024, "{held} bytes held after close");
    }
}
