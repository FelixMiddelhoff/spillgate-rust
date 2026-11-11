//! Peak heap of the brotli codec with a counting allocator (SG-R-CDC-04, SG-R-CDC-07, SG-R-MEM-01,
//! SG-R-MEM-02, SG-I-04, SG-I-08). Lives in this workspace because the main crate forbids unsafe code.
//! One test function: the allocator counters are global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

use spillgate::br::{self, BrotliOptions};
use spillgate::{Decoder, Error, ErrorKind, Limits};
use spillgate_test_support::{brotli_large_window_prefix, brotli_stored, brotli_zeros, BitWriter};

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

const MIB: usize = 1 << 20;

fn decoder(max_output: u64, cap: u32) -> Decoder {
    Decoder::builder(Limits::new(max_output).disable_ratio_limit())
        .codec("br", br::codec(BrotliOptions { max_window_bits: cap }).unwrap())
        .build()
        .unwrap()
}

/// Decode `stream`; returns the error kind (None = clean end) and the number of bytes delivered.
fn decode(d: &Decoder, stream: &[u8]) -> (Option<ErrorKind>, u64) {
    let mut reader = d.reader(stream, &["br"]).unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let kind = loop {
        match reader.read(&mut buf) {
            Ok(0) => break None,
            Ok(n) => total += n as u64,
            Err(e) => break Some(Error::from_io(&e).unwrap().kind()),
        }
    };
    reader.close();
    (kind, total)
}

/// RFC 7932 VarLenUint8 for NBLTYPES / NTREES (value 1..=256).
fn var_len(w: &mut BitWriter, value: u32) {
    if value == 1 {
        w.bits(0, 1);
        return;
    }
    let v = value - 1;
    w.bits(1, 1);
    if v == 1 {
        w.bits(0, 3);
        return;
    }
    let n = 31 - v.leading_zeros();
    w.bits(u64::from(n), 3);
    w.bits(u64::from(v - (1 << n)), n);
}

/// A simple prefix code with one symbol (zero bits per symbol).
fn one_symbol(w: &mut BitWriter, symbol: u64, symbol_bits: u32) {
    w.bits(1, 2); // HSKIP = 1: simple code
    w.bits(0, 2); // NSYM - 1
    w.bits(symbol, symbol_bits);
}

/// A first meta-block that asks for the most table memory the format allows: 256 block types of each
/// kind, 256 literal trees, 256 insert-and-copy trees, 256 distance trees. It then stops: the decoder
/// has allocated everything by the time it asks for more input (so the stream ends `corrupt`).
fn table_hog(window: impl Fn(&mut BitWriter), trees: u32) -> Vec<u8> {
    let mut w = BitWriter::new();
    window(&mut w);
    w.bits(0, 1); // ISLAST = 0: the full window is allocated
    w.bits(0, 2); // MNIBBLES = 4
    w.bits(0xffff, 16); // MLEN = 65536
    w.bits(0, 1); // ISUNCOMPRESSED = 0
    for _ in 0..3 {
        // NBLTYPESL, NBLTYPESI, NBLTYPESD, each with its two prefix codes and the first block count
        var_len(&mut w, trees);
        one_symbol(&mut w, 0, 9); // block type code (alphabet NBLTYPES + 2)
        one_symbol(&mut w, 0, 5); // block count code (alphabet 26)
        w.bits(0, 2); // first block count: symbol 0 + 2 extra bits
    }
    w.bits(0, 2); // NPOSTFIX
    w.bits(0, 4); // NDIRECT
    w.zero_bits(2 * u64::from(trees)); // context mode of every literal block type
    for _ in 0..2 {
        // NTREESL then NTREESD, each with a context map of one repeated tree index
        var_len(&mut w, trees);
        w.bits(0, 1); // RLEMAX = 0
        one_symbol(&mut w, 0, 8); // context map code (alphabet NTREES)
        w.bits(0, 1); // IMTF = 0
    }
    for symbol_bits in [8u32, 10, 6] {
        // literal (alphabet 256), insert-and-copy (704), distance (64) trees
        for _ in 0..trees {
            one_symbol(&mut w, 0, symbol_bits);
        }
    }
    w.finish()
}

fn window_header(bits: u32) -> impl Fn(&mut BitWriter) {
    move |w| match bits {
        24 => {
            w.bits(1, 1);
            w.bits(7, 3);
        }
        10 => {
            w.bits(1, 1);
            w.bits(0, 3);
            w.bits(2, 3);
        }
        _ => unreachable!(),
    }
}

#[test]
fn brotli_peak_heap() {
    // Covers: SG-R-MEM-01 SG-R-MEM-02 SG-R-CDC-07 SG-I-04 SG-I-08
    // Warm up so that one-time allocations of the runtime are not counted.
    let d24 = decoder(64 * MIB as u64, 24);
    let _ = decode(&d24, &brotli_stored(b"warm", 24).unwrap());

    // 1. A 4 GiB bomb with a 2^24 window against max_output 64 MiB: the window and the fixed tables.
    let bomb = brotli_zeros(4 << 30, 24).unwrap();
    let ((kind, total), peak) = peak_during(|| decode(&d24, &bomb));
    assert_eq!((kind, total), (Some(ErrorKind::OutputLimit), 64 * MIB as u64));
    println!(
        "bomb, window 2^24: peak {peak} bytes ({:.2} MiB)",
        peak as f64 / MIB as f64
    );
    assert!(peak < 16 * MIB + MIB, "bomb peak {peak}");
    assert!(peak > 15 * MIB, "the window is allocated: {peak}");

    // 2. The same bomb with window 2^10 and cap 10: tiny.
    let small = brotli_zeros(4 << 30, 10).unwrap();
    let d10 = decoder(64 * MIB as u64, 10);
    let ((kind, _), peak) = peak_during(|| decode(&d10, &small));
    assert_eq!(kind, Some(ErrorKind::OutputLimit));
    println!("bomb, window 2^10: peak {peak} bytes");
    assert!(peak < 400 * 1024, "small-window bomb peak {peak}");

    // 3. A stream asking for a window above the cap, or the large-window marker, allocates no window
    //    and no decoder state at all (SG-R-CDC-04: refused before the decoder exists).
    for (name, stream, cap) in [
        ("window 24 vs cap 16", bomb.clone(), 16u32),
        ("window 24 vs cap 23", bomb.clone(), 23),
        (
            "large-window marker",
            [brotli_large_window_prefix(), vec![0; 100]].concat(),
            24,
        ),
    ] {
        let d = decoder(64 * MIB as u64, cap);
        let ((kind, total), peak) = peak_during(|| decode(&d, &stream));
        assert_eq!((kind, total), (Some(ErrorKind::MemoryLimit), 0), "{name}");
        println!("{name}: peak {peak} bytes");
        // the 64 KiB read buffer of `decode` and the 4 KiB input buffer are all that is allocated
        assert!(peak < 80 * 1024, "{name}: refusal peak {peak}");
    }

    // 4. Hostile table sizes: 256 block types and 256 trees of each kind in the first meta-block.
    //    Window 2^24 and window 2^10 (cap equal to the window).
    for (name, bits) in [("table hog, window 2^24", 24u32), ("table hog, window 2^10", 10)] {
        let stream = table_hog(window_header(bits), 256);
        println!("{name}: {} byte stream", stream.len());
        let d = decoder(64 * MIB as u64, bits);
        let ((kind, total), peak) = peak_during(|| decode(&d, &stream));
        assert_eq!((kind, total), (Some(ErrorKind::Corrupt), 0), "{name}");
        println!("{name}: peak {peak} bytes ({:.2} MiB)", peak as f64 / MIB as f64);
        let window = if bits == 24 { 16 * MIB } else { 1024 };
        let tables = peak.saturating_sub(window);
        println!(
            "{name}: peak minus window = {tables} bytes ({:.2} MiB)",
            tables as f64 / MIB as f64
        );
        assert!(tables < 4 * MIB, "{name}: tables {tables}");
    }

    // 5. Nothing is retained: repeated decodes, including failed ones, return to the starting level.
    let before = CURRENT.load(Ordering::SeqCst);
    let hog = table_hog(window_header(24), 256);
    for _ in 0..20 {
        let _ = decode(&d24, &bomb);
        let _ = decode(&d24, &hog);
        let _ = decode(&decoder(1, 10), &bomb);
    }
    let held = CURRENT.load(Ordering::SeqCst).saturating_sub(before);
    assert!(held < 64 * 1024, "{held} bytes still held after 60 decodes");

    // 6. A reader closed early releases its decoder state.
    let before = CURRENT.load(Ordering::SeqCst);
    {
        let mut reader = d24.reader(&bomb[..], &["br"]).unwrap();
        let mut buf = [0u8; 100];
        assert!(reader.read(&mut buf).unwrap() > 0);
        assert!(CURRENT.load(Ordering::SeqCst) > before + 15 * MIB);
        reader.close();
        let held = CURRENT.load(Ordering::SeqCst).saturating_sub(before);
        assert!(held < 16 * 1024, "{held} bytes held after close");
    }

    // 7. A stream that fails (here: truncated after the window was allocated) releases its window at
    //    the failure, not only when the reader is closed.
    let before = CURRENT.load(Ordering::SeqCst);
    let cut = brotli_zeros(40 * MIB as u64, 24).unwrap();
    let mut reader = d24.reader(&cut[..cut.len() - 1], &["br"]).unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut peak_open = 0;
    let kind = loop {
        match reader.read(&mut buf) {
            Ok(0) => panic!("a truncated stream ended cleanly"),
            Ok(_) => peak_open = peak_open.max(CURRENT.load(Ordering::SeqCst).saturating_sub(before)),
            Err(e) => break Error::from_io(&e).unwrap().kind(),
        }
    };
    assert_eq!(kind, ErrorKind::Corrupt);
    assert!(peak_open > 15 * MIB, "the window was in use: {peak_open}");
    let held = CURRENT.load(Ordering::SeqCst).saturating_sub(before);
    assert!(
        held < 256 * 1024,
        "{held} bytes still held after the failure, reader not yet closed"
    );
    reader.close();
}
