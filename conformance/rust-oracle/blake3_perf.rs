//! Matched keyed-BLAKE3 microbenchmark oracle built inside the pinned official
//! xet-core workspace. This is development tooling and is never linked into
//! the Go module.

use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use serde::Serialize;
use xet_core_structures::merklehash::DataHash;

const DATA_KEY: [u8; 32] = [
    0x66, 0x97, 0xf5, 0x77, 0x5b, 0x95, 0x50, 0xde, 0x31, 0x35, 0xcb, 0xac, 0xa5, 0x97, 0x18, 0x1c,
    0x9d, 0xe4, 0x21, 0x10, 0x9b, 0xeb, 0x2b, 0x58, 0xb4, 0xd0, 0xb0, 0x4b, 0x93, 0xad, 0xf2, 0x29,
];

struct CountingAllocator;

static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, old_layout, new_size) };
        if !new_pointer.is_null() {
            ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Serialize)]
struct Record {
    schema_version: u32,
    implementation: &'static str,
    scenario: String,
    message_size: usize,
    iterations_per_worker: usize,
    workers: usize,
    gomaxprocs: usize,
    elapsed_ns: u64,
    bytes_processed: u64,
    bytes_per_second: f64,
    digest: String,
    allocated_bytes: u64,
    allocations: u64,
    gc_cycles: u32,
    gc_pause_ns: u64,
}

fn deterministic_data(size: usize) -> Vec<u8> {
    let mut data = vec![0; size];
    let mut state = 0x9e3779b97f4a7c15u64;
    for byte in &mut data {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        *byte = state as u8;
    }
    data
}

fn stream_hash(hasher: &mut blake3::Hasher, data: &[u8], segmented: bool) -> [u8; 32] {
    if segmented {
        for segment in data.chunks(1024) {
            hasher.update(segment);
        }
    } else {
        hasher.update(data);
    }
    *hasher.finalize().as_bytes()
}

fn parallel_hash(data: &[u8], iterations: usize, workers: usize, segmented: bool) -> [u8; 32] {
    let barrier = Arc::new(Barrier::new(workers + 1));
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                let mut hasher = blake3::Hasher::new_keyed(&DATA_KEY);
                barrier.wait();
                let mut digest = [0; 32];
                for _ in 0..iterations {
                    if segmented {
                        digest = stream_hash(&mut hasher, data, true);
                        hasher.reset();
                    } else {
                        digest = *blake3::keyed_hash(&DATA_KEY, data).as_bytes();
                    }
                }
                digest
            }));
        }
        barrier.wait();
        let mut digest = [0; 32];
        for handle in handles {
            digest = handle.join().unwrap();
        }
        digest
    })
}

fn benchmark(
    scenario: &str,
    size: usize,
    iterations: usize,
    workers: usize,
) -> Result<Record, String> {
    if size == 0 || iterations == 0 || workers == 0 {
        return Err("size, iterations, and workers must be positive".to_string());
    }
    let parallel = matches!(scenario, "caller_parallel" | "caller_parallel_segmented");
    if !parallel && workers != 1 {
        return Err("workers must be 1 except for caller-parallel scenarios".to_string());
    }
    if !matches!(
        scenario,
        "one_shot"
            | "stream_new"
            | "stream_reuse"
            | "stream_segmented"
            | "owned"
            | "caller_parallel"
            | "caller_parallel_segmented"
    ) {
        return Err(format!("unknown scenario {scenario:?}"));
    }

    let data = deterministic_data(size);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    let start = Instant::now();
    let mut digest = [0; 32];
    match scenario {
        "one_shot" => {
            for _ in 0..iterations {
                digest = *blake3::keyed_hash(&DATA_KEY, &data).as_bytes();
            }
        }
        "stream_new" => {
            for _ in 0..iterations {
                digest = stream_hash(&mut blake3::Hasher::new_keyed(&DATA_KEY), &data, false);
            }
        }
        "stream_reuse" | "stream_segmented" => {
            let segmented = scenario == "stream_segmented";
            let mut hasher = blake3::Hasher::new_keyed(&DATA_KEY);
            for _ in 0..iterations {
                digest = stream_hash(&mut hasher, &data, segmented);
                hasher.reset();
            }
        }
        "owned" => {
            for _ in 0..iterations {
                let owned = data.clone();
                digest = *blake3::keyed_hash(&DATA_KEY, &owned).as_bytes();
                std::hint::black_box(owned);
            }
        }
        "caller_parallel" | "caller_parallel_segmented" => {
            digest = parallel_hash(
                &data,
                iterations,
                workers,
                scenario == "caller_parallel_segmented",
            );
        }
        _ => unreachable!(),
    }
    let elapsed = start.elapsed();
    let mut bytes_processed = size as u64 * iterations as u64;
    if parallel {
        bytes_processed *= workers as u64;
    }
    Ok(Record {
        schema_version: 1,
        implementation: "rust-blake3-1.8.3",
        scenario: scenario.to_string(),
        message_size: size,
        iterations_per_worker: iterations,
        workers,
        gomaxprocs: 0,
        elapsed_ns: elapsed.as_nanos().try_into().unwrap(),
        bytes_processed,
        bytes_per_second: bytes_processed as f64 / elapsed.as_secs_f64(),
        digest: DataHash::from(digest).to_string(),
        allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        gc_cycles: 0,
        gc_pause_ns: 0,
    })
}

fn positive(value: &str, name: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be positive"))?;
    if parsed == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(parsed)
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() != 6 || args[1] != "perf" {
        eprintln!(
            "usage: xet-go-rust-blake3-oracle perf <scenario> <message-size> <iterations-per-worker> <workers>"
        );
        return ExitCode::from(2);
    }
    let result = positive(&args[3], "message size")
        .and_then(|size| positive(&args[4], "iterations").map(|iterations| (size, iterations)))
        .and_then(|(size, iterations)| {
            positive(&args[5], "workers").map(|workers| (size, iterations, workers))
        })
        .and_then(|(size, iterations, workers)| benchmark(&args[2], size, iterations, workers));
    match result {
        Ok(record) => {
            println!("{}", serde_json::to_string(&record).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("xet-go-rust-blake3-oracle: {error}");
            ExitCode::FAILURE
        }
    }
}
