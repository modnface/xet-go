//! Development-only differential oracle built inside the pinned official
//! huggingface/xet-core workspace. This is never linked into the Go module.

use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

use serde::Serialize;
use xet_core_structures::merklehash::{file_hash, xorb_hash};
use xet_data::deduplication::Chunker;

#[derive(Serialize)]
struct ChunkRecord {
    end: usize,
    len: usize,
    hash: String,
    raw_hex: String,
}

#[derive(Serialize)]
struct CorpusRecord {
    size: usize,
    chunks: Vec<ChunkRecord>,
    xorb_hash: String,
    file_hash: String,
}

#[derive(Serialize)]
struct BenchRecord {
    size: usize,
    iterations: usize,
    elapsed_ns: u128,
    bytes_per_second: f64,
    file_hash: String,
}

fn raw_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn calculate(data: &[u8]) -> CorpusRecord {
    let chunks = Chunker::default().next_block(data, true);
    let nodes: Vec<_> = chunks
        .iter()
        .map(|chunk| (chunk.hash, chunk.data.len() as u64))
        .collect();
    let mut end = 0;
    let records = chunks
        .iter()
        .map(|chunk| {
            end += chunk.data.len();
            ChunkRecord {
                end,
                len: chunk.data.len(),
                hash: chunk.hash.to_string(),
                raw_hex: raw_hex(chunk.hash.as_bytes()),
            }
        })
        .collect();
    CorpusRecord {
        size: data.len(),
        chunks: records,
        xorb_hash: xorb_hash(&nodes).to_string(),
        file_hash: file_hash(&nodes).to_string(),
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: xet-go-rust-oracle <corpus|bench> <file> [iterations]");
        return ExitCode::from(2);
    }
    let data = match fs::read(&args[2]) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("read {}: {error}", args[2]);
            return ExitCode::FAILURE;
        }
    };
    match args[1].as_str() {
        "corpus" => println!("{}", serde_json::to_string(&calculate(&data)).unwrap()),
        "bench" => {
            let iterations: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(1);
            let start = Instant::now();
            let mut result = calculate(&data);
            for _ in 1..iterations {
                result = calculate(&data);
            }
            let elapsed = start.elapsed();
            println!(
                "{}",
                serde_json::to_string(&BenchRecord {
                    size: data.len(),
                    iterations,
                    elapsed_ns: elapsed.as_nanos(),
                    bytes_per_second: data.len() as f64 * iterations as f64 / elapsed.as_secs_f64(),
                    file_hash: result.file_hash,
                })
                .unwrap()
            );
        }
        command => {
            eprintln!("unknown command {command:?}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

