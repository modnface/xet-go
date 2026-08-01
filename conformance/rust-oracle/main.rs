//! Development-only differential oracle built inside the pinned official
//! huggingface/xet-core workspace. This is never linked into the Go module.

use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::fs;
use std::io::Cursor;
use std::mem::size_of;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};
use xet_core_structures::merklehash::{
    DataHash, MerkleHashSubtree, compute_data_hash, file_hash, xorb_hash,
};
use xet_core_structures::metadata_shard::chunk_verification::range_hash_from_chunks;
use xet_core_structures::metadata_shard::file_structs::{
    FileDataSequenceEntry, FileDataSequenceHeader, FileMetadataExt, FileVerificationEntry,
    MDBFileInfo,
};
use xet_core_structures::metadata_shard::shard_in_memory::MDBInMemoryShard;
use xet_core_structures::metadata_shard::streaming_shard::MDBMinimalShard;
use xet_core_structures::metadata_shard::xorb_structs::{
    MDBXorbInfo, XorbChunkSequenceEntry, XorbChunkSequenceHeader,
};
use xet_core_structures::metadata_shard::{MDBShardFileHeader, MDBShardInfo};
use xet_core_structures::xorb_object::{
    CompressionScheme, deserialize_chunks, serialize_chunk,
    xorb_format_test_utils::serialize_xorb_to_stream_reference,
};
use xet_data::deduplication::Chunker;

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
    schema_version: u32,
    implementation: &'static str,
    operation: String,
    scheme: Option<String>,
    input_size: usize,
    iterations: usize,
    elapsed_ns: u64,
    bytes_per_second: f64,
    identity: String,
    serialized_size: usize,
    chunks: usize,
    allocated_bytes: u64,
    allocations: u64,
    gc_cycles: u32,
    gc_pause_ns: u64,
    gomaxprocs: usize,
}

#[derive(Serialize)]
struct EncodedXorbRecord {
    body_hex: String,
    chunks: usize,
}

#[derive(Serialize)]
struct DecodedXorbRecord {
    data_hex: String,
    boundaries: Vec<u32>,
}

#[derive(Serialize)]
struct EncodedShardRecord {
    body_hex: String,
    full_body_hex: String,
    file_hash: String,
    xorb_hash: String,
}

#[derive(Serialize)]
struct DecodedShardRecord {
    files: usize,
    xorbs: usize,
    verification: bool,
}

#[derive(Serialize)]
struct SubtreeRecord {
    full: MerkleHashSubtree,
    left: MerkleHashSubtree,
    right: MerkleHashSubtree,
    merged: MerkleHashSubtree,
    final_hash: String,
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

fn encode_benchmark_xorb(data: &[u8], scheme: CompressionScheme) -> (Vec<u8>, DataHash, usize) {
    let chunks = Chunker::default().next_block(data, true);
    let nodes: Vec<_> = chunks
        .iter()
        .map(|chunk| (chunk.hash, chunk.data.len() as u64))
        .collect();
    let mut body = Vec::new();
    for chunk in &chunks {
        serialize_chunk(&chunk.data, &mut body, scheme).unwrap();
    }
    (body, xorb_hash(&nodes), chunks.len())
}

fn encode_benchmark_chunks(
    chunks: &[Vec<u8>],
    scheme: CompressionScheme,
) -> (Vec<u8>, DataHash, usize) {
    let nodes: Vec<_> = chunks
        .iter()
        .map(|chunk| (compute_data_hash(chunk), chunk.len() as u64))
        .collect();
    let mut body = Vec::new();
    for chunk in chunks {
        serialize_chunk(chunk, &mut body, scheme).unwrap();
    }
    (body, xorb_hash(&nodes), chunks.len())
}

fn chunk_owned(data: &[u8]) -> Vec<Vec<u8>> {
    let mut chunker = Chunker::default();
    let mut chunks = Vec::with_capacity(data.len() / (64 << 10) + 1);
    let mut position = 0;
    while position < data.len() {
        let relative_end = chunker
            .next_boundary(&data[position..])
            .unwrap_or(data.len() - position);
        let end = position + relative_end;
        chunks.push(data[position..end].to_vec());
        position = end;
    }
    chunks
}

fn hash_chunks(chunks: &[Vec<u8>]) -> Vec<(DataHash, u64)> {
    chunks
        .iter()
        .map(|chunk| (compute_data_hash(chunk), chunk.len() as u64))
        .collect()
}

fn decode_benchmark_xorb(body: &[u8]) -> (DataHash, usize) {
    let (decoded, boundaries) = deserialize_chunks(&mut Cursor::new(body)).unwrap();
    let nodes: Vec<_> = boundaries
        .windows(2)
        .map(|range| {
            let start = range[0] as usize;
            let end = range[1] as usize;
            (
                compute_data_hash(&decoded[start..end]),
                (end - start) as u64,
            )
        })
        .collect();
    (xorb_hash(&nodes), nodes.len())
}

fn benchmark(data: &[u8], operation: &str, iterations: usize) -> BenchRecord {
    assert!(iterations > 0);
    let mut identity = DataHash::default();
    let mut serialized_size = 0usize;
    let mut chunks = 0usize;
    let scheme_name = match operation {
        "xorb_encode_none" | "xorb_encode_chunks_none" | "xorb_decode_none" => {
            Some("none".to_string())
        }
        "xorb_encode_lz4" | "xorb_encode_chunks_lz4" | "xorb_decode_lz4" => Some("lz4".to_string()),
        _ => None,
    };

    let prepared_chunks = match operation {
        "chunk_owned"
        | "leaf_hash"
        | "merkle_hash"
        | "xorb_encode_chunks_none"
        | "xorb_encode_chunks_lz4" => Some(chunk_owned(data)),
        _ => None,
    };
    let prepared_nodes = prepared_chunks.as_ref().map(|chunks| hash_chunks(chunks));
    if let Some(nodes) = prepared_nodes.as_ref() {
        identity = file_hash(nodes);
        chunks = nodes.len();
    }

    let decode_body = match operation {
        "xorb_decode_none" => Some(encode_benchmark_xorb(data, CompressionScheme::None).0),
        "xorb_decode_lz4" => Some(encode_benchmark_xorb(data, CompressionScheme::LZ4).0),
        _ => None,
    };

    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    let start = Instant::now();
    for _ in 0..iterations {
        match operation {
            "chunk_owned" => {
                let result = chunk_owned(data);
                chunks = result.len();
                std::hint::black_box(result);
            }
            "leaf_hash" => {
                let result = hash_chunks(prepared_chunks.as_ref().unwrap());
                chunks = result.len();
                std::hint::black_box(result);
            }
            "merkle_hash" => {
                let nodes = prepared_nodes.as_ref().unwrap();
                identity = file_hash(nodes);
                chunks = nodes.len();
            }
            "chunk_hash" => {
                let result = Chunker::default().next_block(data, true);
                let nodes: Vec<_> = result
                    .iter()
                    .map(|chunk| (chunk.hash, chunk.data.len() as u64))
                    .collect();
                identity = file_hash(&nodes);
                chunks = result.len();
            }
            "xorb_encode_none" => {
                let result = encode_benchmark_xorb(data, CompressionScheme::None);
                serialized_size = result.0.len();
                identity = result.1;
                chunks = result.2;
                std::hint::black_box(result.0);
            }
            "xorb_encode_lz4" => {
                let result = encode_benchmark_xorb(data, CompressionScheme::LZ4);
                serialized_size = result.0.len();
                identity = result.1;
                chunks = result.2;
                std::hint::black_box(result.0);
            }
            "xorb_encode_chunks_none" | "xorb_encode_chunks_lz4" => {
                let scheme = if operation == "xorb_encode_chunks_none" {
                    CompressionScheme::None
                } else {
                    CompressionScheme::LZ4
                };
                let result = encode_benchmark_chunks(prepared_chunks.as_ref().unwrap(), scheme);
                serialized_size = result.0.len();
                identity = result.1;
                chunks = result.2;
                std::hint::black_box(result.0);
            }
            "xorb_decode_none" | "xorb_decode_lz4" => {
                let body = decode_body.as_ref().unwrap();
                let result = decode_benchmark_xorb(body);
                serialized_size = body.len();
                identity = result.0;
                chunks = result.1;
            }
            _ => panic!("unknown benchmark operation {operation:?}"),
        }
        std::hint::black_box(&identity);
    }
    let elapsed = start.elapsed();
    let allocated_bytes = ALLOCATED_BYTES.load(Ordering::Relaxed);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    BenchRecord {
        schema_version: 1,
        implementation: "rust-xet-core",
        operation: operation.to_string(),
        scheme: scheme_name,
        input_size: data.len(),
        iterations,
        elapsed_ns: elapsed.as_nanos().try_into().unwrap(),
        bytes_per_second: data.len() as f64 * iterations as f64 / elapsed.as_secs_f64(),
        identity: identity.to_string(),
        serialized_size,
        chunks,
        allocated_bytes,
        allocations,
        gc_cycles: 0,
        gc_pause_ns: 0,
        gomaxprocs: 1,
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: xet-go-rust-oracle <corpus|bench|perf|subtree|encode-xorb|encode-xorb-complete|decode-xorb|encode-shard|decode-shard> <file> [argument]"
        );
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
            println!(
                "{}",
                serde_json::to_string(&benchmark(&data, "chunk_hash", iterations)).unwrap()
            );
        }
        "perf" => {
            let operation = args.get(3).map(String::as_str).unwrap_or("chunk_hash");
            let iterations: usize = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1);
            println!(
                "{}",
                serde_json::to_string(&benchmark(&data, operation, iterations)).unwrap()
            );
        }
        "subtree" => {
            let chunks = Chunker::default().next_block(&data, true);
            let nodes: Vec<_> = chunks
                .iter()
                .map(|chunk| (chunk.hash, chunk.data.len() as u64))
                .collect();
            let split: usize = args
                .get(3)
                .and_then(|value| value.parse().ok())
                .unwrap_or(nodes.len() / 2);
            assert!(split <= nodes.len());
            let full = MerkleHashSubtree::from_chunks(true, &nodes, true);
            let left = MerkleHashSubtree::from_chunks(true, &nodes[..split], false);
            let right = MerkleHashSubtree::from_chunks(false, &nodes[split..], true);
            let merged = MerkleHashSubtree::merge(&[left.clone(), right.clone()]).unwrap();
            let final_hash = merged.final_hash().unwrap().to_string();
            println!(
                "{}",
                serde_json::to_string(&SubtreeRecord {
                    full,
                    left,
                    right,
                    merged,
                    final_hash,
                })
                .unwrap()
            );
        }
        "encode-xorb" => {
            let scheme: CompressionScheme = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("auto")
                .parse()
                .unwrap();
            let chunks = Chunker::default().next_block(&data, true);
            let mut body = Vec::new();
            for chunk in &chunks {
                serialize_chunk(&chunk.data, &mut body, scheme).unwrap();
            }
            println!(
                "{}",
                serde_json::to_string(&EncodedXorbRecord {
                    body_hex: raw_hex(&body),
                    chunks: chunks.len(),
                })
                .unwrap()
            );
        }
        "encode-xorb-complete" => {
            let scheme: CompressionScheme = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("none")
                .parse()
                .unwrap();
            let chunks = Chunker::default().next_block(&data, true);
            let nodes: Vec<_> = chunks
                .iter()
                .map(|chunk| (chunk.hash, chunk.data.len() as u64))
                .collect();
            let hash = xorb_hash(&nodes);
            let mut boundary = 0u32;
            let chunk_boundaries: Vec<_> = chunks
                .iter()
                .map(|chunk| {
                    boundary += chunk.data.len() as u32;
                    (chunk.hash, boundary)
                })
                .collect();
            let mut output = Cursor::new(Vec::new());
            serialize_xorb_to_stream_reference(
                &mut output,
                &hash,
                &data,
                &chunk_boundaries,
                scheme,
            )
            .unwrap();
            println!(
                "{}",
                serde_json::to_string(&EncodedXorbRecord {
                    body_hex: raw_hex(&output.into_inner()),
                    chunks: chunks.len(),
                })
                .unwrap()
            );
        }
        "decode-xorb" => {
            let (decoded, boundaries) =
                deserialize_chunks(&mut std::io::Cursor::new(&data)).unwrap();
            println!(
                "{}",
                serde_json::to_string(&DecodedXorbRecord {
                    data_hex: raw_hex(&decoded),
                    boundaries,
                })
                .unwrap()
            );
        }
        "encode-shard" => {
            let chunks = Chunker::default().next_block(&data, true);
            let nodes: Vec<_> = chunks
                .iter()
                .map(|c| (c.hash, c.data.len() as u64))
                .collect();
            let xorb_hash_value = xorb_hash(&nodes);
            let file_hash_value = file_hash(&nodes);
            let mut serialized_xorb = Vec::new();
            let mut xorb_chunks = Vec::new();
            let mut raw_offset = 0u32;
            for chunk in &chunks {
                serialize_chunk(&chunk.data, &mut serialized_xorb, CompressionScheme::None)
                    .unwrap();
                xorb_chunks.push(XorbChunkSequenceEntry::new(
                    chunk.hash,
                    chunk.data.len() as u32,
                    raw_offset,
                ));
                raw_offset += chunk.data.len() as u32;
            }
            let mut xorb_header =
                XorbChunkSequenceHeader::new(xorb_hash_value, chunks.len(), data.len() as u32);
            xorb_header.num_bytes_on_disk = serialized_xorb.len() as u32;
            let xorb_info = MDBXorbInfo {
                metadata: xorb_header,
                chunks: xorb_chunks,
            };
            let segment = FileDataSequenceEntry::new(
                xorb_hash_value,
                data.len() as u32,
                0u32,
                chunks.len() as u32,
            );
            let chunk_hashes: Vec<_> = chunks.iter().map(|c| c.hash).collect();
            let verification = FileVerificationEntry::new(range_hash_from_chunks(&chunk_hashes));
            let sha_raw: [u8; 32] = Sha256::digest(&data).into();
            let file_info = MDBFileInfo {
                metadata: FileDataSequenceHeader::new(file_hash_value, 1u32, true, true),
                segments: vec![segment],
                verification: vec![verification],
                metadata_ext: Some(FileMetadataExt::new(DataHash::from(sha_raw))),
            };
            let mut shard = MDBInMemoryShard::default();
            shard.add_xorb_block(Arc::new(xorb_info)).unwrap();
            shard.add_file_reconstruction_info(file_info).unwrap();
            let mut body = shard.to_bytes().unwrap();
            let full_body_hex = raw_hex(&body);
            let info = MDBShardInfo::load_from_reader(&mut Cursor::new(&body)).unwrap();
            body.truncate(info.metadata.file_lookup_offset as usize);
            let mut upload_header = info.header;
            upload_header.footer_size = 0;
            upload_header
                .serialize(&mut &mut body[..size_of::<MDBShardFileHeader>()])
                .unwrap();
            println!(
                "{}",
                serde_json::to_string(&EncodedShardRecord {
                    body_hex: raw_hex(&body),
                    full_body_hex,
                    file_hash: file_hash_value.to_string(),
                    xorb_hash: xorb_hash_value.to_string(),
                })
                .unwrap()
            );
        }
        "decode-shard" => {
            let shard = MDBMinimalShard::from_reader(&mut Cursor::new(&data), true, true).unwrap();
            println!(
                "{}",
                serde_json::to_string(&DecodedShardRecord {
                    files: shard.num_files(),
                    xorbs: shard.num_xorb(),
                    verification: shard.has_file_verification(),
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
