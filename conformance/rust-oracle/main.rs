//! Development-only differential oracle built inside the pinned official
//! huggingface/xet-core workspace. This is never linked into the Go module.

use std::env;
use std::fs;
use std::io::Cursor;
use std::mem::size_of;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};
use xet_core_structures::merklehash::{DataHash, file_hash, xorb_hash};
use xet_core_structures::metadata_shard::chunk_verification::range_hash_from_chunks;
use xet_core_structures::metadata_shard::file_structs::{
    FileDataSequenceEntry, FileDataSequenceHeader, FileMetadataExt, FileVerificationEntry, MDBFileInfo,
};
use xet_core_structures::metadata_shard::shard_in_memory::MDBInMemoryShard;
use xet_core_structures::metadata_shard::streaming_shard::MDBMinimalShard;
use xet_core_structures::metadata_shard::xorb_structs::{MDBXorbInfo, XorbChunkSequenceEntry, XorbChunkSequenceHeader};
use xet_core_structures::metadata_shard::{MDBShardFileHeader, MDBShardInfo};
use xet_core_structures::xorb_object::{CompressionScheme, deserialize_chunks, serialize_chunk};
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
        eprintln!("usage: xet-go-rust-oracle <corpus|bench|encode-xorb|decode-xorb|encode-shard|decode-shard> <file> [argument]");
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
        "encode-xorb" => {
            let scheme: CompressionScheme = args.get(3).map(String::as_str).unwrap_or("auto").parse().unwrap();
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
        "decode-xorb" => {
            let (decoded, boundaries) = deserialize_chunks(&mut std::io::Cursor::new(&data)).unwrap();
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
            let nodes: Vec<_> = chunks.iter().map(|c| (c.hash, c.data.len() as u64)).collect();
            let xorb_hash_value = xorb_hash(&nodes);
            let file_hash_value = file_hash(&nodes);
            let mut serialized_xorb = Vec::new();
            let mut xorb_chunks = Vec::new();
            let mut raw_offset = 0u32;
            for chunk in &chunks {
                serialize_chunk(&chunk.data, &mut serialized_xorb, CompressionScheme::None).unwrap();
                xorb_chunks.push(XorbChunkSequenceEntry::new(
                    chunk.hash,
                    chunk.data.len() as u32,
                    raw_offset,
                ));
                raw_offset += chunk.data.len() as u32;
            }
            let mut xorb_header = XorbChunkSequenceHeader::new(xorb_hash_value, chunks.len(), data.len() as u32);
            xorb_header.num_bytes_on_disk = serialized_xorb.len() as u32;
            let xorb_info = MDBXorbInfo {
                metadata: xorb_header,
                chunks: xorb_chunks,
            };
            let segment = FileDataSequenceEntry::new(xorb_hash_value, data.len() as u32, 0u32, chunks.len() as u32);
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
