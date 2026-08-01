// Command go-perf runs protocol microbenchmarks with the same JSON contract as
// the pinned official Rust oracle. It is invoked by compare-performance.sh.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

type benchRecord struct {
	SchemaVersion  int     `json:"schema_version"`
	Implementation string  `json:"implementation"`
	Operation      string  `json:"operation"`
	Scheme         string  `json:"scheme,omitempty"`
	InputSize      int     `json:"input_size"`
	Iterations     int     `json:"iterations"`
	ElapsedNS      uint64  `json:"elapsed_ns"`
	BytesPerSecond float64 `json:"bytes_per_second"`
	Identity       string  `json:"identity"`
	SerializedSize int     `json:"serialized_size"`
	Chunks         int     `json:"chunks"`
}

func main() {
	if len(os.Args) != 5 || os.Args[1] != "perf" {
		fmt.Fprintln(os.Stderr, "usage: go-perf perf <file> <operation> <iterations>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatal(err)
	}
	iterations, err := strconv.Atoi(os.Args[4])
	if err != nil || iterations < 1 {
		fatal(errors.New("iterations must be positive"))
	}
	stopCPUProfile, err := startCPUProfile(os.Getenv("XET_PERF_CPU_PROFILE"))
	if err != nil {
		fatal(err)
	}
	record, err := benchmark(data, os.Args[3], iterations)
	stopCPUProfile()
	if err != nil {
		fatal(err)
	}
	if err := writeProfile(os.Getenv("XET_PERF_ALLOCS_PROFILE"), "allocs"); err != nil {
		fatal(err)
	}
	if err := writeProfile(os.Getenv("XET_PERF_HEAP_PROFILE"), "heap"); err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(record); err != nil {
		fatal(err)
	}
}

func startCPUProfile(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("start CPU profile: %w", err)
	}
	return func() {
		pprof.StopCPUProfile()
		_ = file.Close()
	}, nil
}

func writeProfile(path, name string) error {
	if path == "" {
		return nil
	}
	profile := pprof.Lookup(name)
	if profile == nil {
		return fmt.Errorf("unknown runtime profile %q", name)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s profile: %w", name, err)
	}
	defer file.Close()
	if err := profile.WriteTo(file, 0); err != nil {
		return fmt.Errorf("write %s profile: %w", name, err)
	}
	return nil
}

func benchmark(data []byte, operation string, iterations int) (benchRecord, error) {
	var (
		identity       xethash.Hash
		serializedSize int
		chunkCount     int
		schemeName     string
		decodeBody     []byte
		keepAlive      any
		preparedParts  []chunker.Chunk
		preparedChunks [][]byte
		preparedNodes  []xethash.Node
	)
	switch operation {
	case "xorb_encode_none", "xorb_encode_chunks_none", "xorb_decode_none":
		schemeName = xorb.None.String()
	case "xorb_encode_lz4", "xorb_encode_chunks_lz4", "xorb_decode_lz4":
		schemeName = xorb.LZ4.String()
	}
	needsPreparedChunks := operation == "chunk_owned" || operation == "leaf_hash" || operation == "merkle_hash" ||
		operation == "xorb_encode_chunks_none" || operation == "xorb_encode_chunks_lz4"
	if needsPreparedChunks {
		preparedParts = chunker.Bytes(data)
		preparedChunks = make([][]byte, len(preparedParts))
		preparedNodes = make([]xethash.Node, len(preparedParts))
		for i, part := range preparedParts {
			preparedChunks[i] = part.Data
			preparedNodes[i] = xethash.Node{Hash: xethash.Chunk(part.Data), Size: uint64(len(part.Data))}
		}
		identity = xethash.File(preparedNodes)
		chunkCount = len(preparedParts)
	}
	if operation == "xorb_decode_none" || operation == "xorb_decode_lz4" {
		scheme := xorb.None
		if operation == "xorb_decode_lz4" {
			scheme = xorb.LZ4
		}
		object, err := encodeData(data, scheme)
		if err != nil {
			return benchRecord{}, err
		}
		decodeBody = object.Body
	}

	runtime.GC()
	start := time.Now()
	for range iterations {
		switch operation {
		case "chunk_owned":
			parts := chunker.Bytes(data)
			chunkCount = len(parts)
			keepAlive = parts
		case "leaf_hash":
			nodes := make([]xethash.Node, len(preparedParts))
			for i, part := range preparedParts {
				nodes[i] = xethash.Node{Hash: xethash.Chunk(part.Data), Size: uint64(len(part.Data))}
			}
			chunkCount = len(nodes)
			keepAlive = nodes
		case "merkle_hash":
			identity = xethash.File(preparedNodes)
			keepAlive = preparedNodes
		case "chunk_hash":
			parts := chunker.Bytes(data)
			nodes := make([]xethash.Node, len(parts))
			for i, part := range parts {
				nodes[i] = xethash.Node{Hash: xethash.Chunk(part.Data), Size: uint64(len(part.Data))}
			}
			identity = xethash.File(nodes)
			chunkCount = len(parts)
		case "xorb_encode_none", "xorb_encode_lz4", "xorb_encode_chunks_none", "xorb_encode_chunks_lz4":
			scheme := xorb.None
			if operation == "xorb_encode_lz4" || operation == "xorb_encode_chunks_lz4" {
				scheme = xorb.LZ4
			}
			var object *xorb.Object
			var err error
			if operation == "xorb_encode_chunks_none" || operation == "xorb_encode_chunks_lz4" {
				object, err = xorb.Encode(preparedChunks, scheme)
			} else {
				object, err = encodeData(data, scheme)
			}
			if err != nil {
				return benchRecord{}, err
			}
			identity = object.Hash
			serializedSize = len(object.Body)
			chunkCount = len(object.Chunks)
			keepAlive = object
		case "xorb_decode_none", "xorb_decode_lz4":
			object, err := xorb.Decode(decodeBody)
			if err != nil {
				return benchRecord{}, err
			}
			identity = object.Hash
			serializedSize = len(decodeBody)
			chunkCount = len(object.Chunks)
			keepAlive = object
		default:
			return benchRecord{}, fmt.Errorf("unknown benchmark operation %q", operation)
		}
	}
	elapsed := time.Since(start)
	runtime.KeepAlive(keepAlive)
	return benchRecord{
		SchemaVersion: 1, Implementation: "go-xet", Operation: operation, Scheme: schemeName,
		InputSize: len(data), Iterations: iterations, ElapsedNS: uint64(elapsed.Nanoseconds()),
		BytesPerSecond: float64(len(data)*iterations) / elapsed.Seconds(), Identity: identity.String(),
		SerializedSize: serializedSize, Chunks: chunkCount,
	}, nil
}

func encodeData(data []byte, scheme xorb.Scheme) (*xorb.Object, error) {
	parts := chunker.Bytes(data)
	chunks := make([][]byte, len(parts))
	for i := range parts {
		chunks[i] = parts[i].Data
	}
	return xorb.Encode(chunks, scheme)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "go-perf:", err)
	os.Exit(1)
}
