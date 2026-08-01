// Command go-perf runs protocol microbenchmarks with the same JSON contract as
// the pinned official Rust oracle. It is invoked by compare-performance.sh.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
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
	record, err := benchmark(data, os.Args[3], iterations)
	if err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(record); err != nil {
		fatal(err)
	}
}

func benchmark(data []byte, operation string, iterations int) (benchRecord, error) {
	var (
		identity       xethash.Hash
		serializedSize int
		chunkCount     int
		schemeName     string
		decodeBody     []byte
		keepAlive      any
	)
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
		schemeName = scheme.String()
	}

	runtime.GC()
	start := time.Now()
	for range iterations {
		switch operation {
		case "chunk_hash":
			parts := chunker.Bytes(data)
			nodes := make([]xethash.Node, len(parts))
			for i, part := range parts {
				nodes[i] = xethash.Node{Hash: xethash.Chunk(part.Data), Size: uint64(len(part.Data))}
			}
			identity = xethash.File(nodes)
			chunkCount = len(parts)
		case "xorb_encode_none", "xorb_encode_lz4":
			scheme := xorb.None
			if operation == "xorb_encode_lz4" {
				scheme = xorb.LZ4
			}
			schemeName = scheme.String()
			object, err := encodeData(data, scheme)
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
