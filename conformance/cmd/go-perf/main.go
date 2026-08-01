// Command go-perf runs protocol microbenchmarks with the same JSON contract as
// the pinned official Rust oracle. It is invoked by compare-performance.sh.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
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
	AllocatedBytes uint64  `json:"allocated_bytes"`
	Allocations    uint64  `json:"allocations"`
	GCCycles       uint32  `json:"gc_cycles"`
	GCPauseNS      uint64  `json:"gc_pause_ns"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, "usage: go-perf perf <file> <operation> <iterations>")
		os.Exit(2)
	} else if err != nil {
		fatal(err)
	}
}

var errUsage = errors.New("invalid command line")

func run(args []string, stdout io.Writer) error {
	if len(args) != 4 || args[0] != "perf" {
		return errUsage
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	iterations, err := strconv.Atoi(args[3])
	if err != nil || iterations < 1 {
		return errors.New("iterations must be positive")
	}
	stopCPUProfile, err := startCPUProfile(os.Getenv("XET_PERF_CPU_PROFILE"))
	if err != nil {
		return err
	}
	stopTrace, err := startTrace(os.Getenv("XET_PERF_TRACE"))
	if err != nil {
		stopCPUProfile()
		return err
	}
	blockPath := os.Getenv("XET_PERF_BLOCK_PROFILE")
	if blockPath != "" {
		runtime.SetBlockProfileRate(1)
		defer runtime.SetBlockProfileRate(0)
	}
	mutexPath := os.Getenv("XET_PERF_MUTEX_PROFILE")
	if mutexPath != "" {
		runtime.SetMutexProfileFraction(1)
		defer runtime.SetMutexProfileFraction(0)
	}
	record, err := benchmark(data, args[2], iterations)
	stopTrace()
	stopCPUProfile()
	if err != nil {
		return err
	}
	if err := writeProfile(os.Getenv("XET_PERF_ALLOCS_PROFILE"), "allocs"); err != nil {
		return err
	}
	if err := writeProfile(os.Getenv("XET_PERF_HEAP_PROFILE"), "heap"); err != nil {
		return err
	}
	if err := writeProfile(blockPath, "block"); err != nil {
		return err
	}
	if err := writeProfile(mutexPath, "mutex"); err != nil {
		return err
	}
	if err := writeProfile(os.Getenv("XET_PERF_GOROUTINE_PROFILE"), "goroutine"); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(record)
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

func startTrace(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create execution trace: %w", err)
	}
	if err := trace.Start(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("start execution trace: %w", err)
	}
	return func() {
		trace.Stop()
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
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
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
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(keepAlive)
	return benchRecord{
		SchemaVersion: 1, Implementation: "go-xet", Operation: operation, Scheme: schemeName,
		InputSize: len(data), Iterations: iterations, ElapsedNS: uint64(elapsed.Nanoseconds()),
		BytesPerSecond: float64(len(data)*iterations) / elapsed.Seconds(), Identity: identity.String(),
		SerializedSize: serializedSize, Chunks: chunkCount,
		AllocatedBytes: after.TotalAlloc - before.TotalAlloc, Allocations: after.Mallocs - before.Mallocs,
		GCCycles: after.NumGC - before.NumGC, GCPauseNS: after.PauseTotalNs - before.PauseTotalNs,
		GOMAXPROCS: runtime.GOMAXPROCS(0),
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
