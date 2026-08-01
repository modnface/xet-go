// Command blake3-perf runs controlled keyed-BLAKE3 microbenchmarks used by
// the matching official Rust development oracle.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
	"lukechampine.com/blake3"
)

var dataKey = [32]byte{
	0x66, 0x97, 0xf5, 0x77, 0x5b, 0x95, 0x50, 0xde,
	0x31, 0x35, 0xcb, 0xac, 0xa5, 0x97, 0x18, 0x1c,
	0x9d, 0xe4, 0x21, 0x10, 0x9b, 0xeb, 0x2b, 0x58,
	0xb4, 0xd0, 0xb0, 0x4b, 0x93, 0xad, 0xf2, 0x29,
}

type record struct {
	SchemaVersion  int     `json:"schema_version"`
	Implementation string  `json:"implementation"`
	Scenario       string  `json:"scenario"`
	MessageSize    int     `json:"message_size"`
	Iterations     int     `json:"iterations_per_worker"`
	Workers        int     `json:"workers"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
	ElapsedNS      uint64  `json:"elapsed_ns"`
	BytesProcessed uint64  `json:"bytes_processed"`
	BytesPerSecond float64 `json:"bytes_per_second"`
	Digest         string  `json:"digest"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	Allocations    uint64  `json:"allocations"`
	GCCycles       uint32  `json:"gc_cycles"`
	GCPauseNS      uint64  `json:"gc_pause_ns"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, "usage: blake3-perf perf <scenario> <message-size> <iterations-per-worker> <workers>")
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "blake3-perf:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("invalid command line")

func run(args []string, stdout io.Writer) error {
	if len(args) != 5 || args[0] != "perf" {
		return errUsage
	}
	size, err := positiveInt(args[2], "message size")
	if err != nil {
		return err
	}
	iterations, err := positiveInt(args[3], "iterations")
	if err != nil {
		return err
	}
	workers, err := positiveInt(args[4], "workers")
	if err != nil {
		return err
	}
	result, err := benchmark(args[1], size, iterations, workers)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}

func positiveInt(value, name string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}

func benchmark(scenario string, size, iterations, workers int) (record, error) {
	data := deterministicData(size)
	if scenario != "caller_parallel" && scenario != "caller_parallel_segmented" && workers != 1 {
		return record{}, errors.New("workers must be 1 except for caller-parallel scenarios")
	}
	if !validScenario(scenario) {
		return record{}, fmt.Errorf("unknown scenario %q", scenario)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	var digest xethash.Hash
	switch scenario {
	case "one_shot":
		for range iterations {
			digest = xethash.Chunk(data)
		}
	case "stream_new":
		for range iterations {
			digest = streamHash(blake3.New(xethash.Size, dataKey[:]), data, false)
		}
	case "stream_reuse", "stream_segmented":
		hasher := blake3.New(xethash.Size, dataKey[:])
		segmented := scenario == "stream_segmented"
		for range iterations {
			digest = streamHash(hasher, data, segmented)
			hasher.Reset()
		}
	case "owned":
		for range iterations {
			owned := append([]byte(nil), data...)
			digest = xethash.Chunk(owned)
			runtime.KeepAlive(owned)
		}
	case "caller_parallel", "caller_parallel_segmented":
		digest = parallelHash(data, iterations, workers, scenario == "caller_parallel_segmented")
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(data)
	bytesProcessed := uint64(size) * uint64(iterations)
	if scenario == "caller_parallel" || scenario == "caller_parallel_segmented" {
		bytesProcessed *= uint64(workers)
	}
	return record{
		SchemaVersion: 1, Implementation: implementationName(scenario), Scenario: scenario,
		MessageSize: size, Iterations: iterations, Workers: workers, GOMAXPROCS: runtime.GOMAXPROCS(0),
		ElapsedNS: uint64(elapsed.Nanoseconds()), BytesProcessed: bytesProcessed,
		BytesPerSecond: float64(bytesProcessed) / elapsed.Seconds(), Digest: digest.String(),
		AllocatedBytes: after.TotalAlloc - before.TotalAlloc, Allocations: after.Mallocs - before.Mallocs,
		GCCycles: after.NumGC - before.NumGC, GCPauseNS: after.PauseTotalNs - before.PauseTotalNs,
	}, nil
}

func implementationName(scenario string) string {
	switch scenario {
	case "stream_new", "stream_reuse", "stream_segmented", "caller_parallel_segmented":
		return "go-lukechampine-blake3"
	default:
		return "go-xethash"
	}
}

func validScenario(scenario string) bool {
	switch scenario {
	case "one_shot", "stream_new", "stream_reuse", "stream_segmented", "owned",
		"caller_parallel", "caller_parallel_segmented":
		return true
	default:
		return false
	}
}

func deterministicData(size int) []byte {
	data := make([]byte, size)
	var state uint64 = 0x9e3779b97f4a7c15
	for i := range data {
		state ^= state << 7
		state ^= state >> 9
		state ^= state << 8
		data[i] = byte(state)
	}
	return data
}

func streamHash(hasher *blake3.Hasher, data []byte, segmented bool) xethash.Hash {
	if segmented {
		for len(data) > 0 {
			size := min(len(data), 1024)
			_, _ = hasher.Write(data[:size])
			data = data[size:]
		}
	} else {
		_, _ = hasher.Write(data)
	}
	var raw [xethash.Size]byte
	hasher.Sum(raw[:0])
	digest, err := xethash.FromBytes(raw[:])
	if err != nil {
		panic(err)
	}
	return digest
}

func parallelHash(data []byte, iterations, workers int, segmented bool) xethash.Hash {
	start := make(chan struct{})
	results := make([]xethash.Hash, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := range workers {
		go func() {
			defer wait.Done()
			hasher := blake3.New(xethash.Size, dataKey[:])
			<-start
			for range iterations {
				if segmented {
					results[worker] = streamHash(hasher, data, true)
					hasher.Reset()
				} else {
					results[worker] = xethash.Chunk(data)
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	return results[0]
}
