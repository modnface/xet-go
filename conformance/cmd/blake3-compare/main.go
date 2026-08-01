// Command blake3-compare runs interleaved matching Go/Rust keyed-BLAKE3
// microbenchmarks and rejects any semantic mismatch.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

type benchRecord struct {
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

type statistics struct {
	Implementation       string        `json:"implementation"`
	MedianBytesPerSecond float64       `json:"median_bytes_per_second"`
	MinBytesPerSecond    float64       `json:"min_bytes_per_second"`
	MaxBytesPerSecond    float64       `json:"max_bytes_per_second"`
	MADPercent           float64       `json:"median_absolute_deviation_percent"`
	MedianElapsedNS      uint64        `json:"median_elapsed_ns"`
	MedianAllocatedBytes uint64        `json:"median_allocated_bytes"`
	MedianAllocations    uint64        `json:"median_allocations"`
	Samples              []benchRecord `json:"samples"`
}

type report struct {
	SchemaVersion int        `json:"schema_version"`
	GeneratedAt   string     `json:"generated_at"`
	Scenario      string     `json:"scenario"`
	MessageSize   int        `json:"message_size"`
	Iterations    int        `json:"iterations_per_worker"`
	Workers       int        `json:"workers"`
	Samples       int        `json:"sample_count"`
	Digest        string     `json:"digest"`
	Go            statistics `json:"go"`
	Rust          statistics `json:"rust"`
	GoRustRatio   float64    `json:"go_to_rust_throughput_ratio"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "blake3-compare:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("blake3-compare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	goBinary := flags.String("go", "", "Go benchmark executable")
	rustBinary := flags.String("rust", "", "Rust benchmark executable")
	scenario := flags.String("scenario", "", "benchmark scenario")
	size := flags.Int("size", 0, "message size")
	iterations := flags.Int("iterations", 0, "iterations per worker")
	workers := flags.Int("workers", 1, "caller workers")
	sampleCount := flags.Int("samples", 7, "timed samples per implementation")
	jsonPath := flags.String("json", "", "optional report path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *goBinary == "" || *rustBinary == "" || *scenario == "" || *size < 1 || *iterations < 1 || *workers < 1 || *sampleCount < 1 {
		return errors.New("binaries, scenario, and positive size/iteration/worker/sample values are required")
	}
	result, err := compare(*goBinary, *rustBinary, *scenario, *size, *iterations, *workers, *sampleCount)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *jsonPath != "" {
		if err := os.WriteFile(*jsonPath, data, 0o644); err != nil {
			return err
		}
	}
	_, err = stdout.Write(data)
	return err
}

func compare(goBinary, rustBinary, scenario string, size, iterations, workers, sampleCount int) (report, error) {
	if _, err := invoke(goBinary, scenario, size, iterations, workers); err != nil {
		return report{}, fmt.Errorf("Go warmup: %w", err)
	}
	if _, err := invoke(rustBinary, scenario, size, iterations, workers); err != nil {
		return report{}, fmt.Errorf("Rust warmup: %w", err)
	}
	goRecords := make([]benchRecord, 0, sampleCount)
	rustRecords := make([]benchRecord, 0, sampleCount)
	for sampleIndex := range sampleCount {
		order := []struct {
			binary string
			target *[]benchRecord
		}{{goBinary, &goRecords}, {rustBinary, &rustRecords}}
		if sampleIndex%2 != 0 {
			slices.Reverse(order)
		}
		for _, item := range order {
			record, err := invoke(item.binary, scenario, size, iterations, workers)
			if err != nil {
				return report{}, err
			}
			*item.target = append(*item.target, record)
		}
	}
	return summarize(scenario, size, iterations, workers, goRecords, rustRecords)
}

func invoke(binary, scenario string, size, iterations, workers int) (benchRecord, error) {
	command := exec.Command(binary, "perf", scenario, strconv.Itoa(size), strconv.Itoa(iterations), strconv.Itoa(workers))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return benchRecord{}, fmt.Errorf("%s: %w: %s", binary, err, strings.TrimSpace(stderr.String()))
	}
	var record benchRecord
	if err := json.Unmarshal(output, &record); err != nil {
		return benchRecord{}, fmt.Errorf("decode %s: %w: %s", binary, err, output)
	}
	if record.SchemaVersion != 1 || record.ElapsedNS == 0 || record.BytesPerSecond <= 0 || math.IsNaN(record.BytesPerSecond) {
		return benchRecord{}, fmt.Errorf("invalid record from %s: %+v", binary, record)
	}
	return record, nil
}

func summarize(scenario string, size, iterations, workers int, goRecords, rustRecords []benchRecord) (report, error) {
	if len(goRecords) == 0 || len(goRecords) != len(rustRecords) {
		return report{}, errors.New("unbalanced benchmark records")
	}
	wantBytes := uint64(size) * uint64(iterations)
	if strings.HasPrefix(scenario, "caller_parallel") {
		wantBytes *= uint64(workers)
	}
	wantDigest := goRecords[0].Digest
	for _, records := range [][]benchRecord{goRecords, rustRecords} {
		for _, record := range records {
			if record.Scenario != scenario || record.MessageSize != size || record.Iterations != iterations ||
				record.Workers != workers || record.BytesProcessed != wantBytes || record.Digest != wantDigest {
				return report{}, fmt.Errorf("benchmark semantics differ: %+v", record)
			}
		}
	}
	if goRecords[0].Implementation != "go-lukechampine-blake3" || rustRecords[0].Implementation != "rust-blake3-1.8.3" {
		return report{}, errors.New("unexpected benchmark implementations")
	}
	goStats := calculateStatistics(goRecords)
	rustStats := calculateStatistics(rustRecords)
	return report{
		SchemaVersion: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Scenario: scenario,
		MessageSize: size, Iterations: iterations, Workers: workers, Samples: len(goRecords), Digest: wantDigest,
		Go: goStats, Rust: rustStats, GoRustRatio: goStats.MedianBytesPerSecond / rustStats.MedianBytesPerSecond,
	}, nil
}

func calculateStatistics(records []benchRecord) statistics {
	throughput := make([]float64, len(records))
	elapsed := make([]uint64, len(records))
	allocated := make([]uint64, len(records))
	allocations := make([]uint64, len(records))
	for i, record := range records {
		throughput[i] = record.BytesPerSecond
		elapsed[i] = record.ElapsedNS
		allocated[i] = record.AllocatedBytes
		allocations[i] = record.Allocations
	}
	slices.Sort(throughput)
	slices.Sort(elapsed)
	slices.Sort(allocated)
	slices.Sort(allocations)
	median := medianFloat(throughput)
	deviations := make([]float64, len(throughput))
	for i, value := range throughput {
		deviations[i] = math.Abs(value - median)
	}
	slices.Sort(deviations)
	return statistics{
		Implementation:       records[0].Implementation,
		MedianBytesPerSecond: median, MinBytesPerSecond: throughput[0], MaxBytesPerSecond: throughput[len(throughput)-1],
		MADPercent: medianFloat(deviations) / median * 100, MedianElapsedNS: medianUint64(elapsed),
		MedianAllocatedBytes: medianUint64(allocated), MedianAllocations: medianUint64(allocations), Samples: records,
	}
}

func medianFloat(values []float64) float64 {
	middle := len(values) / 2
	if len(values)%2 != 0 {
		return values[middle]
	}
	return (values[middle-1] + values[middle]) / 2
}

func medianUint64(values []uint64) uint64 {
	middle := len(values) / 2
	if len(values)%2 != 0 {
		return values[middle]
	}
	return values[middle-1]/2 + values[middle]/2 + (values[middle-1]%2+values[middle]%2)/2
}
