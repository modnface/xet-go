// Command perf-compare executes, validates, and summarizes matching Go and
// pinned xet-core benchmark records.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const rustRevision = "de71453d952bd8b806edaa997c72313051a49050"

var operations = []string{
	"chunk_owned",
	"leaf_hash",
	"merkle_hash",
	"chunk_hash",
	"xorb_encode_chunks_none",
	"xorb_encode_chunks_lz4",
	"xorb_encode_none",
	"xorb_encode_lz4",
	"xorb_decode_none",
	"xorb_decode_lz4",
}

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

type sample struct {
	ElapsedNS      uint64  `json:"elapsed_ns"`
	BytesPerSecond float64 `json:"bytes_per_second"`
	SerializedSize int     `json:"serialized_size"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	Allocations    uint64  `json:"allocations"`
	GCCycles       uint32  `json:"gc_cycles"`
	GCPauseNS      uint64  `json:"gc_pause_ns"`
}

type statistics struct {
	Implementation       string   `json:"implementation"`
	MedianBytesPerSecond float64  `json:"median_bytes_per_second"`
	MinBytesPerSecond    float64  `json:"min_bytes_per_second"`
	MaxBytesPerSecond    float64  `json:"max_bytes_per_second"`
	MedianElapsedNS      uint64   `json:"median_elapsed_ns"`
	Samples              []sample `json:"samples"`
}

type comparison struct {
	Operation   string     `json:"operation"`
	Scheme      string     `json:"scheme,omitempty"`
	Identity    string     `json:"identity"`
	Chunks      int        `json:"chunks"`
	Go          statistics `json:"go"`
	Rust        statistics `json:"rust"`
	GoRustRatio float64    `json:"go_to_rust_throughput_ratio"`
}

type report struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   string       `json:"generated_at"`
	Input         inputInfo    `json:"input"`
	Environment   envInfo      `json:"environment"`
	Iterations    int          `json:"iterations_per_sample"`
	SampleCount   int          `json:"sample_count"`
	Comparisons   []comparison `json:"comparisons"`
}

type inputInfo struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type envInfo struct {
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	LogicalCPU    int    `json:"logical_cpu_count"`
	GoVersion     string `json:"go_version"`
	RustToolchain string `json:"rust_toolchain"`
	RustRevision  string `json:"xet_core_revision"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fatal(err)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("perf-compare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	goBinary := flags.String("go", "", "Go benchmark executable")
	rustBinary := flags.String("rust", "", "Rust oracle executable")
	inputPath := flags.String("input", "", "benchmark input")
	iterations := flags.Int("iterations", 3, "iterations per timed sample")
	sampleCount := flags.Int("samples", 5, "timed samples per implementation and operation")
	jsonPath := flags.String("json", "", "JSON report path")
	markdownPath := flags.String("markdown", "", "Markdown report path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *goBinary == "" || *rustBinary == "" || *inputPath == "" || *jsonPath == "" || *markdownPath == "" ||
		*iterations < 1 || *sampleCount < 1 {
		return errors.New("all paths and positive iteration/sample counts are required")
	}
	result, err := compare(*goBinary, *rustBinary, *inputPath, *iterations, *sampleCount)
	if err != nil {
		return err
	}
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	jsonData = append(jsonData, '\n')
	if err := writeAtomic(*jsonPath, jsonData); err != nil {
		return err
	}
	if err := writeAtomic(*markdownPath, renderMarkdown(result)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%s\n%s\n", *jsonPath, *markdownPath); err != nil {
		return err
	}
	return nil
}

func compare(goBinary, rustBinary, inputPath string, iterations, sampleCount int) (report, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return report{}, err
	}
	digest := sha256.Sum256(data)
	result := report{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Input:         inputInfo{Name: filepath.Base(inputPath), Size: len(data), SHA256: hex.EncodeToString(digest[:])},
		Environment: envInfo{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, LogicalCPU: runtime.NumCPU(), GoVersion: runtime.Version(),
			RustToolchain: "1.95.0", RustRevision: rustRevision,
		},
		Iterations:  iterations,
		SampleCount: sampleCount,
	}
	for _, operation := range operations {
		if _, err := invoke(goBinary, inputPath, operation, 1); err != nil {
			return report{}, fmt.Errorf("go warmup %s: %w", operation, err)
		}
		if _, err := invoke(rustBinary, inputPath, operation, 1); err != nil {
			return report{}, fmt.Errorf("rust warmup %s: %w", operation, err)
		}
		goRecords := make([]benchRecord, 0, sampleCount)
		rustRecords := make([]benchRecord, 0, sampleCount)
		for i := range sampleCount {
			order := []struct {
				binary string
				output *[]benchRecord
			}{{goBinary, &goRecords}, {rustBinary, &rustRecords}}
			if i%2 != 0 {
				slices.Reverse(order)
			}
			for _, invocation := range order {
				record, err := invoke(invocation.binary, inputPath, operation, iterations)
				if err != nil {
					return report{}, err
				}
				*invocation.output = append(*invocation.output, record)
			}
		}
		comp, err := summarize(operation, len(data), iterations, goRecords, rustRecords)
		if err != nil {
			return report{}, err
		}
		result.Comparisons = append(result.Comparisons, comp)
	}
	return result, nil
}

func invoke(binary, input, operation string, iterations int) (benchRecord, error) {
	command := exec.Command(binary, "perf", input, operation, strconv.Itoa(iterations))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return benchRecord{}, fmt.Errorf("%s %s: %w: %s", filepath.Base(binary), operation, err, strings.TrimSpace(stderr.String()))
	}
	var record benchRecord
	if err := json.Unmarshal(output, &record); err != nil {
		return benchRecord{}, fmt.Errorf("decode %s output: %w: %s", filepath.Base(binary), err, output)
	}
	if record.SchemaVersion != 1 || record.Operation != operation || record.Iterations != iterations ||
		record.ElapsedNS == 0 || record.BytesPerSecond <= 0 || math.IsNaN(record.BytesPerSecond) {
		return benchRecord{}, fmt.Errorf("invalid %s benchmark record: %+v", filepath.Base(binary), record)
	}
	return record, nil
}

func summarize(operation string, inputSize, iterations int, goRecords, rustRecords []benchRecord) (comparison, error) {
	if len(goRecords) == 0 || len(goRecords) != len(rustRecords) {
		return comparison{}, errors.New("unbalanced performance samples")
	}
	firstGo, firstRust := goRecords[0], rustRecords[0]
	if firstGo.InputSize != inputSize || firstRust.InputSize != inputSize || firstGo.Iterations != iterations ||
		firstRust.Iterations != iterations || firstGo.Identity != firstRust.Identity || firstGo.Chunks != firstRust.Chunks ||
		firstGo.Scheme != firstRust.Scheme || firstGo.Implementation != "go-xet" || firstRust.Implementation != "rust-xet-core" {
		return comparison{}, fmt.Errorf("Go/Rust %s semantics differ: Go=%+v Rust=%+v", operation, firstGo, firstRust)
	}
	if (operation == "xorb_encode_none" || operation == "xorb_encode_chunks_none") && firstGo.SerializedSize != firstRust.SerializedSize {
		return comparison{}, fmt.Errorf("uncompressed xorb bytes differ in size: Go=%d Rust=%d", firstGo.SerializedSize, firstRust.SerializedSize)
	}
	for _, records := range [][]benchRecord{goRecords, rustRecords} {
		first := records[0]
		for _, record := range records {
			if record.InputSize != firstGo.InputSize || record.Iterations != iterations || record.Identity != firstGo.Identity ||
				record.Chunks != firstGo.Chunks || record.Operation != operation || record.Scheme != firstGo.Scheme ||
				record.SerializedSize != first.SerializedSize || record.Implementation != first.Implementation {
				return comparison{}, fmt.Errorf("unstable benchmark semantics for %s: %+v", operation, record)
			}
		}
	}
	goStats := calculateStatistics(firstGo.Implementation, goRecords)
	rustStats := calculateStatistics(firstRust.Implementation, rustRecords)
	return comparison{
		Operation: operation, Scheme: firstGo.Scheme, Identity: firstGo.Identity, Chunks: firstGo.Chunks,
		Go: goStats, Rust: rustStats, GoRustRatio: goStats.MedianBytesPerSecond / rustStats.MedianBytesPerSecond,
	}, nil
}

func calculateStatistics(implementation string, records []benchRecord) statistics {
	throughputs := make([]float64, len(records))
	elapsed := make([]uint64, len(records))
	samples := make([]sample, len(records))
	for i, record := range records {
		throughputs[i] = record.BytesPerSecond
		elapsed[i] = record.ElapsedNS
		samples[i] = sample{
			ElapsedNS: record.ElapsedNS, BytesPerSecond: record.BytesPerSecond, SerializedSize: record.SerializedSize,
			AllocatedBytes: record.AllocatedBytes, Allocations: record.Allocations,
			GCCycles: record.GCCycles, GCPauseNS: record.GCPauseNS,
		}
	}
	slices.Sort(throughputs)
	slices.Sort(elapsed)
	return statistics{
		Implementation:       implementation,
		MedianBytesPerSecond: medianFloat(throughputs), MinBytesPerSecond: throughputs[0], MaxBytesPerSecond: throughputs[len(throughputs)-1],
		MedianElapsedNS: medianUint64(elapsed), Samples: samples,
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

func renderMarkdown(value report) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "# Xet Go versus official Rust performance\n\n")
	fmt.Fprintf(&out, "Input: `%s` (%d bytes, SHA-256 `%s`)\n\n", value.Input.Name, value.Input.Size, value.Input.SHA256)
	fmt.Fprintf(&out, "Environment: `%s/%s`, %d logical CPUs, `%s`, Rust `%s`, xet-core `%s`. Each result is the median of %d samples with %d iterations per sample.\n\n",
		value.Environment.GOOS, value.Environment.GOARCH, value.Environment.LogicalCPU, value.Environment.GoVersion,
		value.Environment.RustToolchain, value.Environment.RustRevision, value.SampleCount, value.Iterations)
	out.WriteString("| Operation | Go MiB/s | Rust MiB/s | Go/Rust | Identity |\n")
	out.WriteString("|---|---:|---:|---:|---|\n")
	for _, comparison := range value.Comparisons {
		fmt.Fprintf(&out, "| `%s` | %.2f | %.2f | %.3fx | `%s` |\n", comparison.Operation,
			comparison.Go.MedianBytesPerSecond/(1<<20), comparison.Rust.MedianBytesPerSecond/(1<<20),
			comparison.GoRustRatio, comparison.Identity)
	}
	out.WriteString("\nRatios above 1.0 mean higher Go throughput. The harness rejects samples when Go and Rust identities or chunk counts differ; `xorb_encode_none` also requires the same serialized length. LZ4 sizes remain in the JSON report because the two conforming encoders may choose different compressed byte representations.\n")
	return []byte(out.String())
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".xet-perf-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}()
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "perf-compare:", err)
	os.Exit(1)
}
