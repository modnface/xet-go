package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(input, bytes.Repeat([]byte("xet"), 10_000), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XET_PERF_CPU_PROFILE", "")
	t.Setenv("XET_PERF_ALLOCS_PROFILE", "")
	t.Setenv("XET_PERF_HEAP_PROFILE", "")
	t.Setenv("XET_PERF_TRACE", "")
	t.Setenv("XET_PERF_BLOCK_PROFILE", "")
	t.Setenv("XET_PERF_MUTEX_PROFILE", "")
	t.Setenv("XET_PERF_GOROUTINE_PROFILE", "")
	var stdout bytes.Buffer
	if err := run([]string{"perf", input, "chunk_hash", "1"}, &stdout); err != nil {
		t.Fatal(err)
	}
	var record benchRecord
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Operation != "chunk_hash" || record.InputSize != 30_000 || record.Identity == "" {
		t.Fatalf("unexpected record: %+v", record)
	}
	previousArgs := os.Args
	t.Cleanup(func() { os.Args = previousArgs })
	os.Args = []string{"go-perf", "perf", input, "chunk_hash", "1"}
	main()
}

func TestRunRejectsInvalidInputs(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(input, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "usage", args: nil},
		{name: "missing input", args: []string{"perf", input + ".missing", "chunk_hash", "1"}},
		{name: "invalid iterations", args: []string{"perf", input, "chunk_hash", "bad"}},
		{name: "nonpositive iterations", args: []string{"perf", input, "chunk_hash", "0"}},
		{name: "unknown operation", args: []string{"perf", input, "unknown", "1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := run(test.args, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	if err := run([]string{"perf", input, "chunk_hash", "1"}, errorWriter{}); err == nil {
		t.Fatal("output error was ignored")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, os.ErrInvalid }

func TestBenchmarkOperationsPreserveIdentity(t *testing.T) {
	data := bytes.Repeat([]byte("official-xet-performance-corpus"), 10_000)
	operations := []string{
		"chunk_owned", "leaf_hash", "merkle_hash", "chunk_hash",
		"xorb_encode_chunks_none", "xorb_encode_chunks_lz4",
		"xorb_encode_none", "xorb_encode_lz4", "xorb_decode_none", "xorb_decode_lz4",
	}
	records := make(map[string]benchRecord, len(operations))
	for _, operation := range operations {
		record, err := benchmark(data, operation, 1)
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		if record.SchemaVersion != 1 || record.InputSize != len(data) || record.Iterations != 1 ||
			record.Identity == "" || record.Chunks == 0 || record.BytesPerSecond <= 0 {
			t.Fatalf("%s returned invalid record: %+v", operation, record)
		}
		records[operation] = record
	}
	for _, operation := range []string{
		"xorb_encode_chunks_none", "xorb_encode_chunks_lz4", "xorb_encode_lz4", "xorb_decode_none", "xorb_decode_lz4",
	} {
		if records[operation].Identity != records["xorb_encode_none"].Identity {
			t.Errorf("%s identity = %s, xorb identity = %s", operation, records[operation].Identity, records["xorb_encode_none"].Identity)
		}
	}
	if records["chunk_hash"].AllocatedBytes == 0 || records["chunk_hash"].Allocations == 0 ||
		records["chunk_hash"].GOMAXPROCS < 1 {
		t.Fatalf("chunk_hash runtime metrics missing: %+v", records["chunk_hash"])
	}
}

func TestBenchmarkRejectsUnknownOperation(t *testing.T) {
	if _, err := benchmark([]byte("x"), "unknown", 1); err == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestOptionalProfiles(t *testing.T) {
	stop, err := startCPUProfile("")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := startCPUProfile(filepath.Join(t.TempDir(), "missing", "cpu.pprof")); err == nil {
		t.Fatal("CPU profile accepted a missing parent directory")
	}
	cpuPath := filepath.Join(t.TempDir(), "cpu.pprof")
	stop, err = startCPUProfile(cpuPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startCPUProfile(filepath.Join(t.TempDir(), "second.pprof")); err == nil {
		stop()
		t.Fatal("second concurrent CPU profile was accepted")
	}
	stop()
	if info, err := os.Stat(cpuPath); err != nil || info.Size() == 0 {
		t.Fatalf("CPU profile was not written: info=%v err=%v", info, err)
	}
	if err := writeProfile("", "allocs"); err != nil {
		t.Fatal(err)
	}
	if err := writeProfile(filepath.Join(t.TempDir(), "unknown.pprof"), "unknown"); err == nil {
		t.Fatal("unknown runtime profile accepted")
	}
	if err := writeProfile(filepath.Join(t.TempDir(), "missing", "heap.pprof"), "heap"); err == nil || !strings.Contains(err.Error(), "create heap profile") {
		t.Fatalf("profile accepted a missing parent directory: %v", err)
	}
	path := filepath.Join(t.TempDir(), "goroutine.pprof")
	if err := writeProfile(path, "goroutine"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		t.Fatalf("profile was not written: info=%v err=%v", info, err)
	}
}

func TestOptionalExecutionTrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.out")
	stop, err := startTrace(path)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Fatalf("execution trace was not written: info=%v err=%v", info, err)
	}
	if _, err := startTrace(filepath.Join(t.TempDir(), "missing", "trace.out")); err == nil {
		t.Fatal("execution trace accepted a missing parent directory")
	}
	first := filepath.Join(t.TempDir(), "first-trace.out")
	stop, err = startTrace(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startTrace(filepath.Join(t.TempDir(), "second-trace.out")); err == nil {
		stop()
		t.Fatal("second concurrent execution trace was accepted")
	}
	stop()
}

func TestRunWithOptionalProfiles(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(input, bytes.Repeat([]byte("profile"), 10_000), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	paths := map[string]string{
		"XET_PERF_CPU_PROFILE":       filepath.Join(dir, "cpu.pprof"),
		"XET_PERF_ALLOCS_PROFILE":    filepath.Join(dir, "allocs.pprof"),
		"XET_PERF_HEAP_PROFILE":      filepath.Join(dir, "heap.pprof"),
		"XET_PERF_TRACE":             filepath.Join(dir, "trace.out"),
		"XET_PERF_BLOCK_PROFILE":     filepath.Join(dir, "block.pprof"),
		"XET_PERF_MUTEX_PROFILE":     filepath.Join(dir, "mutex.pprof"),
		"XET_PERF_GOROUTINE_PROFILE": filepath.Join(dir, "goroutine.pprof"),
	}
	for name, path := range paths {
		t.Setenv(name, path)
	}
	if err := run([]string{"perf", input, "chunk_hash", "1"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for name, path := range paths {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Errorf("%s output missing: info=%v err=%v", name, info, err)
		}
	}
}

func TestRunProfileErrors(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(input, bytes.Repeat([]byte("error-profile"), 100), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, variable := range []string{"XET_PERF_CPU_PROFILE", "XET_PERF_TRACE", "XET_PERF_ALLOCS_PROFILE"} {
		t.Run(variable, func(t *testing.T) {
			for _, name := range []string{
				"XET_PERF_CPU_PROFILE", "XET_PERF_ALLOCS_PROFILE", "XET_PERF_HEAP_PROFILE", "XET_PERF_TRACE",
				"XET_PERF_BLOCK_PROFILE", "XET_PERF_MUTEX_PROFILE", "XET_PERF_GOROUTINE_PROFILE",
			} {
				t.Setenv(name, "")
			}
			t.Setenv(variable, filepath.Join(t.TempDir(), "missing", "profile"))
			if err := run([]string{"perf", input, "chunk_hash", "1"}, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid profile destination succeeded")
			}
		})
	}
}
