package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if implementation := os.Getenv("BLAKE3_COMPARE_HELPER"); implementation != "" {
		os.Exit(runHelper(implementation))
	}
	os.Exit(m.Run())
}

func runHelper(implementation string) int {
	if implementation == "fail" {
		fmt.Fprintln(os.Stderr, "intentional helper failure")
		return 1
	}
	if implementation == "invalid-json" {
		fmt.Println("not JSON")
		return 0
	}
	if implementation == "invalid-record" {
		fmt.Println(`{"schema_version":1}`)
		return 0
	}
	if len(os.Args) != 6 || os.Args[1] != "perf" {
		return 2
	}
	size, _ := strconv.Atoi(os.Args[3])
	iterations, _ := strconv.Atoi(os.Args[4])
	workers, _ := strconv.Atoi(os.Args[5])
	processed := uint64(size * iterations)
	if strings.HasPrefix(os.Args[2], "caller_parallel") {
		processed *= uint64(workers)
	}
	name := "rust-blake3-1.8.3"
	if implementation == "go" {
		name = expectedGoImplementation(os.Args[2])
	}
	_ = json.NewEncoder(os.Stdout).Encode(benchRecord{
		SchemaVersion: 1, Implementation: name, Scenario: os.Args[2], MessageSize: size,
		Iterations: iterations, Workers: workers, ElapsedNS: 100, BytesProcessed: processed,
		BytesPerSecond: 1000, Digest: "digest", AllocatedBytes: 100, Allocations: 2,
	})
	return 0
}

func helperExecutable(t *testing.T, implementation string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("helper wrapper uses a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), implementation+"-helper")
	script := fmt.Sprintf("#!/bin/sh\nBLAKE3_COMPARE_HELPER=%s exec %s \"$@\"\n",
		implementation, strconv.Quote(os.Args[0]))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunAndCompare(t *testing.T) {
	goHelper := helperExecutable(t, "go")
	rustHelper := helperExecutable(t, "rust")
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	args := []string{
		"-go", goHelper, "-rust", rustHelper, "-scenario", "one_shot", "-size", "64",
		"-iterations", "10", "-workers", "1", "-samples", "2", "-json", jsonPath,
	}
	var stdout bytes.Buffer
	if err := run(args, &stdout); err != nil {
		t.Fatal(err)
	}
	var got report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Samples != 2 || got.GoRustRatio != 1 || got.Digest != "digest" || got.Go.Implementation != "go-xethash" {
		t.Fatalf("unexpected report: %+v", got)
	}
	written, err := os.ReadFile(jsonPath)
	if err != nil || !bytes.Equal(written, stdout.Bytes()) {
		t.Fatalf("JSON report differs: err=%v", err)
	}

	parallel, err := compare(goHelper, rustHelper, "caller_parallel", 64, 10, 2, 2)
	if err != nil || parallel.Samples != 2 {
		t.Fatalf("parallel compare = %+v, %v", parallel, err)
	}
}

func TestRunErrors(t *testing.T) {
	goHelper := helperExecutable(t, "go")
	rustHelper := helperExecutable(t, "rust")
	for _, args := range [][]string{
		nil,
		{"-unknown"},
		{"-go", goHelper, "-rust", rustHelper, "-scenario", "one_shot", "-size", "64"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid arguments accepted: %q", args)
		}
	}
	valid := []string{
		"-go", goHelper, "-rust", rustHelper, "-scenario", "one_shot", "-size", "64",
		"-iterations", "1", "-samples", "1",
	}
	if err := run(append(append([]string{}, valid...), "-json", t.TempDir()), &bytes.Buffer{}); err == nil {
		t.Fatal("directory JSON path succeeded")
	}
	if err := run(valid, errorWriter{}); err == nil {
		t.Fatal("failing stdout writer succeeded")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestInvokeErrors(t *testing.T) {
	for _, implementation := range []string{"fail", "invalid-json", "invalid-record"} {
		if _, err := invoke(helperExecutable(t, implementation), "one_shot", 64, 1, 1); err == nil {
			t.Fatalf("%s helper succeeded", implementation)
		}
	}
	if _, err := compare(helperExecutable(t, "fail"), helperExecutable(t, "rust"), "one_shot", 64, 1, 1, 1); err == nil {
		t.Fatal("Go warmup failure succeeded")
	}
	if _, err := compare(helperExecutable(t, "go"), helperExecutable(t, "fail"), "one_shot", 64, 1, 1, 1); err == nil {
		t.Fatal("Rust warmup failure succeeded")
	}
}

func validRecords(scenario string) (benchRecord, benchRecord) {
	goRecord := benchRecord{
		SchemaVersion: 1, Implementation: expectedGoImplementation(scenario), Scenario: scenario,
		MessageSize: 64, Iterations: 10, Workers: 1, ElapsedNS: 100, BytesProcessed: 640,
		BytesPerSecond: 6400, Digest: "digest", AllocatedBytes: 1000, Allocations: 10,
	}
	rustRecord := goRecord
	rustRecord.Implementation = "rust-blake3-1.8.3"
	rustRecord.BytesPerSecond = 12800
	return goRecord, rustRecord
}

func TestSummarize(t *testing.T) {
	goRecord, rustRecord := validRecords("one_shot")
	report, err := summarize("one_shot", 64, 10, 1, []benchRecord{goRecord}, []benchRecord{rustRecord})
	if err != nil {
		t.Fatal(err)
	}
	if report.GoRustRatio != 0.5 || report.Digest != "digest" || report.Go.MedianAllocatedBytes != 1000 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestSummarizeRejectsInvalidRecords(t *testing.T) {
	goRecord, rustRecord := validRecords("one_shot")
	for name, records := range map[string]struct {
		goRecords   []benchRecord
		rustRecords []benchRecord
	}{
		"empty":      {nil, nil},
		"unbalanced": {[]benchRecord{goRecord}, nil},
		"semantics":  {[]benchRecord{goRecord}, []benchRecord{func() benchRecord { value := rustRecord; value.Digest = "other"; return value }()}},
		"go impl":    {[]benchRecord{func() benchRecord { value := goRecord; value.Implementation = "other"; return value }()}, []benchRecord{rustRecord}},
		"rust impl":  {[]benchRecord{goRecord}, []benchRecord{func() benchRecord { value := rustRecord; value.Implementation = "other"; return value }()}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := summarize("one_shot", 64, 10, 1, records.goRecords, records.rustRecords); err == nil {
				t.Fatal("invalid records succeeded")
			}
		})
	}
}

func TestStatisticsAndMedians(t *testing.T) {
	records := []benchRecord{
		{Implementation: "go", BytesPerSecond: 80, ElapsedNS: 30, AllocatedBytes: 300, Allocations: 3},
		{Implementation: "go", BytesPerSecond: 100, ElapsedNS: 20, AllocatedBytes: 100, Allocations: 1},
		{Implementation: "go", BytesPerSecond: 120, ElapsedNS: 10, AllocatedBytes: 200, Allocations: 2},
	}
	stats := calculateStatistics(records)
	if stats.MedianBytesPerSecond != 100 || stats.MADPercent != 20 || stats.MedianElapsedNS != 20 ||
		stats.MedianAllocatedBytes != 200 || stats.MedianAllocations != 2 {
		t.Fatalf("unexpected statistics: %+v", stats)
	}
	if medianFloat([]float64{2, 4}) != 3 || medianUint64([]uint64{1, 2}) != 1 {
		t.Fatal("even median calculation differs")
	}
	if expectedGoImplementation("stream_reuse") != "go-unified-blake3-fork" {
		t.Fatal("streaming implementation label differs")
	}
}
