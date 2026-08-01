package main

import (
	"strings"
	"testing"
)

func TestSummarizeValidatesSemantics(t *testing.T) {
	goRecord := validRecord("go-xet")
	rustRecord := validRecord("rust-xet-core")
	result, err := summarize("xorb_encode_none", 100, 2, []benchRecord{goRecord}, []benchRecord{rustRecord})
	if err != nil {
		t.Fatal(err)
	}
	if result.GoRustRatio != 1 || result.Identity != goRecord.Identity || result.Chunks != 2 {
		t.Fatalf("summary differs: %+v", result)
	}
	rustRecord.Identity = "different"
	if _, err := summarize("xorb_encode_none", 100, 2, []benchRecord{goRecord}, []benchRecord{rustRecord}); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	rustRecord = validRecord("rust-xet-core")
	rustRecord.SerializedSize++
	if _, err := summarize("xorb_encode_none", 100, 2, []benchRecord{goRecord}, []benchRecord{rustRecord}); err == nil {
		t.Fatal("uncompressed serialized-size mismatch accepted")
	}
}

func TestStatisticsAndMarkdown(t *testing.T) {
	records := []benchRecord{validRecord("go-xet"), validRecord("go-xet"), validRecord("go-xet")}
	records[0].BytesPerSecond, records[0].ElapsedNS = 30, 10
	records[1].BytesPerSecond, records[1].ElapsedNS = 10, 30
	records[2].BytesPerSecond, records[2].ElapsedNS = 20, 20
	statistics := calculateStatistics("go-xet", records)
	if statistics.MedianBytesPerSecond != 20 || statistics.MinBytesPerSecond != 10 ||
		statistics.MaxBytesPerSecond != 30 || statistics.MedianElapsedNS != 20 {
		t.Fatalf("statistics differ: %+v", statistics)
	}
	markdown := string(renderMarkdown(report{
		Input:       inputInfo{Name: "fixture.bin", Size: 100, SHA256: "abc"},
		Environment: envInfo{GOOS: "test", GOARCH: "arch", LogicalCPU: 1, GoVersion: "go-test", RustToolchain: "rust-test", RustRevision: rustRevision},
		Iterations:  2, SampleCount: 3,
		Comparisons: []comparison{{Operation: "chunk_hash", Identity: "identity", Go: statistics, Rust: statistics, GoRustRatio: 1}},
	}))
	for _, expected := range []string{"fixture.bin", "chunk_hash", "1.000x", rustRevision} {
		if !strings.Contains(markdown, expected) {
			t.Errorf("Markdown lacks %q", expected)
		}
	}
}

func validRecord(implementation string) benchRecord {
	return benchRecord{
		SchemaVersion: 1, Implementation: implementation, Operation: "xorb_encode_none", Scheme: "none",
		InputSize: 100, Iterations: 2, ElapsedNS: 20, BytesPerSecond: 10, Identity: "same", SerializedSize: 108, Chunks: 2,
	}
}
