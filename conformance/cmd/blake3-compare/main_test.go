package main

import "testing"

func TestSummarize(t *testing.T) {
	goRecord := benchRecord{
		SchemaVersion: 1, Implementation: "go-lukechampine-blake3", Scenario: "one_shot",
		MessageSize: 64, Iterations: 10, Workers: 1, ElapsedNS: 100, BytesProcessed: 640,
		BytesPerSecond: 6400, Digest: "digest", AllocatedBytes: 1000, Allocations: 10,
	}
	rustRecord := goRecord
	rustRecord.Implementation = "rust-blake3-1.8.3"
	rustRecord.BytesPerSecond = 12800
	report, err := summarize("one_shot", 64, 10, 1, []benchRecord{goRecord}, []benchRecord{rustRecord})
	if err != nil {
		t.Fatal(err)
	}
	if report.GoRustRatio != 0.5 || report.Digest != "digest" || report.Go.MedianAllocatedBytes != 1000 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestSummarizeRejectsMismatch(t *testing.T) {
	goRecord := benchRecord{
		Implementation: "go-lukechampine-blake3", Scenario: "caller_parallel", MessageSize: 64,
		Iterations: 10, Workers: 2, BytesProcessed: 1280, Digest: "go",
	}
	rustRecord := goRecord
	rustRecord.Implementation = "rust-blake3-1.8.3"
	rustRecord.Digest = "rust"
	if _, err := summarize("caller_parallel", 64, 10, 2, []benchRecord{goRecord}, []benchRecord{rustRecord}); err == nil {
		t.Fatal("digest mismatch succeeded")
	}
}

func TestStatistics(t *testing.T) {
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
}
