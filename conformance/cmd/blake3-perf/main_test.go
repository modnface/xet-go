package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestScenariosMatch(t *testing.T) {
	for _, size := range []int{1, 64, 1024, 1025, 8192, 64 << 10, 1 << 20} {
		var want string
		for _, scenario := range []string{"one_shot", "stream_new", "stream_reuse", "stream_segmented", "owned"} {
			result, err := benchmark(scenario, size, 2, 1)
			if err != nil {
				t.Fatalf("size %d %s: %v", size, scenario, err)
			}
			if want == "" {
				want = result.Digest
			} else if result.Digest != want {
				t.Fatalf("size %d %s digest = %s, want %s", size, scenario, result.Digest, want)
			}
			if result.BytesProcessed != uint64(size*2) || result.BytesPerSecond <= 0 || result.GOMAXPROCS < 1 {
				t.Fatalf("invalid result: %+v", result)
			}
		}
	}
}

func TestParallelScenariosMatch(t *testing.T) {
	want, err := benchmark("one_shot", 64<<10, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"caller_parallel", "caller_parallel_segmented"} {
		result, err := benchmark(scenario, 64<<10, 2, 2)
		if err != nil {
			t.Fatal(err)
		}
		if result.Digest != want.Digest || result.BytesProcessed != (64<<10)*4 {
			t.Fatalf("invalid parallel result: %+v; want digest %s", result, want.Digest)
		}
	}
}

func TestRunAndErrors(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"perf", "one_shot", "64", "2", "1"}, &stdout); err != nil {
		t.Fatal(err)
	}
	var result record
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Digest == "" {
		t.Fatalf("invalid output: result=%+v err=%v", result, err)
	}
	for _, args := range [][]string{
		nil,
		{"perf", "unknown", "64", "1", "1"},
		{"perf", "one_shot", "bad", "1", "1"},
		{"perf", "one_shot", "64", "0", "1"},
		{"perf", "one_shot", "64", "1", "2"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid arguments accepted: %q", args)
		}
	}
}
