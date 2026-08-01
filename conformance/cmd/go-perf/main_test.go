package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

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
	if err := writeProfile("", "allocs"); err != nil {
		t.Fatal(err)
	}
	if err := writeProfile(filepath.Join(t.TempDir(), "unknown.pprof"), "unknown"); err == nil {
		t.Fatal("unknown runtime profile accepted")
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
