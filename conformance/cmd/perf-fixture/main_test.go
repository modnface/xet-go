package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateDeterministicPatterns(t *testing.T) {
	for _, pattern := range []string{"zero", "repeat", "random"} {
		first, err := generate(257, pattern)
		if err != nil {
			t.Fatalf("%s: %v", pattern, err)
		}
		second, err := generate(257, pattern)
		if err != nil {
			t.Fatalf("%s second call: %v", pattern, err)
		}
		if len(first) != 257 || !bytes.Equal(first, second) {
			t.Fatalf("%s is not deterministic at requested size", pattern)
		}
	}
	zero, _ := generate(257, "zero")
	if !bytes.Equal(zero, make([]byte, len(zero))) {
		t.Fatal("zero pattern contains nonzero bytes")
	}
	repeated, _ := generate(257, "repeat")
	if !bytes.HasPrefix(repeated, []byte("xet-go deterministic performance fixture\n")) {
		t.Fatal("repeat pattern has an unexpected prefix")
	}
	random, _ := generate(257, "random")
	if bytes.Equal(random, zero) || bytes.Equal(random, repeated) {
		t.Fatal("random pattern duplicates a low-entropy pattern")
	}
}

func TestGenerateRejectsUnknownPattern(t *testing.T) {
	if _, err := generate(1, "unknown"); err == nil {
		t.Fatal("unknown pattern accepted")
	}
}

func TestWriteAtomicCreatesParentsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "fixture.bin")
	want := []byte("deterministic fixture")
	if err := writeAtomic(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("written data = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want 644", info.Mode().Perm())
	}
}
