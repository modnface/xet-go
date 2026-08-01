// Command perf-fixture writes deterministic inputs for local performance
// comparisons. Generated files are benchmark artifacts, not protocol vectors.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	size := flag.Int("size", 0, "fixture size in bytes")
	pattern := flag.String("pattern", "random", "content pattern: zero, repeat, or random")
	output := flag.String("output", "", "output file")
	flag.Parse()
	if *size <= 0 || *output == "" {
		fatal(errors.New("positive -size and -output are required"))
	}
	data, err := generate(*size, *pattern)
	if err != nil {
		fatal(err)
	}
	if err := writeAtomic(*output, data); err != nil {
		fatal(err)
	}
}

func generate(size int, pattern string) ([]byte, error) {
	data := make([]byte, size)
	switch pattern {
	case "zero":
	case "repeat":
		const seed = "xet-go deterministic performance fixture\n"
		for offset := 0; offset < len(data); {
			offset += copy(data[offset:], seed)
		}
	case "random":
		state := uint64(0x4d595df4d0f33173)
		for i := range data {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			data[i] = byte(state >> 56)
		}
	default:
		return nil, fmt.Errorf("unknown pattern %q", pattern)
	}
	return data, nil
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".perf-fixture-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "perf-fixture:", err)
	os.Exit(1)
}
