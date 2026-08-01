package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

func TestSummarizeRejectsUnbalancedAndUnstableSamples(t *testing.T) {
	goRecord := validRecord("go-xet")
	rustRecord := validRecord("rust-xet-core")
	if _, err := summarize("xorb_encode_none", 100, 2, nil, nil); err == nil {
		t.Fatal("empty samples succeeded")
	}
	if _, err := summarize("xorb_encode_none", 100, 2, []benchRecord{goRecord}, []benchRecord{rustRecord, rustRecord}); err == nil {
		t.Fatal("unbalanced samples succeeded")
	}
	unstableGo := goRecord
	unstableGo.Chunks++
	if _, err := summarize("xorb_encode_none", 100, 2,
		[]benchRecord{goRecord, unstableGo}, []benchRecord{rustRecord, rustRecord}); err == nil {
		t.Fatal("unstable Go samples succeeded")
	}
	unstableRust := rustRecord
	unstableRust.SerializedSize++
	if _, err := summarize("xorb_encode_none", 100, 2,
		[]benchRecord{goRecord, goRecord}, []benchRecord{rustRecord, unstableRust}); err == nil {
		t.Fatal("unstable Rust samples succeeded")
	}
	if medianFloat([]float64{2, 4}) != 3 || medianUint64([]uint64{2, 5}) != 3 {
		t.Fatal("even median differs")
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

func TestCompareRunsBothImplementationsAndAlternatesOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX shell script")
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "input.bin")
	if err := os.WriteFile(input, []byte("benchmark input"), 0o600); err != nil {
		t.Fatal(err)
	}
	goBinary := writeBenchmarkHelper(t, directory, "go-helper", "go-xet")
	rustBinary := writeBenchmarkHelper(t, directory, "rust-helper", "rust-xet-core")

	got, err := compare(goBinary, rustBinary, input, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.Input.Name != "input.bin" || got.Input.Size != len("benchmark input") ||
		got.Iterations != 2 || got.SampleCount != 2 || len(got.Comparisons) != len(operations) {
		t.Fatalf("report = %#v", got)
	}
	for _, comparison := range got.Comparisons {
		if comparison.Go.Implementation != "go-xet" || comparison.Rust.Implementation != "rust-xet-core" || comparison.GoRustRatio != 1 {
			t.Fatalf("comparison = %#v", comparison)
		}
	}
}

func TestInvokeRejectsProcessAndRecordFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses POSIX shell scripts")
	}
	directory := t.TempDir()
	for name, script := range map[string]string{
		"process":      "#!/bin/sh\necho failure >&2\nexit 7\n",
		"invalid-json": "#!/bin/sh\nprintf 'not json'\n",
		"invalid-data": "#!/bin/sh\nprintf '%s\\n' '{\"schema_version\":1}'\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := invoke(path, "input", "chunk_hash", 1); err == nil {
				t.Fatal("invoke succeeded")
			}
		})
	}
}

func TestCompareReportsWarmupFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses POSIX shell scripts")
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "input")
	if err := os.WriteFile(input, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodGo := writeBenchmarkHelper(t, directory, "go", "go-xet")
	goodRust := writeBenchmarkHelper(t, directory, "rust", "rust-xet-core")
	broken := filepath.Join(directory, "broken")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := compare(broken, goodRust, input, 1, 1); err == nil || !strings.Contains(err.Error(), "go warmup") {
		t.Fatalf("Go warmup error = %v", err)
	}
	if _, err := compare(goodGo, broken, input, 1, 1); err == nil || !strings.Contains(err.Error(), "rust warmup") {
		t.Fatalf("Rust warmup error = %v", err)
	}
}

func TestCompareReportsInputAndTimedFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses POSIX shell scripts")
	}
	if _, err := compare("go", "rust", filepath.Join(t.TempDir(), "missing"), 1, 1); err == nil {
		t.Fatal("missing input succeeded")
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "input.bin")
	if err := os.WriteFile(input, []byte("benchmark input"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodGo := writeBenchmarkHelper(t, directory, "good-go", "go-xet")
	goodRust := writeBenchmarkHelper(t, directory, "good-rust", "rust-xet-core")
	timedFailure := filepath.Join(directory, "timed-failure")
	script := "#!/bin/sh\nif [ \"$4\" != \"1\" ]; then echo timed failure >&2; exit 1; fi\n" +
		"printf '%s\\n' '{\"schema_version\":1,\"implementation\":\"go-xet\",\"operation\":\"'$3'\",\"input_size\":15,\"iterations\":1,\"elapsed_ns\":1,\"bytes_per_second\":1,\"identity\":\"identity\",\"chunks\":3}'\n"
	if err := os.WriteFile(timedFailure, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := compare(timedFailure, goodRust, input, 2, 1); err == nil {
		t.Fatal("timed Go failure succeeded")
	}
	// The warmup record must identify as Rust before exercising the timed Rust failure.
	rustScript := strings.Replace(script, `"go-xet"`, `"rust-xet-core"`, 1)
	if err := os.WriteFile(timedFailure, []byte(rustScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := compare(goodGo, timedFailure, input, 2, 1); err == nil {
		t.Fatal("timed Rust failure succeeded")
	}
}

func TestWriteAtomicPublishesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := writeAtomic(path, []byte("report")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "report" {
		t.Fatalf("data = %q, err = %v", data, err)
	}
	parentFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(parentFile, "report"), []byte("x")); err == nil {
		t.Fatal("write below regular file succeeded")
	}
}

func TestRunValidatesArgumentsAndPublishesReports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX shell script")
	}
	if err := run(nil, io.Discard); err == nil {
		t.Fatal("missing command arguments succeeded")
	}
	if err := run([]string{"-unknown"}, io.Discard); err == nil {
		t.Fatal("unknown flag succeeded")
	}

	directory := t.TempDir()
	input := filepath.Join(directory, "input.bin")
	if err := os.WriteFile(input, []byte("benchmark input"), 0o600); err != nil {
		t.Fatal(err)
	}
	goBinary := writeBenchmarkHelper(t, directory, "go-helper", "go-xet")
	rustBinary := writeBenchmarkHelper(t, directory, "rust-helper", "rust-xet-core")
	jsonPath := filepath.Join(directory, "reports", "comparison.json")
	markdownPath := filepath.Join(directory, "reports", "comparison.md")
	args := []string{
		"-go", goBinary, "-rust", rustBinary, "-input", input,
		"-iterations", "1", "-samples", "1", "-json", jsonPath, "-markdown", markdownPath,
	}
	var stdout bytes.Buffer
	if err := run(args, &stdout); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != jsonPath+"\n"+markdownPath+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if err := run(args, failingWriter{}); err == nil {
		t.Fatal("command output failure succeeded")
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var result report
	if err := json.Unmarshal(data, &result); err != nil || len(result.Comparisons) != len(operations) {
		t.Fatalf("JSON report = %#v, error %v", result, err)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil || !strings.Contains(string(markdown), "Go versus official Rust") {
		t.Fatalf("Markdown report = %q, error %v", markdown, err)
	}

	parentFile := filepath.Join(directory, "regular-file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badJSON := append([]string(nil), args...)
	badJSON[len(badJSON)-3] = filepath.Join(parentFile, "report.json")
	if err := run(badJSON, io.Discard); err == nil {
		t.Fatal("unwritable JSON report succeeded")
	}
	badMarkdown := append([]string(nil), args...)
	badMarkdown[len(badMarkdown)-1] = filepath.Join(parentFile, "report.md")
	if err := run(badMarkdown, io.Discard); err == nil {
		t.Fatal("unwritable Markdown report succeeded")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }

func writeBenchmarkHelper(t *testing.T, directory, name, implementation string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	script := `#!/bin/sh
operation="$3"
iterations="$4"
scheme=""
serialized=0
case "$operation" in
  *none) scheme="none"; serialized=99 ;;
  *lz4) scheme="lz4"; serialized=77 ;;
esac
printf '{"schema_version":1,"implementation":"%s","operation":"%s","scheme":"%s","input_size":15,"iterations":%s,"elapsed_ns":100,"bytes_per_second":200,"identity":"identity","serialized_size":%s,"chunks":3}\n' ` + implementation + ` "$operation" "$scheme" "$iterations" "$serialized"
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
