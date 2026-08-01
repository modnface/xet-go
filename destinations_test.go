package xet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
)

func TestUploadSourcesAndConvenienceInputs(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	first := deterministicData(300_000)
	second := deterministicData(180_000)
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	secondSHA := sha256.Sum256(second)
	result, err := client.UploadSources(context.Background(), []UploadSource{
		{Path: path, Size: int64(len(first))},
		{ReaderAt: bytes.NewReader(second), Size: int64(len(second)), SHA256: &secondSHA},
		{Reader: bytes.NewReader(first), Size: int64(len(first))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 3 || result.Files[0] != result.Files[2] || result.Report.Files != 3 ||
		result.Report.Dedup.SessionDedupBytes < uint64(len(first)) {
		t.Fatalf("unexpected source result: %#v", result)
	}
	if _, err := client.UploadSources(context.Background(), []UploadSource{{Reader: bytes.NewReader(first), Size: 1}}); err == nil {
		t.Fatal("accepted incorrect source size")
	}
}

func TestDownloadAtAndRangeAt(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	data := deterministicData(700_000)
	upload, err := client.UploadBytes(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	whole := make([]byte, len(data)+32)
	if _, err := client.DownloadAt(context.Background(), upload.File, sliceWriterAt(whole[16:])); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole[16:16+len(data)], data) {
		t.Fatal("random-access full download differs")
	}
	rangeValue := xetcas.FileRange{Start: 12_345, End: 345_678}
	partial := make([]byte, int(rangeValue.Len())+11)
	if _, err := client.DownloadRangeAt(context.Background(), upload.File.Hash, rangeValue,
		sliceWriterAt(partial), 7); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(partial[7:7+rangeValue.Len()], data[rangeValue.Start:rangeValue.End]) {
		t.Fatal("random-access range download differs")
	}
}

type sliceWriterAt []byte

func (w sliceWriterAt) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(w)) && len(data) != 0 {
		return 0, os.ErrInvalid
	}
	return copy(w[offset:], data), nil
}

func TestDownloadFilePublishesOnlyVerifiedContent(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	data := deterministicData(400_000)
	upload, err := client.UploadBytes(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("old-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := upload.File
	bad.SHA256 = sha256.Sum256([]byte("wrong SHA-256"))
	if _, err := client.DownloadFile(context.Background(), bad, path, DownloadFileOptions{NoSync: true}); err == nil {
		t.Fatal("corrupt file identity unexpectedly published")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, []byte("old-content")) {
		t.Fatalf("failed download changed destination: %q", unchanged)
	}
	if _, err := client.DownloadFile(context.Background(), upload.File, path, DownloadFileOptions{NoSync: true}); err != nil {
		t.Fatal(err)
	}
	completed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(completed, data) {
		t.Fatal("atomic file download differs")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".artifact.bin.xet-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v, %v", matches, err)
	}
}

func TestDownloadGroupPreservesRequestOrder(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	first := deterministicData(300_000)
	second := deterministicData(500_000)
	upload, err := client.UploadSources(context.Background(), []UploadSource{
		{Reader: bytes.NewReader(first), Size: int64(len(first))},
		{Reader: bytes.NewReader(second), Size: int64(len(second))},
	})
	if err != nil {
		t.Fatal(err)
	}
	var firstOut bytes.Buffer
	secondRange := xetcas.FileRange{Start: 11_111, End: 222_222}
	secondOut := make([]byte, secondRange.Len()+3)
	report, err := client.DownloadGroup(context.Background(), []DownloadRequest{
		{File: upload.Files[0], Writer: &firstOut},
		{File: upload.Files[1], Range: &secondRange, WriterAt: sliceWriterAt(secondOut), WriterAtOffset: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Downloads) != 2 || report.Downloads[0].Err != nil || report.Downloads[1].Err != nil ||
		report.LogicalBytes != uint64(len(first))+secondRange.Len() {
		t.Fatalf("unexpected group report: %#v", report)
	}
	if !bytes.Equal(firstOut.Bytes(), first) || !bytes.Equal(secondOut[3:], second[secondRange.Start:secondRange.End]) {
		t.Fatal("download group output differs")
	}
}

func TestUploadSourceValidationAndUploadFile(t *testing.T) {
	for name, source := range map[string]UploadSource{
		"none":           {},
		"multiple":       {Path: "path", Reader: bytes.NewReader(nil)},
		"missing path":   {Path: filepath.Join(t.TempDir(), "missing"), Size: -1},
		"ReaderAt size":  {ReaderAt: bytes.NewReader(nil), Size: -1},
		"invalid size":   {Reader: bytes.NewReader(nil), Size: -2},
		"directory path": {Path: t.TempDir(), Size: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := openUploadSource(source); err == nil {
				t.Fatalf("openUploadSource(%#v) succeeded", source)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("source data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := openUploadSource(UploadSource{Path: path, Size: 1}); err == nil {
		t.Fatal("incorrect path size succeeded")
	}

	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.UploadSources(context.Background(), nil); err == nil {
		t.Fatal("empty source batch succeeded")
	}
	wrongSHA := sha256.Sum256([]byte("wrong"))
	if _, err := client.UploadSources(context.Background(), []UploadSource{{Reader: bytes.NewReader([]byte("data")), Size: 4, SHA256: &wrongSHA}}); err == nil {
		t.Fatal("incorrect source SHA-256 succeeded")
	}
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := batch.AddSource(UploadSource{}); err == nil {
		t.Fatal("invalid AddSource succeeded")
	}
	batch.Abort(nil)
	if _, err := batch.AddSource(UploadSource{Reader: bytes.NewReader(nil), Size: 0}); !errors.Is(err, ErrBatchFinalized) {
		t.Fatalf("AddSource after abort = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.UploadSources(ctx, []UploadSource{{Reader: bytes.NewReader(nil), Size: 0}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled UploadSources = %v", err)
	}
	result, err := client.UploadFile(context.Background(), path)
	if err != nil || result.File.Size != uint64(len("source data")) {
		t.Fatalf("UploadFile = %#v, %v", result, err)
	}
	if _, err := client.UploadFile(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing UploadFile succeeded")
	}
}

type shortWriterAt struct {
	err error
}

func (w shortWriterAt) WriteAt(data []byte, _ int64) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return max(0, len(data)-1), nil
}

func TestRandomAccessDestinationContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.DownloadAt(context.Background(), FileInfo{}, nil); err == nil {
		t.Fatal("nil DownloadAt writer succeeded")
	}
	validRange := xetcas.FileRange{Start: 0, End: 1}
	if _, err := client.DownloadRangeAt(context.Background(), xethash.Zero, validRange, nil, 0); err == nil {
		t.Fatal("nil DownloadRangeAt writer succeeded")
	}
	if _, err := client.DownloadRangeAt(context.Background(), xethash.Zero, validRange, shortWriterAt{}, -1); err == nil {
		t.Fatal("negative destination offset succeeded")
	}
	if _, err := client.DownloadRangeAt(context.Background(), xethash.Zero, xetcas.FileRange{}, shortWriterAt{}, 0); err == nil {
		t.Fatal("invalid source range succeeded")
	}

	writer := &sequentialWriterAt{dst: shortWriterAt{}, offset: math.MaxInt64}
	if _, err := writer.Write([]byte("xx")); err == nil {
		t.Fatal("destination offset overflow succeeded")
	}
	writer = &sequentialWriterAt{dst: shortWriterAt{}}
	if _, err := writer.Write([]byte("xx")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v", err)
	}
	want := errors.New("write failed")
	writer = &sequentialWriterAt{dst: shortWriterAt{err: want}}
	if _, err := writer.Write([]byte("xx")); !errors.Is(err, want) {
		t.Fatalf("writer error = %v", err)
	}
}

func TestDownloadFileInputAndPublicationContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.DownloadFile(context.Background(), FileInfo{}, "", DownloadFileOptions{}); err == nil {
		t.Fatal("empty download path succeeded")
	}
	path := filepath.Join(t.TempDir(), "file")
	if _, err := client.DownloadFile(context.Background(), FileInfo{}, path, DownloadFileOptions{Mode: os.ModeDir}); err == nil {
		t.Fatal("non-regular mode succeeded")
	}
	if _, err := client.DownloadFile(context.Background(), FileInfo{}, filepath.Join(t.TempDir(), "missing", "file"), DownloadFileOptions{}); err == nil {
		t.Fatal("missing parent directory succeeded")
	}
	if strconv.IntSize == 64 {
		if _, err := client.DownloadFile(context.Background(), FileInfo{Size: math.MaxUint64}, path, DownloadFileOptions{}); err == nil {
			t.Fatal("oversized local file succeeded")
		}
	}

	upload, err := client.UploadBytes(context.Background(), []byte("durable download"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DownloadFile(context.Background(), upload.File, path, DownloadFileOptions{Mode: 0o640}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, err = %v", info.Mode(), err)
	}

	directoryTarget := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directoryTarget, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DownloadFile(context.Background(), upload.File, directoryTarget, DownloadFileOptions{NoSync: true}); err == nil {
		t.Fatal("rename over non-empty directory succeeded")
	}
}

func TestDownloadGroupInputAndCancellationContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.DownloadGroup(nil, nil); err == nil { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatal("nil group context succeeded")
	}
	empty, err := client.DownloadGroup(context.Background(), nil)
	if err != nil || empty.Downloads == nil || len(empty.Downloads) != 0 {
		t.Fatalf("empty group = %#v, %v", empty, err)
	}
	buffer := &bytes.Buffer{}
	for name, request := range map[string]DownloadRequest{
		"no destination":   {},
		"two destinations": {Writer: buffer, WriterAt: shortWriterAt{}},
		"negative offset":  {Writer: buffer, WriterAtOffset: -1},
		"invalid range":    {Writer: buffer, Range: &xetcas.FileRange{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.DownloadGroup(context.Background(), []DownloadRequest{request}); err == nil {
				t.Fatal("invalid request succeeded")
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := client.DownloadGroup(ctx, []DownloadRequest{{Writer: &bytes.Buffer{}}, {Writer: &bytes.Buffer{}}})
	if !errors.Is(err, context.Canceled) || len(report.Downloads) != 2 {
		t.Fatalf("canceled group = %#v, %v", report, err)
	}
	if err := firstDownloadGroupError(errors.New("first"), context.Background(), context.Background()); err == nil || err.Error() != "first" {
		t.Fatalf("first error = %v", err)
	}
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	if err := firstDownloadGroupError(nil, parent, context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent error = %v", err)
	}

	failing := newTestEngine(t, newMemoryProtocol())
	report, err = failing.DownloadGroup(context.Background(), []DownloadRequest{
		{File: FileInfo{Hash: xethash.Chunk([]byte("missing-one"))}, WriterAt: sliceWriterAt(make([]byte, 1))},
		{File: FileInfo{Hash: xethash.Chunk([]byte("missing-two"))}, Range: &xetcas.FileRange{Start: 0, End: 1}, Writer: &bytes.Buffer{}},
		{File: FileInfo{Hash: xethash.Chunk([]byte("missing-three"))}, Writer: &bytes.Buffer{}},
	})
	if err == nil || len(report.Downloads) != 3 {
		t.Fatalf("failing group = %#v, %v", report, err)
	}
}
