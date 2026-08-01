package xet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacobwoliver/xet-go/xetcas"
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
