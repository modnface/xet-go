package xet

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

func TestDiskUploadJournalLifecycleAndCorruption(t *testing.T) {
	journal, err := NewDiskUploadJournal(t.TempDir(), "operation/with/untrusted/path")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("journal xorb"))
	if found, err := journal.HasXorb(context.Background(), hash); err != nil || found {
		t.Fatalf("empty journal found=%v err=%v", found, err)
	}
	if err := journal.MarkXorb(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	if found, err := journal.HasXorb(context.Background(), hash); err != nil || !found {
		t.Fatalf("marked journal found=%v err=%v", found, err)
	}
	path := journal.directory + string(os.PathSeparator) + hash.String() + ".xorb"
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := journal.HasXorb(context.Background(), hash); err != nil || found {
		t.Fatalf("corrupt journal found=%v err=%v", found, err)
	}
	if err := journal.MarkXorb(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	if err := journal.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found, err := journal.HasXorb(context.Background(), hash); err != nil || found {
		t.Fatalf("cleared journal found=%v err=%v", found, err)
	}
}

func TestUploadJournalResumesAfterShardFailure(t *testing.T) {
	protocol := newMemoryProtocol()
	protocol.shardFailures = 1
	journal, err := NewDiskUploadJournal(t.TempDir(), "resumable-upload")
	if err != nil {
		t.Fatal(err)
	}
	newClient := func() *Client {
		client, err := NewClient(protocol, Options{
			Compression: xorb.None, CompressionSet: true,
			UploadConcurrency: 2, DownloadConcurrency: 2,
			UploadJournal: journal,
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	data := deterministicData(2 << 20)
	if _, err := newClient().Upload(context.Background(), bytes.NewReader(data)); err == nil {
		t.Fatal("injected shard failure did not fail upload")
	}
	protocol.mu.Lock()
	xorbsAfterFailure := len(protocol.objects)
	protocol.mu.Unlock()
	if xorbsAfterFailure == 0 {
		t.Fatal("first attempt did not upload an xorb")
	}
	result, err := newClient().Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.Xorbs != 0 || result.Report.ResumedXorbs != xorbsAfterFailure || !result.Report.JournalCleared {
		t.Fatalf("unexpected resumed report: %#v", result.Report)
	}
	var output bytes.Buffer
	if _, err := newClient().Download(context.Background(), result.File, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("resumed upload reconstruction differs")
	}
}
