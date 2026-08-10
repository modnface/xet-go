package xet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
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

func TestDiskUploadJournalInputAndFailureContracts(t *testing.T) {
	if _, err := NewDiskUploadJournal("", "operation"); err == nil {
		t.Fatal("empty root succeeded")
	}
	if _, err := NewDiskUploadJournal(t.TempDir(), " "); err == nil {
		t.Fatal("empty operation ID succeeded")
	}
	hash := xethash.Chunk([]byte("journal contracts"))
	var nilJournal *DiskUploadJournal
	if _, err := nilJournal.HasXorb(context.Background(), hash); err == nil {
		t.Fatal("nil HasXorb succeeded")
	}
	if err := nilJournal.MarkXorb(context.Background(), hash); err == nil {
		t.Fatal("nil MarkXorb succeeded")
	}
	if err := nilJournal.Clear(context.Background()); err == nil {
		t.Fatal("nil Clear succeeded")
	}

	journal, err := NewDiskUploadJournal(t.TempDir(), "operation")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := journal.HasXorb(ctx, hash); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled HasXorb = %v", err)
	}
	if err := journal.MarkXorb(ctx, hash); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled MarkXorb = %v", err)
	}
	if err := journal.Clear(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Clear = %v", err)
	}
	if err := journal.Clear(context.Background()); err != nil {
		t.Fatalf("clear missing journal: %v", err)
	}

	if err := journal.MarkXorb(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkXorb(context.Background(), hash); err != nil {
		t.Fatalf("idempotent mark: %v", err)
	}
	entryPath := filepath.Join(journal.directory, hash.String()+".xorb")
	if err := os.Remove(entryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(entryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.HasXorb(context.Background(), hash); err == nil {
		t.Fatal("journal directory entry read succeeded")
	}
	if err := journal.Clear(context.Background()); err == nil {
		t.Fatal("journal containing a directory cleared")
	}
}

func TestDiskUploadJournalFilesystemErrors(t *testing.T) {
	hash := xethash.Chunk([]byte("filesystem errors"))
	root := t.TempDir()
	parentFile := filepath.Join(root, "file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal := &DiskUploadJournal{directory: filepath.Join(parentFile, "journal")}
	if err := journal.MarkXorb(context.Background(), hash); err == nil {
		t.Fatal("mark below regular file succeeded")
	}

	journal = &DiskUploadJournal{directory: parentFile}
	if err := journal.Clear(context.Background()); err == nil {
		t.Fatal("clear on regular file succeeded")
	}
	if _, err := journal.HasXorb(context.Background(), hash); err == nil {
		t.Fatal("read below regular file succeeded")
	}
}

type cancelOnSecondCheck struct{ calls int }

func (*cancelOnSecondCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*cancelOnSecondCheck) Done() <-chan struct{}       { return nil }
func (c *cancelOnSecondCheck) Err() error {
	c.calls++
	if c.calls >= 2 {
		return context.Canceled
	}
	return nil
}
func (*cancelOnSecondCheck) Value(any) any { return nil }

func TestDiskUploadJournalCancellationDuringClear(t *testing.T) {
	journal, err := NewDiskUploadJournal(t.TempDir(), "cancel during clear")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(journal.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal.directory, "entry"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelOnSecondCheck{}
	if err := journal.Clear(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Clear cancellation = %v", err)
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
