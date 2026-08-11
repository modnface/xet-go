package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jmwoliver/xet-go/content"
)

func TestConfigurationAndObjectKeys(t *testing.T) {
	client := newFakeClient()
	if _, err := New(nil, Options{}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("nil public client = %v", err)
	}
	if _, err := New(awss3.NewFromConfig(aws.Config{Region: "us-east-1"}), Options{Bucket: "bucket"}); err != nil {
		t.Fatalf("public constructor = %v", err)
	}
	if _, err := newStore(nil, Options{Bucket: "bucket"}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("nil private client = %v", err)
	}
	for _, bucket := range []string{"", " bucket", "bucket ", "bad\x00bucket"} {
		if _, err := newStore(client, Options{Bucket: bucket}); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("bucket %q = %v", bucket, err)
		}
	}
	for _, prefix := range []string{
		"/root", "root/", "root//leaf", "root/./leaf", "root/../leaf", "root\\leaf", "root\x00leaf", strings.Repeat("a", 513),
	} {
		if _, err := newStore(client, Options{Bucket: "bucket", Prefix: prefix}); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("prefix %q = %v", prefix, err)
		}
	}
	if _, err := newStore(client, Options{Bucket: "bucket", TempDirectory: filepath.Join(t.TempDir(), "missing")}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("missing temporary directory = %v", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newStore(client, Options{Bucket: "bucket", TempDirectory: file}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("file temporary directory = %v", err)
	}
	store, err := newStore(client, Options{Bucket: "bucket", Prefix: "operator/content", TempDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	if got, want := store.objectKey(sum), "operator/content/content-v1/blobs/00/00/"+strings.Repeat("0", 64); got != want {
		t.Fatalf("object key = %q, want %q", got, want)
	}
	if prefix, err := validatePrefix(""); err != nil || prefix != "" {
		t.Fatalf("empty prefix = %q, %v", prefix, err)
	}
}

func TestConditionalComparisonFaults(t *testing.T) {
	ctx := context.Background()
	body := []byte("conditional comparison body")
	blob := testBlob(body)
	precondition := &smithy.GenericAPIError{Code: "PreconditionFailed"}
	for name, configure := range map[string]func(*fakeClient, *Store, error){
		"head failure": func(client *fakeClient, _ *Store, failure error) {
			client.head = func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
				return nil, failure
			}
		},
		"open head failure": func(client *fakeClient, store *Store, failure error) {
			client.setObject(store.objectKey(blob.SHA256), body)
			var calls int
			client.head = func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
				calls++
				if calls == 1 {
					return &awss3.HeadObjectOutput{ContentLength: aws.Int64(blob.Size)}, nil
				}
				return nil, failure
			}
		},
		"comparison read failure": func(client *fakeClient, store *Store, failure error) {
			client.setObject(store.objectKey(blob.SHA256), body)
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return &awss3.GetObjectOutput{
					Body:          &terminalReadCloser{terminalReader: terminalReader{data: body, err: failure}},
					ContentLength: aws.Int64(blob.Size),
				}, nil
			}
		},
		"comparison close failure": func(client *fakeClient, store *Store, failure error) {
			client.setObject(store.objectKey(blob.SHA256), body)
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return &awss3.GetObjectOutput{
					Body:          &observedReadCloser{Reader: bytes.NewReader(body), closeErr: failure},
					ContentLength: aws.Int64(blob.Size),
				}, nil
			}
		},
		"mismatch and close failure": func(client *fakeClient, store *Store, failure error) {
			wrong := bytes.Repeat([]byte{'x'}, len(body))
			client.setObject(store.objectKey(blob.SHA256), wrong)
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return &awss3.GetObjectOutput{
					Body:          &observedReadCloser{Reader: bytes.NewReader(wrong), closeErr: failure},
					ContentLength: aws.Int64(blob.Size),
				}, nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newFakeClient()
			store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
			failure := errors.New("injected comparison failure")
			client.putErrors = []error{precondition}
			configure(client, store, failure)
			_, err := store.Put(ctx, blob, bytes.NewReader(body))
			if !errors.Is(err, failure) {
				t.Fatalf("comparison failure = %v", err)
			}
			if name == "mismatch and close failure" && !errors.Is(err, content.ErrConflict) {
				t.Fatalf("mismatch classification = %v", err)
			}
		})
	}
	t.Run("object disappears before comparison open", func(t *testing.T) {
		client := newFakeClient()
		store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
		client.setObject(store.objectKey(blob.SHA256), body)
		client.putErrors = []error{precondition}
		var calls int
		client.head = func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
			calls++
			if calls == 1 {
				return &awss3.HeadObjectOutput{ContentLength: aws.Int64(blob.Size)}, nil
			}
			return nil, &smithy.GenericAPIError{Code: "NoSuchKey"}
		}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, content.ErrNotFound) {
			t.Fatalf("disappearing object = %v", err)
		}
	})

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := compare(canceled, bytes.NewReader(body), bytes.NewReader(body), int64(len(body))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled comparison = %v", err)
	}
	if err := compare(ctx, bytes.NewReader(body[:1]), bytes.NewReader(body), int64(len(body))); !errors.Is(err, content.ErrConflict) || !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("short comparison = %v", err)
	}
	if equal([]byte{1}, []byte{1, 2}) || !equal([]byte{1, 2}, []byte{1, 2}) {
		t.Fatal("constant-time equality length handling is incorrect")
	}

	temporary := t.TempDir()
	client := newFakeClient()
	store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: temporary})
	if err := os.RemoveAll(temporary); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("spool creation failure = %v", err)
	}
	writeFailure := errors.New("local spool write failed")
	if _, err := (localSpoolWriter{Writer: errorWriter{err: writeFailure}}).Write(body); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, writeFailure) {
		t.Fatalf("local spool error = %v", err)
	}
	if _, err := (localSpoolWriter{Writer: shortWriter{}}).Write(body); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("local spool short write = %v", err)
	}
	spoolReadFailure := errors.New("local spool read failed")
	if _, err := (localSpoolReader{Reader: &terminalReader{err: spoolReadFailure}}).Read(make([]byte, 1)); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, spoolReadFailure) {
		t.Fatalf("local spool read error = %v", err)
	}
	if err := compare(ctx, bytes.NewReader([]byte{1}), bytes.NewReader(nil), 0); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("comparison extra byte = %v", err)
	}
	probeFailure := errors.New("comparison probe failed")
	if err := compare(ctx, &terminalReader{err: probeFailure}, bytes.NewReader(nil), 0); !errors.Is(err, probeFailure) {
		t.Fatalf("comparison probe error = %v", err)
	}
	if count, err := readBlock(&invalidCountReader{count: -1}, make([]byte, 1)); count != 0 || !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("negative read count = %d, %v", count, err)
	}
	if count, err := readBlock(&invalidCountReader{count: 2}, make([]byte, 1)); count != 0 || !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("oversized read count = %d, %v", count, err)
	}
	if count, err := readBlock(noProgressReader{}, make([]byte, 1)); count != 0 || !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("no-progress read = %d, %v", count, err)
	}
	if count, err := readBlock(&oneByteReader{data: body}, make([]byte, len(body))); count != len(body) || err != nil {
		t.Fatalf("partial-progress read = %d, %v", count, err)
	}
}

func TestPutIsVerifiedImmutableAndCleansSpool(t *testing.T) {
	ctx := context.Background()
	temporary := t.TempDir()
	client := newFakeClient()
	store, err := newStore(client, Options{Bucket: "bucket", Prefix: "put", TempDirectory: temporary})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("ordinary S3 content")
	blob := testBlob(body)
	if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || !inserted {
		t.Fatalf("first put = %v, %v", inserted, err)
	}
	if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || inserted {
		t.Fatalf("idempotent put = %v, %v", inserted, err)
	}
	client.mu.Lock()
	lastPut := client.lastPut
	putCalls := client.putCalls
	client.mu.Unlock()
	if lastPut == nil || aws.ToString(lastPut.Bucket) != "bucket" || aws.ToString(lastPut.Key) != store.objectKey(blob.SHA256) ||
		aws.ToString(lastPut.IfNoneMatch) != "*" || aws.ToInt64(lastPut.ContentLength) != blob.Size || putCalls != 2 {
		t.Fatalf("put request = %#v, calls %d", lastPut, putCalls)
	}
	if client.requestChecksum != aws.RequestChecksumCalculationWhenRequired {
		t.Fatalf("request checksum mode = %v", client.requestChecksum)
	}
	assertDirectoryEmpty(t, temporary)

	client.setObject(store.objectKey(blob.SHA256), bytes.Repeat([]byte{'x'}, len(body)))
	if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("immutable collision = %v", err)
	}
	client.setObject(store.objectKey(blob.SHA256), []byte("short"))
	if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("immutable length collision = %v", err)
	}
	assertDirectoryEmpty(t, temporary)

	for name, test := range map[string]struct {
		blob   content.Blob
		reader io.Reader
		want   error
	}{
		"negative size": {content.Blob{Size: -1}, bytes.NewReader(nil), content.ErrInvalid},
		"nil body":      {blob, nil, content.ErrInvalid},
		"short body":    {blob, bytes.NewReader(body[:len(body)-1]), content.ErrCorrupt},
		"long body":     {blob, bytes.NewReader(append(append([]byte(nil), body...), 'x')), content.ErrCorrupt},
		"wrong SHA":     {content.Blob{SHA256: sha256.Sum256([]byte("different")), Size: blob.Size}, bytes.NewReader(body), content.ErrCorrupt},
	} {
		t.Run(name, func(t *testing.T) {
			before := client.callCount()
			if _, err := store.Put(ctx, test.blob, test.reader); !errors.Is(err, test.want) {
				t.Fatalf("put error = %v, want %v", err, test.want)
			}
			if got := client.callCount(); got != before {
				t.Fatalf("network calls = %d, want %d", got, before)
			}
			assertDirectoryEmpty(t, temporary)
		})
	}
	if _, err := store.Put(nil, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatalf("nil context = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Put(canceled, blob, bytes.NewReader(body)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put = %v", err)
	}
	sourceFailure := errors.New("source terminal failure")
	if _, err := store.Put(ctx, blob, &terminalReader{data: body, err: sourceFailure}); !errors.Is(err, sourceFailure) {
		t.Fatalf("source terminal error = %v", err)
	}
}

func TestPutConditionalErrorsRetriesAndAbsentRace(t *testing.T) {
	ctx := context.Background()
	body := []byte("conditional S3 body")
	blob := testBlob(body)
	for name, failure := range map[string]error{
		"API":    &smithy.GenericAPIError{Code: "PreconditionFailed"},
		"status": statusError(http.StatusPreconditionFailed),
	} {
		t.Run("absent after "+name, func(t *testing.T) {
			client := newFakeClient()
			client.putErrors = []error{failure}
			store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
			if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
				t.Fatalf("absent conflict = %v", err)
			}
		})
	}
	t.Run("conditional retries then succeeds", func(t *testing.T) {
		client := newFakeClient()
		client.putErrors = []error{
			&smithy.GenericAPIError{Code: "ConditionalRequestConflict"}, statusError(http.StatusConflict),
		}
		store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
		if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || !inserted {
			t.Fatalf("retry put = %v, %v", inserted, err)
		}
		if got := client.putCount(); got != 3 {
			t.Fatalf("put calls = %d", got)
		}
	})
	t.Run("retry limit", func(t *testing.T) {
		client := newFakeClient()
		for range conditionalRetries + 1 {
			client.putErrors = append(client.putErrors, &smithy.GenericAPIError{Code: "ConditionalRequestConflict"})
		}
		store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("retry limit = %v", err)
		}
		if got := client.putCount(); got != conditionalRetries+1 {
			t.Fatalf("put calls = %d", got)
		}
	})
	t.Run("canceled retry", func(t *testing.T) {
		client := newFakeClient()
		client.putErrors = []error{&smithy.GenericAPIError{Code: "ConditionalRequestConflict"}}
		ctx, cancel := context.WithCancel(ctx)
		client.afterPut = cancel
		store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled retry = %v", err)
		}
	})
	t.Run("backend error preserves cause", func(t *testing.T) {
		client := newFakeClient()
		failure := errors.New("backend failed")
		client.putErrors = []error{failure}
		store, _ := newStore(client, Options{Bucket: "bucket", TempDirectory: t.TempDir()})
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, failure) {
			t.Fatalf("backend error = %v", err)
		}
	})
}

func TestHeadClassifiesS3Responses(t *testing.T) {
	ctx := context.Background()
	client := newFakeClient()
	store, _ := newStore(client, Options{Bucket: "bucket"})
	body := []byte("head body")
	blob := testBlob(body)
	client.setObject(store.objectKey(blob.SHA256), body)
	if info, found, err := store.Head(ctx, blob.SHA256); err != nil || !found || info.Size != blob.Size {
		t.Fatalf("head = %#v, %v, %v", info, found, err)
	}
	if _, found, err := store.Head(ctx, sha256.Sum256([]byte("missing"))); err != nil || found {
		t.Fatalf("missing head = %v, %v", found, err)
	}
	for name, failure := range map[string]error{
		"status missing": statusError(http.StatusNotFound),
		"API missing":    &smithy.GenericAPIError{Code: "NotFound"},
	} {
		t.Run(name, func(t *testing.T) {
			client.head = func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) { return nil, failure }
			defer func() { client.head = nil }()
			if _, found, err := store.Head(ctx, blob.SHA256); err != nil || found {
				t.Fatalf("head = %v, %v", found, err)
			}
		})
	}
	for name, output := range map[string]*awss3.HeadObjectOutput{
		"nil": nil, "missing length": {}, "negative": {ContentLength: aws.Int64(-1)},
	} {
		t.Run(name, func(t *testing.T) {
			client.head = func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) { return output, nil }
			defer func() { client.head = nil }()
			if _, _, err := store.Head(ctx, blob.SHA256); !errors.Is(err, content.ErrCorrupt) {
				t.Fatalf("head metadata = %v", err)
			}
		})
	}
	failure := errors.New("head backend failed")
	client.head = func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) { return nil, failure }
	if _, _, err := store.Head(ctx, blob.SHA256); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, failure) {
		t.Fatalf("head backend = %v", err)
	}
	if _, _, err := store.Head(nil, blob.SHA256); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatalf("nil head context = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.Head(canceled, blob.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled head context = %v", err)
	}
}

func TestOpenFullRangeEmptyAndFailures(t *testing.T) {
	ctx := context.Background()
	body := []byte("S3 ordinary content with ranges")
	blob := testBlob(body)
	client := newFakeClient()
	store, _ := newStore(client, Options{Bucket: "bucket", Prefix: "open"})
	client.setObject(store.objectKey(blob.SHA256), body)
	assertOpened(t, store, blob, nil, body)
	wanted := content.Range{Start: 3, End: int64(len(body) - 4)}
	assertOpened(t, store, blob, &wanted, body[wanted.Start:wanted.End])
	client.mu.Lock()
	lastGet := client.lastGet
	client.mu.Unlock()
	if lastGet == nil || aws.ToString(lastGet.Range) != fmt.Sprintf("bytes=%d-%d", wanted.Start, wanted.End-1) {
		t.Fatalf("range request = %#v", lastGet)
	}
	empty := testBlob(nil)
	client.setObject(store.objectKey(empty.SHA256), nil)
	assertOpened(t, store, empty, nil, nil)

	if _, err := store.Open(nil, blob, nil); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatalf("nil open context = %v", err)
	}
	if _, err := store.Open(ctx, content.Blob{Size: -1}, nil); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("invalid blob = %v", err)
	}
	missing := testBlob([]byte("missing"))
	if _, err := store.Open(ctx, missing, nil); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("missing open = %v", err)
	}
	wrongSize := blob
	wrongSize.Size++
	if _, err := store.Open(ctx, wrongSize, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("retained size = %v", err)
	}
	for _, invalid := range []content.Range{{Start: -1, End: 1}, {Start: 0, End: 0}, {Start: 0, End: blob.Size + 1}} {
		if _, err := store.Open(ctx, blob, &invalid); !errors.Is(err, content.ErrRangeNotSatisfiable) {
			t.Fatalf("range %#v = %v", invalid, err)
		}
	}

	for name, failure := range map[string]error{
		"missing API":    &smithy.GenericAPIError{Code: "NoSuchKey"},
		"missing status": statusError(http.StatusNotFound),
		"range API":      &smithy.GenericAPIError{Code: "InvalidRange"},
		"range status":   statusError(http.StatusRequestedRangeNotSatisfiable),
	} {
		t.Run(name, func(t *testing.T) {
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) { return nil, failure }
			defer func() { client.get = nil }()
			requested := (*content.Range)(nil)
			want := content.ErrNotFound
			if strings.HasPrefix(name, "range") {
				requested, want = &wanted, content.ErrRangeNotSatisfiable
			}
			if _, err := store.Open(ctx, blob, requested); !errors.Is(err, want) {
				t.Fatalf("get error = %v", err)
			}
		})
	}
	getFailure := errors.New("get backend failed")
	client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) { return nil, getFailure }
	if _, err := store.Open(ctx, blob, nil); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, getFailure) {
		t.Fatalf("get backend = %v", err)
	}
	client.get = nil
}

func TestOpenRejectsMetadataAndVerifiesStreams(t *testing.T) {
	ctx := context.Background()
	body := []byte("verified S3 stream")
	blob := testBlob(body)
	client := newFakeClient()
	store, _ := newStore(client, Options{Bucket: "bucket"})
	client.setObject(store.objectKey(blob.SHA256), body)

	for name, makeOutput := range map[string]func(*observedReadCloser) *awss3.GetObjectOutput{
		"nil": func(*observedReadCloser) *awss3.GetObjectOutput { return nil },
		"nil body": func(*observedReadCloser) *awss3.GetObjectOutput {
			return &awss3.GetObjectOutput{ContentLength: aws.Int64(blob.Size)}
		},
		"nil length": func(reader *observedReadCloser) *awss3.GetObjectOutput {
			return &awss3.GetObjectOutput{Body: reader}
		},
		"negative length": func(reader *observedReadCloser) *awss3.GetObjectOutput {
			return &awss3.GetObjectOutput{Body: reader, ContentLength: aws.Int64(-1)}
		},
		"wrong length": func(reader *observedReadCloser) *awss3.GetObjectOutput {
			return &awss3.GetObjectOutput{Body: reader, ContentLength: aws.Int64(blob.Size - 1)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader := &observedReadCloser{Reader: bytes.NewReader(body)}
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return makeOutput(reader), nil
			}
			defer func() { client.get = nil }()
			if _, err := store.Open(ctx, blob, nil); !errors.Is(err, content.ErrCorrupt) {
				t.Fatalf("metadata = %v", err)
			}
			if name != "nil" && name != "nil body" && !reader.closed.Load() {
				t.Fatal("rejected response body was not closed")
			}
		})
	}
	for name, contentRange := range map[string]*string{
		"nil range":   nil,
		"wrong range": aws.String(fmt.Sprintf("bytes %d-%d/%d", 2, 3, blob.Size)),
	} {
		t.Run(name, func(t *testing.T) {
			reader := &observedReadCloser{Reader: bytes.NewReader(body[1:3])}
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return &awss3.GetObjectOutput{Body: reader, ContentLength: aws.Int64(2), ContentRange: contentRange}, nil
			}
			defer func() { client.get = nil }()
			wanted := content.Range{Start: 1, End: 3}
			if _, err := store.Open(ctx, blob, &wanted); !errors.Is(err, content.ErrCorrupt) || !reader.closed.Load() {
				t.Fatalf("range metadata = %v, closed %v", err, reader.closed.Load())
			}
		})
	}

	for name, stream := range map[string]io.ReadCloser{
		"corrupt SHA": io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, len(body)))),
		"short":       io.NopCloser(bytes.NewReader(body[:len(body)-1])),
		"long":        io.NopCloser(bytes.NewReader(append(append([]byte(nil), body...), 'x'))),
	} {
		t.Run(name, func(t *testing.T) {
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return &awss3.GetObjectOutput{Body: stream, ContentLength: aws.Int64(blob.Size)}, nil
			}
			defer func() { client.get = nil }()
			opened, err := store.Open(ctx, blob, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadAll(opened); !errors.Is(err, content.ErrCorrupt) {
				t.Fatalf("stream verification = %v", err)
			}
			_ = opened.Close()
		})
	}

	readFailure := errors.New("terminal backend read failure")
	client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
		return &awss3.GetObjectOutput{
			Body: &terminalReadCloser{terminalReader: terminalReader{data: body, err: readFailure}}, ContentLength: aws.Int64(blob.Size),
		}, nil
	}
	opened, err := store.Open(ctx, blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(opened); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, readFailure) {
		t.Fatalf("terminal read error = %v", err)
	}
	_ = opened.Close()

	closeFailure := errors.New("backend close failure")
	client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
		return &awss3.GetObjectOutput{
			Body: &observedReadCloser{Reader: bytes.NewReader(body), closeErr: closeFailure}, ContentLength: aws.Int64(blob.Size),
		}, nil
	}
	opened, err = store.Open(ctx, blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = opened.Close(); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, closeFailure) {
		t.Fatalf("close error = %v", err)
	}
	client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
		return &awss3.GetObjectOutput{
			Body: &observedReadCloser{Reader: bytes.NewReader(body), closeErr: closeFailure}, ContentLength: aws.Int64(blob.Size - 1),
		}, nil
	}
	if _, err = store.Open(ctx, blob, nil); !errors.Is(err, content.ErrCorrupt) ||
		!errors.Is(err, content.ErrUnavailable) || !errors.Is(err, closeFailure) {
		t.Fatalf("metadata and close failure = %v", err)
	}
}

func TestOpenCancellationAndConcurrentCloseUnblockRead(t *testing.T) {
	body := []byte("x")
	blob := testBlob(body)
	for name, cancelContext := range map[string]bool{"cancel": true, "close": false} {
		t.Run(name, func(t *testing.T) {
			client := newFakeClient()
			store, _ := newStore(client, Options{Bucket: "bucket"})
			client.setObject(store.objectKey(blob.SHA256), body)
			blocker := newBlockingReadCloser()
			client.get = func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error) {
				return &awss3.GetObjectOutput{Body: blocker, ContentLength: aws.Int64(1)}, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			opened, err := store.Open(ctx, blob, nil)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := opened.Read(make([]byte, 1)); result <- err }()
			select {
			case <-blocker.started:
			case <-time.After(time.Second):
				t.Fatal("read did not block")
			}
			if cancelContext {
				cancel()
			} else if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if cancelContext && !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled read = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("read was not unblocked")
			}
			if !blocker.closed.Load() {
				t.Fatal("backend reader was not closed")
			}
			cancel()
			_ = opened.Close()
		})
	}
}

func testBlob(body []byte) content.Blob {
	return content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
}

func assertOpened(t *testing.T, store *Store, blob content.Blob, wanted *content.Range, expected []byte) {
	t.Helper()
	reader, err := store.Open(context.Background(), blob, wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, expected) {
		t.Fatalf("opened = %q, %v, %v", got, readErr, closeErr)
	}
}

func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary directory = %#v, %v", entries, err)
	}
}

type fakeClient struct {
	mu              sync.Mutex
	objects         map[string][]byte
	putErrors       []error
	afterPut        func()
	head            func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error)
	get             func(context.Context, *awss3.GetObjectInput) (*awss3.GetObjectOutput, error)
	putCalls        int
	headCalls       int
	getCalls        int
	lastPut         *awss3.PutObjectInput
	lastHead        *awss3.HeadObjectInput
	lastGet         *awss3.GetObjectInput
	requestChecksum aws.RequestChecksumCalculation
}

func newFakeClient() *fakeClient { return &fakeClient{objects: make(map[string][]byte)} }

func (client *fakeClient) PutObject(
	ctx context.Context,
	input *awss3.PutObjectInput,
	optionFunctions ...func(*awss3.Options),
) (*awss3.PutObjectOutput, error) {
	var options awss3.Options
	for _, apply := range optionFunctions {
		apply(&options)
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	client.mu.Lock()
	client.putCalls++
	client.lastPut = input
	client.requestChecksum = options.RequestChecksumCalculation
	var injected error
	if len(client.putErrors) != 0 {
		injected, client.putErrors = client.putErrors[0], client.putErrors[1:]
	}
	after := client.afterPut
	client.afterPut = nil
	if injected == nil {
		key := aws.ToString(input.Key)
		if _, exists := client.objects[key]; exists {
			injected = &smithy.GenericAPIError{Code: "PreconditionFailed"}
		} else {
			client.objects[key] = append([]byte(nil), body...)
		}
	}
	client.mu.Unlock()
	if after != nil {
		after()
	}
	if injected != nil {
		return nil, injected
	}
	return &awss3.PutObjectOutput{}, nil
}

func (client *fakeClient) HeadObject(
	ctx context.Context,
	input *awss3.HeadObjectInput,
	_ ...func(*awss3.Options),
) (*awss3.HeadObjectOutput, error) {
	client.mu.Lock()
	client.headCalls++
	client.lastHead = input
	hook := client.head
	client.mu.Unlock()
	if hook != nil {
		return hook(ctx, input)
	}
	client.mu.Lock()
	body, found := client.objects[aws.ToString(input.Key)]
	client.mu.Unlock()
	if !found {
		return nil, &smithy.GenericAPIError{Code: "NoSuchKey"}
	}
	return &awss3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(body)))}, nil
}

func (client *fakeClient) GetObject(
	ctx context.Context,
	input *awss3.GetObjectInput,
	_ ...func(*awss3.Options),
) (*awss3.GetObjectOutput, error) {
	client.mu.Lock()
	client.getCalls++
	client.lastGet = input
	hook := client.get
	client.mu.Unlock()
	if hook != nil {
		return hook(ctx, input)
	}
	client.mu.Lock()
	body, found := client.objects[aws.ToString(input.Key)]
	body = append([]byte(nil), body...)
	client.mu.Unlock()
	if !found {
		return nil, &smithy.GenericAPIError{Code: "NoSuchKey"}
	}
	output := &awss3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body)), ContentLength: aws.Int64(int64(len(body)))}
	if input.Range != nil {
		var start, end int64
		if _, err := fmt.Sscanf(aws.ToString(input.Range), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= int64(len(body)) {
			return nil, &smithy.GenericAPIError{Code: "InvalidRange"}
		}
		selected := body[start : end+1]
		output.Body = io.NopCloser(bytes.NewReader(selected))
		output.ContentLength = aws.Int64(int64(len(selected)))
		output.ContentRange = aws.String(fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
	}
	return output, nil
}

func (client *fakeClient) setObject(key string, body []byte) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.objects[key] = append([]byte(nil), body...)
}

func (client *fakeClient) callCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.putCalls + client.headCalls + client.getCalls
}

func (client *fakeClient) putCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.putCalls
}

type statusError int

func (err statusError) Error() string       { return fmt.Sprintf("HTTP status %d", err) }
func (err statusError) HTTPStatusCode() int { return int(err) }

type terminalReader struct {
	data []byte
	err  error
	done bool
}

func (reader *terminalReader) Read(buffer []byte) (int, error) {
	if reader.done {
		return 0, io.EOF
	}
	reader.done = true
	return copy(buffer, reader.data), reader.err
}

type terminalReadCloser struct{ terminalReader }

func (*terminalReadCloser) Close() error { return nil }

type observedReadCloser struct {
	io.Reader
	closed   atomic.Bool
	closeErr error
}

func (reader *observedReadCloser) Close() error {
	reader.closed.Store(true)
	return reader.closeErr
}

type blockingReadCloser struct {
	started chan struct{}
	closed  atomic.Bool
	once    sync.Once
	done    chan struct{}
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{started: make(chan struct{}), done: make(chan struct{})}
}

func (reader *blockingReadCloser) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.done
	return 0, errors.New("backend reader closed")
}

func (reader *blockingReadCloser) Close() error {
	if reader.closed.CompareAndSwap(false, true) {
		close(reader.done)
	}
	return nil
}

type errorWriter struct{ err error }

func (writer errorWriter) Write([]byte) (int, error) { return 0, writer.err }

type shortWriter struct{}

func (shortWriter) Write(buffer []byte) (int, error) { return len(buffer) - 1, nil }

type invalidCountReader struct{ count int }

func (reader *invalidCountReader) Read([]byte) (int, error) { return reader.count, nil }

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type oneByteReader struct{ data []byte }

func (reader *oneByteReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	buffer[0] = reader.data[0]
	reader.data = reader.data[1:]
	return 1, nil
}
