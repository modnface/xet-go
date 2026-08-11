package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

type memoryS3 struct {
	mu      sync.Mutex
	objects map[string][]byte

	putError  error
	putErrors []error
	putCalls  int
	headError error
	getError  error
	listError error

	headOutput *awss3.HeadObjectOutput
	getOutput  *awss3.GetObjectOutput
	listOutput *awss3.ListObjectsV2Output
	headSet    bool
	getSet     bool
	listSet    bool
	lastPut    *awss3.PutObjectInput
	lastHead   *awss3.HeadObjectInput
	lastGet    *awss3.GetObjectInput
	lastList   *awss3.ListObjectsV2Input
}

func newMemoryS3() *memoryS3 { return &memoryS3{objects: make(map[string][]byte)} }

func (s *memoryS3) PutObject(
	ctx context.Context,
	input *awss3.PutObjectInput,
	_ ...func(*awss3.Options),
) (*awss3.PutObjectOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPut = input
	s.putCalls++
	if s.putError != nil {
		return nil, s.putError
	}
	if input.Bucket == nil || input.Key == nil || input.ContentLength == nil ||
		input.IfNoneMatch == nil || *input.IfNoneMatch != "*" {
		return nil, errors.New("fake S3: invalid conditional put")
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != *input.ContentLength {
		return nil, errors.New("fake S3: content length mismatch")
	}
	if len(s.putErrors) != 0 {
		err := s.putErrors[0]
		s.putErrors = s.putErrors[1:]
		if err != nil {
			return nil, err
		}
	}
	if _, exists := s.objects[*input.Key]; exists {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "exists"}
	}
	s.objects[*input.Key] = append([]byte(nil), body...)
	return &awss3.PutObjectOutput{}, nil
}

func (s *memoryS3) HeadObject(
	ctx context.Context,
	input *awss3.HeadObjectInput,
	_ ...func(*awss3.Options),
) (*awss3.HeadObjectOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHead = input
	if s.headError != nil {
		return nil, s.headError
	}
	if s.headSet {
		return s.headOutput, nil
	}
	body, exists := s.objects[aws.ToString(input.Key)]
	if !exists {
		return nil, &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing"}
	}
	return &awss3.HeadObjectOutput{ContentLength: aws.Int64(int64(len(body)))}, nil
}

func (s *memoryS3) GetObject(
	ctx context.Context,
	input *awss3.GetObjectInput,
	_ ...func(*awss3.Options),
) (*awss3.GetObjectOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGet = input
	if s.getError != nil {
		return nil, s.getError
	}
	if s.getSet {
		return s.getOutput, nil
	}
	body, exists := s.objects[aws.ToString(input.Key)]
	if !exists {
		return nil, &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing"}
	}
	selected := body
	if input.Range != nil {
		start, end, err := parseRange(*input.Range)
		if err != nil || start < 0 || end < start || end >= int64(len(body)) {
			return nil, &smithy.GenericAPIError{Code: "InvalidRange", Message: "invalid"}
		}
		selected = body[start : end+1]
	}
	copy := append([]byte(nil), selected...)
	output := &awss3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(copy)), ContentLength: aws.Int64(int64(len(copy))),
	}
	if input.Range != nil {
		start, end, _ := parseRange(*input.Range)
		output.ContentRange = aws.String(fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
	}
	return output, nil
}

func (s *memoryS3) ListObjectsV2(
	ctx context.Context,
	input *awss3.ListObjectsV2Input,
	_ ...func(*awss3.Options),
) (*awss3.ListObjectsV2Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastList = input
	if s.listError != nil {
		return nil, s.listError
	}
	if s.listSet {
		return s.listOutput, nil
	}
	var keys []string
	for key := range s.objects {
		if strings.HasPrefix(key, aws.ToString(input.Prefix)) && key > aws.ToString(input.StartAfter) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	start := 0
	if input.ContinuationToken != nil {
		var err error
		start, err = strconv.Atoi(*input.ContinuationToken)
		if err != nil || start < 0 || start > len(keys) {
			return nil, errors.New("fake S3: bad continuation")
		}
	}
	maximum := int(aws.ToInt32(input.MaxKeys))
	end := min(start+maximum, len(keys))
	output := &awss3.ListObjectsV2Output{
		Contents: make([]types.Object, 0, end-start), IsTruncated: aws.Bool(end != len(keys)),
	}
	for _, key := range keys[start:end] {
		output.Contents = append(output.Contents, types.Object{
			Key: aws.String(key), Size: aws.Int64(int64(len(s.objects[key]))),
		})
	}
	if end != len(keys) {
		output.NextContinuationToken = aws.String(strconv.Itoa(end))
	}
	return output, nil
}

type fakePresigner struct {
	request *v4.PresignedHTTPRequest
	set     bool
	err     error
	input   *awss3.GetObjectInput
	expires time.Duration
}

func (p *fakePresigner) PresignGetObject(
	ctx context.Context,
	input *awss3.GetObjectInput,
	options ...func(*awss3.PresignOptions),
) (*v4.PresignedHTTPRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.input = input
	configured := awss3.PresignOptions{}
	for _, option := range options {
		option(&configured)
	}
	p.expires = configured.Expires
	if p.err != nil {
		return nil, p.err
	}
	if p.set {
		return p.request, nil
	}
	return &v4.PresignedHTTPRequest{
		URL: fmt.Sprintf("https://storage.example/object?X-Amz-Date=20260810T110000Z&X-Amz-Expires=%d&X-Amz-Signature=redacted",
			int64(configured.Expires/time.Second)), Method: http.MethodGet,
		SignedHeader: http.Header{"Range": {*input.Range}},
	}, nil
}

func newTestStore(t *testing.T, client *memoryS3) (*Store, *fakePresigner) {
	t.Helper()
	presigner := &fakePresigner{}
	store, err := newStore(client, presigner, Options{
		Bucket: "bucket", Prefix: "tenant/cas", TempDirectory: t.TempDir(), PresignExpiry: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, presigner
}

func testKey(kind casserver.BlobKind, value string) casserver.BlobKey {
	return casserver.BlobKey{Kind: kind, Hash: xethash.Chunk([]byte(value))}
}

func TestConstructionAndObjectKeys(t *testing.T) {
	client := newMemoryS3()
	presigner := &fakePresigner{}
	valid, err := newStore(client, presigner, Options{Bucket: "bucket"})
	if err != nil {
		t.Fatal(err)
	}
	if valid.presignTTL != defaultPresignTTL {
		t.Fatalf("default presign expiry = %s", valid.presignTTL)
	}
	key := testKey(casserver.BlobXorb, "key")
	got, err := valid.objectKey(key)
	wantHash := key.Hash.String()
	want := "blobs-v1/xorb/" + wantHash[:2] + "/" + wantHash[2:4] + "/" + wantHash
	if err != nil || got != want {
		t.Fatalf("object key = %q, %v; want %q", got, err, want)
	}
	parsed, err := valid.parseObjectKey(casserver.BlobXorb, got)
	if err != nil || parsed != key {
		t.Fatalf("parsed key = %#v, %v", parsed, err)
	}

	invalidOptions := []Options{
		{}, {Bucket: " "}, {Bucket: " bucket"}, {Bucket: "bucket\x00"},
		{Bucket: "bucket", Prefix: "/cas"}, {Bucket: "bucket", Prefix: "cas/"},
		{Bucket: "bucket", Prefix: "cas//x"}, {Bucket: "bucket", Prefix: "cas/../x"},
		{Bucket: "bucket", Prefix: "cas\\x"},
		{Bucket: "bucket", Prefix: strings.Repeat("x", 513)},
		{Bucket: "bucket", PresignExpiry: -time.Second},
		{Bucket: "bucket", PresignExpiry: 1500 * time.Millisecond},
		{Bucket: "bucket", PresignExpiry: maximumPresignTTL + time.Second},
		{Bucket: "bucket", TempDirectory: t.Name()},
	}
	for _, options := range invalidOptions {
		if _, err := newStore(client, presigner, options); err == nil {
			t.Errorf("newStore(%#v) succeeded", options)
		}
	}
	if _, err := newStore(nil, presigner, Options{Bucket: "bucket"}); err == nil {
		t.Fatal("nil client succeeded")
	}
	if _, err := newStore(client, nil, Options{Bucket: "bucket"}); err == nil {
		t.Fatal("nil presigner succeeded")
	}
	if _, err := New(nil, Options{Bucket: "bucket"}); err == nil {
		t.Fatal("public nil client succeeded")
	}
	sdkClient := awss3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("access", "secret", ""),
	})
	if _, err := New(sdkClient, Options{Bucket: "bucket"}); err != nil {
		t.Fatalf("public constructor = %v", err)
	}
	for _, key := range []casserver.BlobKey{
		{Kind: casserver.BlobXorb},
		{Kind: "ordinary", Hash: testKey(casserver.BlobXorb, "valid").Hash},
	} {
		if _, err := valid.objectKey(key); !errors.Is(err, casserver.ErrInvalid) {
			t.Errorf("invalid key %#v = %v", key, err)
		}
	}
	for _, prefix := range []string{".", "..", "../tenant"} {
		if _, err := normalizePrefix(prefix); err == nil {
			t.Errorf("traversal prefix %q succeeded", prefix)
		}
	}
	for _, malformed := range []string{
		"wrong/" + wantHash, "blobs-v1/xorb/aa/bb/short",
		"blobs-v1/xorb/ff/" + wantHash[2:4] + "/" + wantHash,
		"blobs-v1/xorb/" + wantHash[:2] + "/" + wantHash[2:4] + "/" + strings.ToUpper(wantHash),
		"blobs-v1/xorb/00/00/" + strings.Repeat("0", 64),
	} {
		if _, err := valid.parseObjectKey(casserver.BlobXorb, malformed); !errors.Is(err, casserver.ErrCorrupt) {
			t.Errorf("malformed key %q = %v", malformed, err)
		}
	}
}

func TestInvalidKeysAndCanceledBackendCalls(t *testing.T) {
	client := newMemoryS3()
	store, presigner := newTestStore(t, client)
	invalid := casserver.BlobKey{Kind: "ordinary", Hash: testKey(casserver.BlobXorb, "hash").Hash}
	if _, err := store.PutIfAbsent(context.Background(), invalid, bytes.NewReader(nil), 0); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("invalid put key = %v", err)
	}
	if _, _, err := store.Head(context.Background(), invalid); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("invalid head key = %v", err)
	}
	if _, err := store.Get(context.Background(), invalid, nil); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("invalid get key = %v", err)
	}
	if _, err := store.ListBlobs(context.Background(), invalid.Kind, casserver.PageRequest{}); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("invalid list kind = %v", err)
	}
	if _, err := store.SignRange(context.Background(), invalid, xetcas.HTTPRange{}); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("invalid sign key = %v", err)
	}
	if _, err := store.parseObjectKey(invalid.Kind, "anything"); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("invalid parse kind = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	contextBody := &contextReader{ctx: ctx, reader: strings.NewReader("x")}
	if _, err := contextBody.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled body = %v", err)
	}
	contextResult := &contextReadCloser{ctx: ctx, reader: io.NopCloser(strings.NewReader("x"))}
	if _, err := contextResult.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled result = %v", err)
	}
	presigner.err = context.Canceled
	if _, err := store.SignRange(ctx, testKey(casserver.BlobXorb, "signed"), xetcas.HTTPRange{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled presigner = %v", err)
	}
}

func TestBlobStoreContract(t *testing.T) {
	client := newMemoryS3()
	store, _ := newTestStore(t, client)
	ctx := context.Background()
	key := testKey(casserver.BlobXorb, "contract")
	body := bytes.Repeat([]byte("S3 Xet blob"), 1_000)
	if info, found, err := store.Head(ctx, key); err != nil || found || info.Size != 0 {
		t.Fatalf("missing head = %#v, %v, %v", info, found, err)
	}
	if _, err := store.Get(ctx, key, nil); !errors.Is(err, casserver.ErrNotFound) {
		t.Fatalf("missing get = %v", err)
	}
	if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil || !inserted {
		t.Fatalf("insert = %v, %v", inserted, err)
	}
	if client.lastPut == nil || aws.ToString(client.lastPut.IfNoneMatch) != "*" ||
		aws.ToInt64(client.lastPut.ContentLength) != int64(len(body)) {
		t.Fatalf("conditional put = %#v", client.lastPut)
	}
	if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil || inserted {
		t.Fatalf("idempotent insert = %v, %v", inserted, err)
	}
	conflict := append([]byte(nil), body...)
	conflict[len(conflict)/2] ^= 0xff
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(conflict), int64(len(conflict))); !errors.Is(err, casserver.ErrConflict) {
		t.Fatalf("equal-length conflict = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body[:len(body)-1]), int64(len(body))); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("short insert = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(append(append([]byte(nil), body...), 1)), int64(len(body))); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("long insert = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, key, nil, int64(len(body))); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("nil body = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(nil), -1); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("negative size = %v", err)
	}

	info, found, err := store.Head(ctx, key)
	if err != nil || !found || info.Size != int64(len(body)) {
		t.Fatalf("head = %#v, %v, %v", info, found, err)
	}
	reader, err := store.Get(ctx, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, body) {
		t.Fatalf("full get = %d bytes, %v, %v", len(got), readErr, closeErr)
	}
	wanted := xetcas.HTTPRange{Start: 7, End: uint64(len(body)) - 9}
	reader, err = store.Get(ctx, key, &wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, body[wanted.Start:wanted.End+1]) ||
		client.lastGet == nil || aws.ToString(client.lastGet.Range) != httpRange(wanted) {
		t.Fatalf("range get = %d bytes, %v, input %#v", len(got), err, client.lastGet)
	}
	for _, invalid := range []xetcas.HTTPRange{{Start: 2, End: 1}, {Start: 0, End: uint64(len(body))}} {
		if _, err := store.Get(ctx, key, &invalid); !errors.Is(err, xetcas.ErrRangeNotSatisfiable) {
			t.Fatalf("invalid range %#v = %v", invalid, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.Head(canceled, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled head = %v", err)
	}
	if _, err := store.Get(canceled, key, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled get = %v", err)
	}
	if _, err := store.PutIfAbsent(canceled, key, bytes.NewReader(body), int64(len(body))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put = %v", err)
	}
}

func TestBackendFailuresAndMetadataValidation(t *testing.T) {
	key := testKey(casserver.BlobXorb, "failures")
	backendFailure := errors.New("backend unavailable")
	for name, configure := range map[string]func(*memoryS3){
		"put":  func(client *memoryS3) { client.putError = backendFailure },
		"head": func(client *memoryS3) { client.headError = backendFailure },
		"get":  func(client *memoryS3) { client.getError = backendFailure },
		"list": func(client *memoryS3) { client.listError = backendFailure },
	} {
		t.Run(name, func(t *testing.T) {
			client := newMemoryS3()
			store, _ := newTestStore(t, client)
			configure(client)
			var err error
			switch name {
			case "put":
				_, err = store.PutIfAbsent(context.Background(), key, bytes.NewReader(nil), 0)
			case "head":
				_, _, err = store.Head(context.Background(), key)
			case "get":
				_, err = store.Get(context.Background(), key, nil)
			case "list":
				_, err = store.ListBlobs(context.Background(), key.Kind, casserver.PageRequest{})
			}
			if !errors.Is(err, backendFailure) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	t.Run("conditional conflict object disappears", func(t *testing.T) {
		client := newMemoryS3()
		client.putError = &smithy.GenericAPIError{Code: "PreconditionFailed"}
		store, _ := newTestStore(t, client)
		if _, err := store.PutIfAbsent(context.Background(), key, bytes.NewReader(nil), 0); err == nil {
			t.Fatal("missing conflicted object succeeded")
		}
	})
	t.Run("conditional conflict different size", func(t *testing.T) {
		client := newMemoryS3()
		store, _ := newTestStore(t, client)
		objectKey, _ := store.objectKey(key)
		client.objects[objectKey] = []byte("other")
		if _, err := store.PutIfAbsent(context.Background(), key, bytes.NewReader(nil), 0); !errors.Is(err, casserver.ErrConflict) {
			t.Fatalf("conflict = %v", err)
		}
	})
	t.Run("conditional write races", func(t *testing.T) {
		tracing := &smithy.GenericAPIError{Code: "ConditionalRequestConflict"}
		precondition := &smithy.GenericAPIError{Code: "PreconditionFailed"}
		t.Run("retry succeeds", func(t *testing.T) {
			client := newMemoryS3()
			client.putErrors = []error{tracing, nil}
			store, _ := newTestStore(t, client)
			if inserted, err := store.PutIfAbsent(context.Background(), key, strings.NewReader("winner"), 6); err != nil || !inserted {
				t.Fatalf("retry = %v, %v", inserted, err)
			}
			if client.putCalls != 2 {
				t.Fatalf("put calls = %d", client.putCalls)
			}
		})
		t.Run("retry observes identical winner", func(t *testing.T) {
			client := newMemoryS3()
			store, _ := newTestStore(t, client)
			objectKey, _ := store.objectKey(key)
			client.objects[objectKey] = []byte("winner")
			client.putErrors = []error{tracing, precondition}
			if inserted, err := store.PutIfAbsent(context.Background(), key, strings.NewReader("winner"), 6); err != nil || inserted {
				t.Fatalf("identical winner = %v, %v", inserted, err)
			}
		})
		t.Run("retry observes different winner", func(t *testing.T) {
			client := newMemoryS3()
			store, _ := newTestStore(t, client)
			objectKey, _ := store.objectKey(key)
			client.objects[objectKey] = []byte("losing")
			client.putErrors = []error{tracing, precondition}
			if _, err := store.PutIfAbsent(context.Background(), key, strings.NewReader("winner"), 6); !errors.Is(err, casserver.ErrConflict) {
				t.Fatalf("different winner = %v", err)
			}
		})
		t.Run("bounded exhaustion", func(t *testing.T) {
			client := newMemoryS3()
			client.putErrors = []error{tracing, tracing, tracing, tracing}
			store, _ := newTestStore(t, client)
			if _, err := store.PutIfAbsent(context.Background(), key, strings.NewReader("winner"), 6); !errors.Is(err, tracing) {
				t.Fatalf("exhausted race = %v", err)
			}
			if client.putCalls != conditionalRetries+1 {
				t.Fatalf("put calls = %d", client.putCalls)
			}
		})
		t.Run("cancellation during retry", func(t *testing.T) {
			client := newMemoryS3()
			client.putError = tracing
			store, _ := newTestStore(t, client)
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			if _, err := store.PutIfAbsent(ctx, key, strings.NewReader("winner"), 6); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("canceled race = %v", err)
			}
		})
	})
	t.Run("spool failures", func(t *testing.T) {
		client := newMemoryS3()
		store, _ := newTestStore(t, client)
		store.tempDirectory = t.Name() + "/missing"
		if _, err := store.PutIfAbsent(context.Background(), key, bytes.NewReader(nil), 0); err == nil {
			t.Fatal("missing spool directory succeeded")
		}
		store.tempDirectory = t.TempDir()
		readFailure := errors.New("source read failure")
		if _, err := store.PutIfAbsent(context.Background(), key, errorReader{err: readFailure}, 1); !errors.Is(err, readFailure) {
			t.Fatalf("source failure = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if _, err := store.PutIfAbsent(ctx, key, cancelEOFReader{cancel: cancel}, 0); !errors.Is(err, context.Canceled) {
			t.Fatalf("post-spool cancellation = %v", err)
		}
	})
	t.Run("invalid head outputs", func(t *testing.T) {
		for _, output := range []*awss3.HeadObjectOutput{nil, {}, {ContentLength: aws.Int64(-1)}} {
			client := newMemoryS3()
			client.headOutput = output
			client.headSet = true
			store, _ := newTestStore(t, client)
			if _, _, err := store.Head(context.Background(), key); !errors.Is(err, casserver.ErrCorrupt) {
				t.Errorf("head output %#v = %v", output, err)
			}
		}
	})
	t.Run("invalid get outputs close bodies", func(t *testing.T) {
		closed := false
		for _, output := range []*awss3.GetObjectOutput{
			nil,
			{},
			{Body: closeRecorder{Reader: strings.NewReader("x"), closed: &closed}},
			{Body: closeRecorder{Reader: strings.NewReader("x"), closed: &closed}, ContentLength: aws.Int64(-1)},
		} {
			client := newMemoryS3()
			client.getOutput = output
			client.getSet = true
			store, _ := newTestStore(t, client)
			if _, err := store.Get(context.Background(), key, nil); !errors.Is(err, casserver.ErrCorrupt) {
				t.Errorf("get output %#v = %v", output, err)
			}
		}
		if !closed {
			t.Fatal("invalid response body was not closed")
		}
	})
	t.Run("range response length", func(t *testing.T) {
		client := newMemoryS3()
		store, _ := newTestStore(t, client)
		objectKey, _ := store.objectKey(key)
		client.objects[objectKey] = []byte("012345")
		for _, output := range []*awss3.GetObjectOutput{
			{Body: io.NopCloser(strings.NewReader("0")), ContentLength: aws.Int64(1), ContentRange: aws.String("bytes 0-1/6")},
			{Body: io.NopCloser(strings.NewReader("01")), ContentLength: aws.Int64(2)},
			{Body: io.NopCloser(strings.NewReader("01")), ContentLength: aws.Int64(2), ContentRange: aws.String("bytes 1-2/6")},
		} {
			client.getOutput = output
			client.getSet = true
			if _, err := store.Get(context.Background(), key, &xetcas.HTTPRange{Start: 0, End: 1}); !errors.Is(err, casserver.ErrCorrupt) {
				t.Errorf("invalid range metadata %#v = %v", output, err)
			}
		}
	})
	t.Run("typed statuses", func(t *testing.T) {
		for _, code := range []string{"NoSuchKey", "NotFound"} {
			client := newMemoryS3()
			client.headError = &smithy.GenericAPIError{Code: code}
			store, _ := newTestStore(t, client)
			if _, found, err := store.Head(context.Background(), key); err != nil || found {
				t.Errorf("%s = %v, %v", code, found, err)
			}
		}
		client := newMemoryS3()
		client.headError = &smithy.GenericAPIError{Code: "NoSuchBucket"}
		store, _ := newTestStore(t, client)
		if _, _, err := store.Head(context.Background(), key); err == nil {
			t.Fatal("missing bucket was treated as a missing object")
		}
		client = newMemoryS3()
		client.getError = &smithy.GenericAPIError{Code: "InvalidRange"}
		store, _ = newTestStore(t, client)
		objectKey, _ := store.objectKey(key)
		client.objects[objectKey] = []byte("x")
		if _, err := store.Get(context.Background(), key, &xetcas.HTTPRange{Start: 0, End: 0}); !errors.Is(err, xetcas.ErrRangeNotSatisfiable) {
			t.Fatalf("invalid range backend = %v", err)
		}
	})
}

func TestListBlobsPaginationAndValidation(t *testing.T) {
	client := newMemoryS3()
	store, _ := newTestStore(t, client)
	ctx := context.Background()
	keys := []casserver.BlobKey{
		testKey(casserver.BlobXorb, "three"), testKey(casserver.BlobXorb, "one"),
		testKey(casserver.BlobXorb, "four"), testKey(casserver.BlobXorb, "two"),
	}
	for i, key := range keys {
		body := bytes.Repeat([]byte{byte(i + 1)}, i+1)
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
	}
	var listed []casserver.BlobEntry
	cursor := ""
	for {
		page, err := store.ListBlobs(ctx, casserver.BlobXorb, casserver.PageRequest{Cursor: cursor, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 2 || aws.ToInt32(client.lastList.MaxKeys) > 2 {
			t.Fatalf("unbounded page = %d items, MaxKeys %d", len(page.Items), aws.ToInt32(client.lastList.MaxKeys))
		}
		listed = append(listed, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(listed) != len(keys) {
		t.Fatalf("listed %d keys, want %d", len(listed), len(keys))
	}
	if !sort.SliceIsSorted(listed, func(i, j int) bool {
		return listed[i].Key.Hash.String() < listed[j].Key.Hash.String()
	}) {
		t.Fatalf("unordered listing: %#v", listed)
	}
	first, err := store.ListBlobs(ctx, casserver.BlobXorb, casserver.PageRequest{Limit: 1})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first page = %#v, %v", first, err)
	}
	if _, err := store.ListBlobs(ctx, casserver.BlobShard, casserver.PageRequest{Cursor: first.NextCursor}); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("cross-kind cursor = %v", err)
	}
	for _, request := range []casserver.PageRequest{{Limit: -1}, {Limit: casserver.MaxPageSize + 1}, {Cursor: "garbage"}} {
		if _, err := store.ListBlobs(ctx, casserver.BlobXorb, request); !errors.Is(err, casserver.ErrInvalid) {
			t.Errorf("request %#v = %v", request, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ListBlobs(canceled, casserver.BlobXorb, casserver.PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list = %v", err)
	}

	t.Run("malformed metadata", func(t *testing.T) {
		validKey, _ := store.objectKey(keys[0])
		cases := []*awss3.ListObjectsV2Output{
			nil,
			{Contents: []types.Object{{Key: nil, Size: aws.Int64(1)}}},
			{Contents: []types.Object{{Key: aws.String(validKey), Size: nil}}},
			{Contents: []types.Object{{Key: aws.String(validKey), Size: aws.Int64(-1)}}},
			{Contents: []types.Object{{Key: aws.String("tenant/cas/blobs-v1/xorb/bad"), Size: aws.Int64(1)}}},
			{Contents: []types.Object{
				{Key: aws.String(validKey), Size: aws.Int64(1)},
				{Key: aws.String(validKey), Size: aws.Int64(1)},
			}},
			{IsTruncated: aws.Bool(true)},
			{Contents: []types.Object{{Key: aws.String(validKey), Size: aws.Int64(1)}}, IsTruncated: aws.Bool(true)},
			{IsTruncated: aws.Bool(false), NextContinuationToken: aws.String("unexpected")},
		}
		for i, output := range cases {
			client.listOutput = output
			client.listSet = true
			if _, err := store.ListBlobs(ctx, casserver.BlobXorb, casserver.PageRequest{Limit: 1}); !errors.Is(err, casserver.ErrCorrupt) {
				t.Errorf("case %d = %v", i, err)
			}
		}
		client.listOutput = &awss3.ListObjectsV2Output{
			Contents: []types.Object{
				{Key: aws.String(validKey), Size: aws.Int64(1)},
				{Key: aws.String(validKey + "x"), Size: aws.Int64(1)},
			},
		}
		client.listSet = true
		if _, err := store.ListBlobs(ctx, casserver.BlobXorb, casserver.PageRequest{Limit: 1}); !errors.Is(err, casserver.ErrCorrupt) {
			t.Fatalf("oversized page = %v", err)
		}
	})
}

func TestSignRange(t *testing.T) {
	client := newMemoryS3()
	store, presigner := newTestStore(t, client)
	fixedExpiry := time.Date(2026, 8, 10, 11, 2, 0, 0, time.UTC)
	key := testKey(casserver.BlobXorb, "signed")
	wanted := xetcas.HTTPRange{Start: 10, End: 99}
	signed, err := store.SignRange(context.Background(), key, wanted)
	if err != nil {
		t.Fatal(err)
	}
	if signed.URL == "" || !signed.ExpiresAt.Equal(fixedExpiry) ||
		presigner.expires != store.presignTTL || aws.ToString(presigner.input.Range) != "bytes=10-99" {
		t.Fatalf("signed = %#v, expires %s, input %#v", signed, presigner.expires, presigner.input)
	}
	if _, err := store.SignRange(context.Background(), key, xetcas.HTTPRange{Start: 2, End: 1}); !errors.Is(err, xetcas.ErrRangeNotSatisfiable) {
		t.Fatalf("invalid range = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.SignRange(canceled, key, wanted); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sign = %v", err)
	}

	backendFailure := errors.New("signer unavailable")
	presigner.err = backendFailure
	if _, err := store.SignRange(context.Background(), key, wanted); !errors.Is(err, backendFailure) {
		t.Fatalf("signer error = %v", err)
	}
	presigner.err = nil
	invalid := []*v4.PresignedHTTPRequest{
		nil,
		{URL: "relative", Method: http.MethodGet, SignedHeader: http.Header{"Range": {"bytes=10-99"}}},
		{URL: "ftp://storage.example/object", Method: http.MethodGet, SignedHeader: http.Header{"Range": {"bytes=10-99"}}},
		{URL: "https://storage.example/object", Method: http.MethodPut, SignedHeader: http.Header{"Range": {"bytes=10-99"}}},
		{URL: "https://storage.example/object", Method: http.MethodGet},
		{URL: "https://storage.example/object", Method: http.MethodGet, SignedHeader: http.Header{"Range": {"bytes=0-99"}}},
	}
	for i, request := range invalid {
		presigner.request = request
		presigner.set = true
		if _, err := store.SignRange(context.Background(), key, wanted); err == nil {
			t.Errorf("invalid request %d succeeded", i)
		}
	}
	presigner.request = &v4.PresignedHTTPRequest{
		URL:    "https://storage.example/object?X-Amz-Date=20260810T110000Z&X-Amz-Expires=60",
		Method: http.MethodGet, SignedHeader: http.Header{"Range": {"bytes=10-99"}},
	}
	if _, err := store.SignRange(context.Background(), key, wanted); err == nil {
		t.Fatal("unexpected signer expiry succeeded")
	}
}

func TestAWSSDKPresignerBindsExactRange(t *testing.T) {
	sdkClient := awss3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("access", "secret", ""),
	})
	store, err := New(sdkClient, Options{Bucket: "xet-bucket", PresignExpiry: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	wanted := xetcas.HTTPRange{Start: 1024, End: 4095}
	signed, err := store.SignRange(context.Background(), testKey(casserver.BlobXorb, "real signer"), wanted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed.URL, "X-Amz-SignedHeaders=host%3Brange") ||
		!strings.Contains(signed.URL, "X-Amz-Expires=90") {
		t.Fatal("presigned URL does not bind the requested range and expiry")
	}
}

type closeRecorder struct {
	io.Reader
	closed *bool
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type cancelEOFReader struct{ cancel context.CancelFunc }

func (r cancelEOFReader) Read([]byte) (int, error) {
	r.cancel()
	return 0, io.EOF
}

func (r closeRecorder) Close() error {
	*r.closed = true
	return nil
}

func parseRange(value string) (int64, int64, error) {
	if !strings.HasPrefix(value, "bytes=") {
		return 0, 0, errors.New("missing bytes prefix")
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid range")
	}
	start, startErr := strconv.ParseInt(parts[0], 10, 64)
	end, endErr := strconv.ParseInt(parts[1], 10, 64)
	return start, end, errors.Join(startErr, endErr)
}

func TestErrorClassificationAndHelpers(t *testing.T) {
	var _ error = statusError(0)
	var _ interface{ HTTPStatusCode() int } = statusError(0)
	for _, test := range []struct {
		name string
		err  error
		call func(error) bool
	}{
		{"precondition API", &smithy.GenericAPIError{Code: "PreconditionFailed"}, isPreconditionFailed},
		{"precondition status", statusError(412), isPreconditionFailed},
		{"conditional API", &smithy.GenericAPIError{Code: "ConditionalRequestConflict"}, isConditionalRequestConflict},
		{"conditional status", statusError(409), isConditionalRequestConflict},
		{"missing status", statusError(404), isMissing},
		{"range status", statusError(416), isRangeInvalid},
		{"other", errors.New("PreconditionFailed text is not a type"), isPreconditionFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := test.call(test.err)
			if got != (test.name != "other") {
				t.Fatalf("classification = %v", got)
			}
		})
	}
	if _, err := decodeCursor(encodeCursor(1, testKey(casserver.BlobXorb, "cursor").Hash), 2); !errors.Is(err, casserver.ErrInvalid) {
		t.Fatalf("cursor kind = %v", err)
	}
	if validSignedURL(":bad") || validSignedURL("https:///missing-host") || !validSignedURL("http://storage.example/x") {
		t.Fatal("signed URL validation mismatch")
	}
	if hasHTTPStatus(statusError(500), 404) {
		t.Fatal("nonmatching HTTP status classified")
	}
	if isMissing(typedStatusError{code: "NoSuchBucket", status: 404}) {
		t.Fatal("typed NoSuchBucket was classified by status fallback")
	}
	validExpiry := "https://storage.example/x?X-Amz-Date=20260810T110000Z&X-Amz-Expires=120"
	if got, err := signedURLExpiry(validExpiry, 2*time.Minute); err != nil ||
		!got.Equal(time.Date(2026, 8, 10, 11, 2, 0, 0, time.UTC)) {
		t.Fatalf("signed expiry = %s, %v", got, err)
	}
	for _, invalid := range []string{
		"%", "https://storage.example/x", validExpiry + "&X-Amz-Date=20260810T110000Z",
		"https://storage.example/x?X-Amz-Date=bad&X-Amz-Expires=120",
		"https://storage.example/x?X-Amz-Date=20260810T110000Z&X-Amz-Expires=0",
		"https://storage.example/x?X-Amz-Date=20260810T110000Z&X-Amz-Expires=0120",
	} {
		if _, err := signedURLExpiry(invalid, 2*time.Minute); err == nil {
			t.Errorf("invalid signed expiry succeeded")
		}
	}
	if equal, err := equalReaders(context.Background(), strings.NewReader("x"), strings.NewReader(""), 1); err == nil || equal {
		t.Fatalf("short reader comparison = %v, %v", equal, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if equal, err := equalReaders(canceled, strings.NewReader("x"), strings.NewReader("x"), 1); !errors.Is(err, context.Canceled) || equal {
		t.Fatalf("canceled comparison = %v, %v", equal, err)
	}
	readFailure := errors.New("trailing read failure")
	if equal, err := equalReaders(context.Background(), errorReader{err: readFailure}, strings.NewReader(""), 0); !errors.Is(err, readFailure) || equal {
		t.Fatalf("trailing comparison = %v, %v", equal, err)
	}
}

type statusError int

func (e statusError) Error() string       { return fmt.Sprintf("HTTP %d", e) }
func (e statusError) HTTPStatusCode() int { return int(e) }

type typedStatusError struct {
	code   string
	status int
}

func (e typedStatusError) Error() string                 { return e.code }
func (e typedStatusError) ErrorCode() string             { return e.code }
func (e typedStatusError) ErrorMessage() string          { return e.code }
func (e typedStatusError) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }
func (e typedStatusError) HTTPStatusCode() int           { return e.status }
