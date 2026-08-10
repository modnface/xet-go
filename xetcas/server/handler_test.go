package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xet "github.com/jmwoliver/xet-go"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func TestHTTPHandlerGoClientEndToEnd(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	var storageRequests atomic.Int32
	storageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageRequests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get(xetcas.SessionIDHeader) != "" {
			t.Errorf("CAS credentials reached storage: %q %q", r.Header.Get("Authorization"), r.Header.Get(xetcas.SessionIDHeader))
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 || parts[0] != string(BlobXorb) {
			http.NotFound(w, r)
			return
		}
		hash, err := xethash.Parse(parts[1])
		if err != nil {
			http.Error(w, "bad hash", http.StatusBadRequest)
			return
		}
		ranges, err := parseRanges(r.Header.Get("Range"))
		if err != nil || len(ranges) != 1 {
			http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		wanted := xetcas.HTTPRange{Start: ranges[0].Start, End: ranges[0].End - 1}
		reader, err := store.Get(r.Context(), BlobKey{Kind: BlobXorb, Hash: hash}, &wanted)
		if err != nil {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			_ = reader.Close()
			t.Error(err)
			return
		}
		if err := reader.Close(); err != nil {
			t.Error(err)
			return
		}
		info, _, _ := store.Head(r.Context(), BlobKey{Kind: BlobXorb, Hash: hash})
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", wanted.Start, wanted.End, info.Size))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body)
	}))
	defer storageServer.Close()

	service, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(_ context.Context, key BlobKey, _ xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange(storageServer.URL + "/" + string(key.Kind) + "/" + key.Hash.String() + "?signed=1"), nil
		}),
		Authorizer:         StaticTokenAuthorizer{Token: "cas-secret", Namespace: "e2e"},
		DedupProtectionKey: xethash.Chunk([]byte("HTTP handler dedup key")),
		Now:                func() time.Time { return time.Unix(2_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	casServer := httptest.NewServer(service.Handler())
	defer casServer.Close()
	endpoint, err := url.Parse(casServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := xetcas.New(xetcas.NewStaticAccess(endpoint, "cas-secret"), xetcas.Options{
		SessionID: "must-not-reach-storage",
		Retry:     xetcas.RetryPolicy{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := xet.NewClient(transport, xet.Options{
		Compression: xorb.None, CompressionSet: true, GlobalDedup: true,
		UploadConcurrency: 2, DownloadConcurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("HTTP CAS end-to-end payload\n"), 30_000)
	upload, err := engine.UploadBytes(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if !upload.Report.ShardUploaded || upload.File.SHA256 == nil {
		t.Fatalf("upload = %#v", upload)
	}
	var full bytes.Buffer
	if _, err := engine.Download(ctx, upload.File, &full); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full.Bytes(), data) {
		t.Fatal("full HTTP reconstruction differs")
	}
	wanted := xetcas.FileRange{Start: 123, End: 45_678}
	var partial bytes.Buffer
	if _, err := engine.DownloadRange(ctx, upload.File.Hash, wanted, &partial); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(partial.Bytes(), data[wanted.Start:wanted.End]) {
		t.Fatal("range HTTP reconstruction differs")
	}
	if storageRequests.Load() == 0 {
		t.Fatal("reconstruction did not use signed storage")
	}

	size, found, err := transport.FileSize(ctx, upload.File.Hash)
	if err != nil || !found || size != uint64(len(data)) {
		t.Fatalf("file HEAD = %d, %v, %v", size, found, err)
	}
	fileRecord, _, _ := store.GetFile(ctx, "e2e", upload.File.Hash)
	xorbRecord, _, _ := store.GetXorb(ctx, fileRecord.File.File.Terms[0].XorbHash)
	exists, err := transport.XorbExists(ctx, xetcas.DefaultXorbPrefix, xorbRecord.Layout.Hash)
	if err != nil || !exists {
		t.Fatalf("xorb HEAD = %v, %v", exists, err)
	}
	dedup, found, err := transport.QueryGlobalDedup(ctx, xetcas.DefaultDedupPrefix, xorbRecord.Layout.Chunks[0].Hash)
	if err != nil || !found || len(dedup) == 0 {
		t.Fatalf("dedup GET = %d bytes, %v, %v", len(dedup), found, err)
	}
	batch, err := transport.BatchQueryReconstruction(ctx, []xethash.Hash{upload.File.Hash})
	if err != nil || len(batch) != 1 {
		t.Fatalf("batch reconstruction = %#v, %v", batch, err)
	}
	chunkHashes, err := transport.QueryFileChunkHashes(ctx, upload.File.Hash, []xetcas.FileRange{{Start: 10, End: 100}})
	if err != nil || chunkHashes.FileSize != uint64(len(data)) || len(chunkHashes.Windows) == 0 {
		t.Fatalf("file chunk hashes = %#v, %v", chunkHashes, err)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		casServer.URL+"/v1/reconstructions/"+upload.File.Hash.String(), nil)
	request.Header.Set("Authorization", "Bearer cas-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var v1 xetcas.ReconstructionV1
	if err := json.NewDecoder(response.Body).Decode(&v1); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(v1.Terms) == 0 {
		t.Fatalf("v1 response = %d %#v", response.StatusCode, v1)
	}

	xorbInfo, err := shard.XorbFromIngested(&xorbRecord.Layout)
	if err != nil {
		t.Fatal(err)
	}
	uploadShard, err := shard.EncodeUpload(shard.Shard{Files: []shard.File{fileRecord.File.File}, Xorbs: []shard.Xorb{xorbInfo}})
	if err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequestWithContext(ctx, http.MethodPost, casServer.URL+"/v1/shards", bytes.NewReader(uploadShard))
	request.Header.Set("Authorization", "Bearer cas-secret")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("v1 shard status = %d", response.StatusCode)
	}
}

func TestHTTPHandlerRejectsMalformedAuthorityAndRanges(t *testing.T) {
	store := NewMemoryStore()
	service, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
		}),
		Authorizer: StaticTokenAuthorizer{Token: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.Handler())
	defer server.Close()
	hash := xethash.Chunk([]byte("missing")).String()
	for name, header := range map[string]struct {
		name   string
		value  string
		status int
	}{
		"malformed auth": {"Authorization", "Basic abc", http.StatusUnauthorized},
		"wrong auth":     {"Authorization", "Bearer wrong", http.StatusForbidden},
		"multi range":    {"Range", "bytes=0-1,3-4", http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, server.URL+"/v2/reconstructions/"+hash, nil)
			request.Header.Set("Authorization", "Bearer secret")
			request.Header.Set(header.name, header.value)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != header.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, header.status)
			}
		})
	}
}
