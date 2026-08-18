package hfcompat

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Verify the pinned client's Git blob identity.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestPreuploadClassifiesAndDetectsExistingContent(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	fixture.handler.large = 100

	body := marshalJSON(t, preuploadRequestDTO{Files: []preuploadFileRequestDTO{
		{Path: "config.json", Size: int64(len(fixture.ordinaryBody)), Sample: fixture.ordinaryBody},
		{Path: "weights/model.bin", Size: int64(len(fixture.xetBody)), Sample: fixture.xetBody[:maxUploadSample]},
		{Path: "new.bin", Size: 101, Sample: []byte("not uploaded")},
	}})
	response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var got preuploadResponseDTO
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 3 {
		t.Fatalf("files = %#v", got.Files)
	}
	ordinaryDigest := sha1.New() //nolint:gosec // Verify the pinned client's Git blob identity.
	_, _ = fmt.Fprintf(ordinaryDigest, "blob %d\x00", len(fixture.ordinaryBody))
	_, _ = ordinaryDigest.Write(fixture.ordinaryBody)
	wantOrdinaryOID := hex.EncodeToString(ordinaryDigest.Sum(nil))
	wantXetOID := hex.EncodeToString(fixture.cas.sum[:])
	assertPreuploadFile(t, got.Files[0], "config.json", "regular", false, &wantOrdinaryOID)
	assertPreuploadFile(t, got.Files[1], "weights/model.bin", "lfs", false, &wantXetOID)
	assertPreuploadFile(t, got.Files[2], "new.bin", "lfs", false, nil)

	fixture.handler.preuploadMax = 1
	response = requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestPreuploadRejectsInvalidPathAndHash(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	fixture.handler.fileBytes = 10
	for name, test := range map[string]struct {
		file   preuploadFileRequestDTO
		status int
	}{
		"path":          {file: preuploadFileRequestDTO{Path: "../escape", Size: 1}, status: http.StatusBadRequest},
		"negative size": {file: preuploadFileRequestDTO{Path: "valid", Size: -1}, status: http.StatusBadRequest},
		"size limit":    {file: preuploadFileRequestDTO{Path: "valid", Size: 11}, status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			body := marshalJSON(t, preuploadRequestDTO{Files: []preuploadFileRequestDTO{test.file}})
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/main", "Bearer hub-token", bytes.NewReader(body), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
	missingOID := strings.Repeat("f", 40)
	response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/"+missingOID, "Bearer hub-token", bytes.NewReader(marshalJSON(t, preuploadRequestDTO{})), nil)
	if response.Code != http.StatusNotFound || response.Header().Get("X-Error-Code") != "RevisionNotFound" {
		t.Fatalf("missing explicit revision = %d, %#v, %s", response.Code, response.Header(), response.Body.String())
	}
}

func TestPreuploadPreservesStorageFailuresAndMissingContent(t *testing.T) {
	tests := map[string]struct {
		path      string
		size      int64
		configure func(handlerFixture, *Service)
		status    int
		wantOID   bool
	}{
		"Xet resolution failure": {
			path: "weights/model.bin", size: -1, status: http.StatusServiceUnavailable,
			configure: func(fixture handlerFixture, handler *Service) {
				handler.writer = &faultWriter{RepositoryWriter: fixture.bucket, resolveErr: bucket.ErrUnavailable}
			},
		},
		"ordinary open failure": {
			path: "config.json", size: -1, status: http.StatusServiceUnavailable,
			configure: func(fixture handlerFixture, handler *Service) {
				handler.bucket = &faultBucket{BucketService: fixture.bucket, openErr: bucket.ErrUnavailable}
			},
		},
		"ordinary content missing": {
			path: "config.json", size: -1, status: http.StatusOK,
			configure: func(fixture handlerFixture, handler *Service) {
				handler.bucket = &faultBucket{BucketService: fixture.bucket, openErr: content.ErrNotFound}
			},
		},
		"ordinary read failure": {
			path: "config.json", size: -1, status: http.StatusInternalServerError,
			configure: func(fixture handlerFixture, handler *Service) {
				handler.bucket = &faultBucket{BucketService: fixture.bucket, openBody: &trackingBody{err: errors.New("read failure")}}
			},
		},
		"ordinary close failure": {
			path: "config.json", size: -1, status: http.StatusInternalServerError,
			configure: func(fixture handlerFixture, handler *Service) {
				handler.bucket = &faultBucket{BucketService: fixture.bucket, openBody: &trackingBody{
					reader: bytes.NewReader(fixture.ordinaryBody), err: errors.New("close failure"),
				}}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			handler := fixture.handler
			test.configure(fixture, handler)
			size := test.size
			if size < 0 {
				if test.path == "weights/model.bin" {
					size = int64(len(fixture.xetBody))
				} else {
					size = int64(len(fixture.ordinaryBody))
				}
			}
			body := marshalJSON(t, preuploadRequestDTO{Files: []preuploadFileRequestDTO{{Path: test.path, Size: size}}})
			response := requestBody(t, handler, http.MethodPost, "/api/models/owner/model/preupload/main", "Bearer hub-token", bytes.NewReader(body), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			if response.Code == http.StatusOK {
				var decoded preuploadResponseDTO
				if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil || len(decoded.Files) != 1 || (decoded.Files[0].OID != nil) != test.wantOID {
					t.Fatalf("response = %#v, err=%v", decoded, err)
				}
			}
		})
	}
}

func TestWriteBackendFailuresAndCommitCompositionGuards(t *testing.T) {
	t.Run("create backend", func(t *testing.T) {
		fixture := newHandlerFixture(t, 0)
		fixture.handler.writer = &faultWriter{RepositoryWriter: fixture.bucket, createErr: bucket.ErrUnavailable}
		response := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"backend","organization":"owner"}`), nil)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
	})

	tests := map[string]struct {
		target    string
		body      func(handlerFixture) []byte
		configure func(handlerFixture, *Service)
		status    int
	}{
		"missing writer": {
			target: "/api/models/owner/model/commit/main", status: http.StatusNotImplemented,
			configure: func(_ handlerFixture, handler *Service) { handler.writer = nil },
		},
		"missing publisher": {
			target: "/api/models/owner/model/commit/main", status: http.StatusNotImplemented,
			configure: func(_ handlerFixture, handler *Service) { handler.publisher = nil },
		},
		"unsupported query": {
			target: "/api/models/owner/model/commit/main?create_pr=1", status: http.StatusNotImplemented,
		},
		"immutable target": {
			target: "/api/models/owner/model/commit/1111111111111111111111111111111111111111", status: http.StatusBadRequest,
		},
		"parent resolution": {
			target: "/api/models/owner/model/commit/main", status: http.StatusServiceUnavailable,
			configure: func(fixture handlerFixture, handler *Service) {
				handler.bucket = &faultBucket{BucketService: fixture.bucket, resolveErr: bucket.ErrUnavailable}
			},
		},
		"regular publication": {
			target: "/api/models/owner/model/commit/main", status: http.StatusServiceUnavailable,
			body: func(fixture handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "put failure", ParentCommit: fixture.snapshot.OID.String()}),
					commitLine("file", commitFileDTO{Path: "new", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("content"))}),
				)
			},
			configure: func(fixture handlerFixture, handler *Service) {
				handler.writer = &faultWriter{RepositoryWriter: fixture.bucket, putErr: bucket.ErrUnavailable}
			},
		},
		"Xet resolution": {
			target: "/api/models/owner/model/commit/main", status: http.StatusServiceUnavailable,
			body: func(fixture handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "resolve failure", ParentCommit: fixture.snapshot.OID.String()}),
					commitLine("lfsFile", commitLFSFileDTO{Path: "new", Algo: "sha256", OID: hex.EncodeToString(fixture.cas.sum[:]), Size: int64Pointer(int64(len(fixture.xetBody)))}),
				)
			},
			configure: func(fixture handlerFixture, handler *Service) {
				handler.writer = &faultWriter{RepositoryWriter: fixture.bucket, resolveErr: bucket.ErrUnavailable}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			if test.configure != nil {
				test.configure(fixture, fixture.handler)
			}
			body := commitBody(t,
				commitLine("header", commitHeaderDTO{Summary: "guard", ParentCommit: fixture.snapshot.OID.String()}),
				commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
			)
			if test.body != nil {
				body = test.body(fixture)
			}
			response := requestBody(t, fixture.handler, http.MethodPost, test.target, "Bearer hub-token", bytes.NewReader(body), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestCommitRejectsInvalidOrDifferentRetainedIntent(t *testing.T) {
	tests := map[string]struct {
		reader SnapshotReader
		status int
	}{
		"backend failure": {
			reader: snapshotReaderFunc(func(context.Context, model.RepoKey, model.OID) (model.Snapshot, error) {
				return model.Snapshot{}, bucket.ErrUnavailable
			}),
			status: http.StatusServiceUnavailable,
		},
		"invalid retained snapshot": {
			reader: snapshotReaderFunc(func(context.Context, model.RepoKey, model.OID) (model.Snapshot, error) {
				return model.Snapshot{}, nil
			}),
			status: http.StatusInternalServerError,
		},
		"different retained snapshot": {
			reader: snapshotReaderFunc(func(_ context.Context, repo model.RepoKey, oid model.OID) (model.Snapshot, error) {
				parent, _ := model.ParseOID("1111111111111111111111111111111111111111")
				return model.Snapshot{
					Repo: repo, OID: oid, Parent: &parent, CreatedAt: time.Unix(1_800_000_000, 0).UTC(),
					Author: model.Identity{Name: "different"}, Message: "different retained intent",
				}, nil
			}),
			status: http.StatusConflict,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			fixture.handler.snapshots = test.reader
			body := commitBody(t,
				commitLine("header", commitHeaderDTO{Summary: "retained", ParentCommit: fixture.snapshot.OID.String()}),
				commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
			)
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestPreuploadHandlesNewRefsAndUnavailableRemoteIdentities(t *testing.T) {
	t.Run("new named ref", func(t *testing.T) {
		fixture := newHandlerFixture(t, 0)
		response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/new-ref", "Bearer hub-token", strings.NewReader(`{"files":[]}`), nil)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
	})

	for name, configure := range map[string]func(handlerFixture, *Service){
		"missing Xet content": func(fixture handlerFixture, handler *Service) {
			handler.writer = &faultWriter{RepositoryWriter: fixture.bucket, resolveErr: bucket.ErrContentNotUploaded}
		},
		"no Xet writer": func(_ handlerFixture, handler *Service) {
			handler.writer = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			configure(fixture, fixture.handler)
			body := marshalJSON(t, preuploadRequestDTO{Files: []preuploadFileRequestDTO{{
				Path: "weights/model.bin", Size: int64(len(fixture.xetBody)),
			}}})
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/main", "Bearer hub-token", bytes.NewReader(body), nil)
			var decoded preuploadResponseDTO
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decoded) != nil || len(decoded.Files) != 1 || decoded.Files[0].OID != nil {
				t.Fatalf("response = %d, %#v, %s", response.Code, decoded, response.Body.String())
			}
		})
	}

	fixture := newHandlerFixture(t, 0)
	fixture.handler.bucket = &faultBucket{BucketService: fixture.bucket, resolveErr: bucket.ErrUnavailable}
	response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/main", "Bearer hub-token", strings.NewReader(`{"files":[]}`), nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolution failure = %d, %s", response.Code, response.Body.String())
	}

	fixture = newHandlerFixture(t, 0)
	fixture.handler.writer = nil
	response = requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"unsupported","organization":"owner"}`), nil)
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("missing create composition = %d, %s", response.Code, response.Body.String())
	}

	blob := fixture.snapshot.Files[0].Ref
	if _, err := fixture.handler.remoteFileOID(context.Background(), fixture.repo, model.OID{}, fixture.snapshot.Files[0].Path, blob); !errors.Is(err, bucket.ErrInvariant) {
		t.Fatalf("invalid pinned snapshot OID = %v", err)
	}
}

func TestCommitFinalRefCheckHandlesConcurrentCompletionAndMovement(t *testing.T) {
	for name, alreadyApplied := range map[string]bool{"already applied": true, "moved elsewhere": false} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			body := commitBody(t,
				commitLine("header", commitHeaderDTO{Summary: "final ref", ParentCommit: fixture.snapshot.OID.String()}),
				commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
			)
			digest := sha256.Sum256(body)
			ref, _ := model.ParseRefName("main")
			finalOID := commitOID(fixture.repo, ref, "user:test", digest, &fixture.snapshot.OID)
			if !alreadyApplied {
				finalOID, _ = model.ParseOID("2222222222222222222222222222222222222222")
			}
			store := &finalRevisionBucket{BucketService: fixture.bucket, final: model.Snapshot{Repo: fixture.repo, OID: finalOID}}
			publisher := &recordingPublisher{delegate: fixture.bucket}
			handler, err := New(Options{
				Bucket: store, Writer: fixture.bucket, Publisher: publisher, Broker: fixture.handler.broker,
				HubBaseURL: "https://hub.test", CASBaseURL: "https://cas.test",
			})
			if err != nil {
				t.Fatal(err)
			}
			response := requestBody(t, handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
			want := http.StatusConflict
			if alreadyApplied {
				want = http.StatusOK
			}
			if response.Code != want || publisher.calls != 0 {
				t.Fatalf("response = %d, calls=%d, body=%s", response.Code, publisher.calls, response.Body.String())
			}
		})
	}
}

func TestCommitAdditionalMalformedStreams(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	tooMuchEncodedContent := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "encoded limit", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("file", commitFileDTO{Path: "new", Encoding: "base64", Content: "AAAAA"}),
	)
	tests := map[string]struct {
		body      io.Reader
		configure func(*Service)
		status    int
	}{
		"empty body":       {body: bytes.NewReader(nil), status: http.StatusBadRequest},
		"empty line":       {body: strings.NewReader("\n"), status: http.StatusBadRequest},
		"missing envelope": {body: strings.NewReader("{\"key\":\"header\"}\n"), status: http.StatusBadRequest},
		"body read failure": {
			body: failingReader{err: errors.New("read failure")}, status: http.StatusInternalServerError,
		},
		"encoded content admission": {
			body: bytes.NewReader(tooMuchEncodedContent), status: http.StatusRequestEntityTooLarge,
			configure: func(handler *Service) { handler.fileBytes = 1 },
		},
		"invalid LFS path": {
			body: bytes.NewReader(commitBody(t,
				commitLine("header", commitHeaderDTO{Summary: "path", ParentCommit: fixture.snapshot.OID.String()}),
				commitLine("lfsFile", commitLFSFileDTO{Path: "../bad", Algo: "sha256", OID: hex.EncodeToString(fixture.cas.sum[:]), Size: int64Pointer(int64(len(fixture.xetBody)))}),
			)),
			status: http.StatusBadRequest,
		},
		"invalid delete DTO": {
			body: strings.NewReader("{\"key\":\"header\",\"value\":{\"summary\":\"delete\",\"parentCommit\":\"1111111111111111111111111111111111111111\"}}\n" +
				"{\"key\":\"deletedFile\",\"value\":{\"path\":\"config.json\",\"unknown\":true}}\n"),
			status: http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			if test.configure != nil {
				test.configure(fixture.handler)
			}
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", test.body, nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestWriteJSONAdmissionAndStrictDTOs(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	tests := []struct {
		name   string
		target string
		body   string
		status int
	}{
		{"create oversized", "/api/repos/create", `{"name":"` + strings.Repeat("x", maxCreateBodyBytes+1) + `"}`, http.StatusRequestEntityTooLarge},
		{"create unknown field", "/api/repos/create", `{"name":"strict","organization":"owner","unknown":true}`, http.StatusBadRequest},
		{"create multiple values", "/api/repos/create", `{"name":"strict","organization":"owner"}{}`, http.StatusBadRequest},
		{"create invalid visibility", "/api/repos/create", `{"name":"strict","organization":"owner","visibility":"secret"}`, http.StatusBadRequest},
		{"preupload unknown field", "/api/models/owner/model/preupload/main", `{"files":[],"unknown":true}`, http.StatusBadRequest},
		{"preupload duplicate", "/api/models/owner/model/preupload/main", `{"files":[{"path":"a","sample":"","size":1},{"path":"a","sample":"","size":1}]}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := requestBody(t, fixture.handler, http.MethodPost, test.target, "Bearer hub-token", strings.NewReader(test.body), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
	query := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/preupload/main?create_pr=1", "Bearer hub-token", strings.NewReader(`{"files":[]}`), nil)
	if query.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported preupload query = %d, %s", query.Code, query.Body.String())
	}
}

func TestCommitAddDeleteXetAndReplay(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	parent := fixture.snapshot.OID.String()
	regularBody := []byte("replacement metadata")
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "update", Description: "details", ParentCommit: parent}),
		commitLine("file", commitFileDTO{Path: "metadata.json", Encoding: "base64", Content: base64.StdEncoding.EncodeToString(regularBody)}),
		commitLine("lfsFile", commitLFSFileDTO{Path: "copy.bin", Algo: "sha256", OID: hex.EncodeToString(fixture.cas.sum[:]), Size: int64Pointer(int64(len(fixture.xetBody)))}),
		commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
	)

	first := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s", first.Code, first.Body.String())
	}
	var response struct {
		CommitOID string `json:"commitOid"`
		CommitURL string `json:"commitUrl"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.CommitOID == "" || !strings.HasPrefix(response.CommitURL, "https://hub.example/root/owner/model/commit/") ||
		!strings.HasSuffix(response.CommitURL, "/commit/"+response.CommitOID) {
		t.Fatalf("response = %#v", response)
	}
	revision, err := model.ParseRevision("main")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.bucket.ResolveRevision(context.Background(), fixture.repo, revision)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OID.String() != response.CommitOID || snapshot.Parent == nil || *snapshot.Parent != fixture.snapshot.OID {
		t.Fatalf("published snapshot = %#v", snapshot)
	}
	if got := snapshotPaths(snapshot); !reflect.DeepEqual(got, []string{"copy.bin", "metadata.json", "weights/model.bin"}) {
		t.Fatalf("paths = %v", got)
	}
	if snapshot.Author.Name != "user:test" || snapshot.Message != "update\n\ndetails" {
		t.Fatalf("metadata = %#v", snapshot)
	}

	replay := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if replay.Code != http.StatusOK || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay status/body = %d %q, first = %q", replay.Code, replay.Body.String(), first.Body.String())
	}
	page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("snapshot count after replay = %d", len(page.Items))
	}
}

func TestCommitFirstPublicationCreatesMain(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	repo, err := model.NewRepoKey("owner", "empty", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.bucket.CreateRepository(context.Background(), model.Repository{Key: repo, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "initial"}),
		commitLine("file", commitFileDTO{Path: "config.json", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("{}\n"))}),
	)
	response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/empty/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	revision, _ := model.ParseRevision("main")
	snapshot, err := fixture.bucket.ResolveRevision(context.Background(), repo, revision)
	if err != nil || snapshot.Parent != nil || len(snapshot.Files) != 1 || snapshot.Files[0].Path != "config.json" {
		t.Fatalf("initial snapshot = %#v, %v", snapshot, err)
	}
}

func TestCommitDeletesFolderWithOfficialTrailingSlash(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "delete weights", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("deletedFolder", commitDeleteDTO{Path: "weights/"}),
	)
	response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	revision, _ := model.ParseRevision("main")
	snapshot, err := fixture.bucket.ResolveRevision(context.Background(), fixture.repo, revision)
	if err != nil || len(snapshot.Files) != 1 || snapshot.Files[0].Path != "config.json" {
		t.Fatalf("snapshot = %#v, %v", snapshot, err)
	}
}

func TestCommitRejectsMissingContentAndMalformedStreams(t *testing.T) {
	missing := sha256.Sum256([]byte("missing"))
	tests := map[string]struct {
		body   func(handlerFixture) []byte
		status int
	}{
		"missing large file": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "missing", ParentCommit: f.snapshot.OID.String()}),
					commitLine("lfsFile", commitLFSFileDTO{Path: "missing.bin", Algo: "sha256", OID: hex.EncodeToString(missing[:]), Size: int64Pointer(7)}),
				)
			},
			status: http.StatusUnprocessableEntity,
		},
		"header not first": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
					commitLine("header", commitHeaderDTO{Summary: "late", ParentCommit: f.snapshot.OID.String()}),
				)
			},
			status: http.StatusBadRequest,
		},
		"truncated line": {
			body: func(f handlerFixture) []byte {
				complete := commitBody(t, commitLine("header", commitHeaderDTO{Summary: "truncated", ParentCommit: f.snapshot.OID.String()}))
				return append(complete, []byte(`{"key":"deletedFile","value":{"path":"config.json"}}`)...)
			},
			status: http.StatusBadRequest,
		},
		"duplicate path": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "duplicate", ParentCommit: f.snapshot.OID.String()}),
					commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
					commitLine("file", commitFileDTO{Path: "config.json", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("new"))}),
				)
			},
			status: http.StatusBadRequest,
		},
		"path traversal": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "traversal", ParentCommit: f.snapshot.OID.String()}),
					commitLine("file", commitFileDTO{Path: "../escape", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("bad"))}),
				)
			},
			status: http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(test.body(fixture)), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			revision, _ := model.ParseRevision("main")
			current, err := fixture.bucket.ResolveRevision(context.Background(), fixture.repo, revision)
			if err != nil || current.OID != fixture.snapshot.OID {
				t.Fatalf("current revision changed: %#v, %v", current, err)
			}
			page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("published snapshots = %#v, %v", page, err)
			}
		})
	}
}

func TestCommitRejectsMalformedAndContradictoryOperations(t *testing.T) {
	tests := map[string]struct {
		body   func(handlerFixture) []byte
		mutate func(*Service)
		status int
	}{
		"no operations": {
			body: func(f handlerFixture) []byte {
				return commitBody(t, commitLine("header", commitHeaderDTO{Summary: "empty", ParentCommit: f.snapshot.OID.String()}))
			},
			status: http.StatusBadRequest,
		},
		"repeated header": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "first", ParentCommit: f.snapshot.OID.String()}),
					commitLine("header", commitHeaderDTO{Summary: "second"}),
				)
			},
			status: http.StatusBadRequest,
		},
		"unknown operation": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "unknown", ParentCommit: f.snapshot.OID.String()}),
					commitLine("symlink", commitDeleteDTO{Path: "config.json"}),
				)
			},
			status: http.StatusBadRequest,
		},
		"invalid regular encoding": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "encoding", ParentCommit: f.snapshot.OID.String()}),
					commitLine("file", commitFileDTO{Path: "new", Encoding: "utf-8", Content: "body"}),
				)
			},
			status: http.StatusBadRequest,
		},
		"invalid base64": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "base64", ParentCommit: f.snapshot.OID.String()}),
					commitLine("file", commitFileDTO{Path: "new", Encoding: "base64", Content: "***"}),
				)
			},
			status: http.StatusBadRequest,
		},
		"invalid LFS algorithm": {
			body: func(f handlerFixture) []byte {
				size := int64(len(f.xetBody))
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "algorithm", ParentCommit: f.snapshot.OID.String()}),
					commitLine("lfsFile", commitLFSFileDTO{Path: "new", Algo: "md5", OID: hex.EncodeToString(f.cas.sum[:]), Size: &size}),
				)
			},
			status: http.StatusBadRequest,
		},
		"invalid LFS OID": {
			body: func(f handlerFixture) []byte {
				size := int64(len(f.xetBody))
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "OID", ParentCommit: f.snapshot.OID.String()}),
					commitLine("lfsFile", commitLFSFileDTO{Path: "new", Algo: "sha256", OID: strings.ToUpper(hex.EncodeToString(f.cas.sum[:])), Size: &size}),
				)
			},
			status: http.StatusBadRequest,
		},
		"LFS size limit": {
			body: func(f handlerFixture) []byte {
				size := int64(len(f.xetBody))
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "size", ParentCommit: f.snapshot.OID.String()}),
					commitLine("lfsFile", commitLFSFileDTO{Path: "new", Algo: "sha256", OID: hex.EncodeToString(f.cas.sum[:]), Size: &size}),
				)
			},
			mutate: func(service *Service) { service.fileBytes = 1 },
			status: http.StatusRequestEntityTooLarge,
		},
		"missing delete": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "delete", ParentCommit: f.snapshot.OID.String()}),
					commitLine("deletedFile", commitDeleteDTO{Path: "missing"}),
				)
			},
			status: http.StatusBadRequest,
		},
		"missing folder": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "folder", ParentCommit: f.snapshot.OID.String()}),
					commitLine("deletedFolder", commitDeleteDTO{Path: "missing/"}),
				)
			},
			status: http.StatusBadRequest,
		},
		"overlapping folder operations": {
			body: func(f handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "overlap", ParentCommit: f.snapshot.OID.String()}),
					commitLine("deletedFolder", commitDeleteDTO{Path: "weights/"}),
					commitLine("file", commitFileDTO{Path: "weights/new", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("new"))}),
				)
			},
			status: http.StatusBadRequest,
		},
		"invalid parent": {
			body: func(handlerFixture) []byte {
				return commitBody(t,
					commitLine("header", commitHeaderDTO{Summary: "parent", ParentCommit: "invalid"}),
					commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
				)
			},
			status: http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			if test.mutate != nil {
				test.mutate(fixture.handler)
			}
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(test.body(fixture)), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("published snapshots = %#v, %v", page, err)
			}
		})
	}
}

func TestCommitAdmissionLimits(t *testing.T) {
	tests := map[string]struct {
		limit  func(*Service)
		status int
	}{
		"operations": {limit: func(service *Service) { service.commitOps = 1 }, status: http.StatusRequestEntityTooLarge},
		"line":       {limit: func(service *Service) { service.lineBytes = 50 }, status: http.StatusRequestEntityTooLarge},
		"metadata":   {limit: func(service *Service) { service.metadata = 80 }, status: http.StatusRequestEntityTooLarge},
		"path":       {limit: func(service *Service) { service.pathBytes = 2 }, status: http.StatusBadRequest},
		"file":       {limit: func(service *Service) { service.fileBytes = 1 }, status: http.StatusRequestEntityTooLarge},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			test.limit(fixture.handler)
			body := commitBody(t,
				commitLine("header", commitHeaderDTO{Summary: "limits", ParentCommit: fixture.snapshot.OID.String()}),
				commitLine("file", commitFileDTO{Path: "one", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("12"))}),
				commitLine("file", commitFileDTO{Path: "two", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("12"))}),
			)
			response := requestBody(t, fixture.handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("published snapshots = %#v, %v", page, err)
			}
		})
	}
}

func TestCommitPublisherSeamAndVeto(t *testing.T) {
	t.Run("canonical exactly once", func(t *testing.T) {
		fixture := newHandlerFixture(t, 0)
		publisher := &recordingPublisher{delegate: fixture.bucket}
		handler := newWriteTestService(t, fixture, publisher)
		body := commitBody(t,
			commitLine("header", commitHeaderDTO{Summary: "publish", ParentCommit: fixture.snapshot.OID.String()}),
			commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
		)
		response := requestBody(t, handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
		publisher.mu.Lock()
		defer publisher.mu.Unlock()
		if publisher.calls != 1 || len(publisher.snapshots) != 1 {
			t.Fatalf("calls/snapshots = %d/%d", publisher.calls, len(publisher.snapshots))
		}
		canonical, err := model.CanonicalSnapshot(publisher.snapshots[0])
		if err != nil || !reflect.DeepEqual(canonical, publisher.snapshots[0]) {
			t.Fatalf("publisher did not receive canonical snapshot: %v", err)
		}
	})

	t.Run("veto", func(t *testing.T) {
		fixture := newHandlerFixture(t, 0)
		publisher := &recordingPublisher{err: fmt.Errorf("%w: host policy veto", bucket.ErrInvalid)}
		handler := newWriteTestService(t, fixture, publisher)
		body := commitBody(t,
			commitLine("header", commitHeaderDTO{Summary: "veto", ParentCommit: fixture.snapshot.OID.String()}),
			commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
		)
		response := requestBody(t, handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
		page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("published snapshots = %#v, %v", page, err)
		}
	})
}

type faultWriter struct {
	RepositoryWriter
	createErr  error
	putErr     error
	resolveErr error
}

func (writer *faultWriter) CreateRepository(ctx context.Context, repository model.Repository) error {
	if writer.createErr != nil {
		return writer.createErr
	}
	return writer.RepositoryWriter.CreateRepository(ctx, repository)
}

func (writer *faultWriter) PutBlob(ctx context.Context, blob content.Blob, source io.Reader) (bool, error) {
	if writer.putErr != nil {
		return false, writer.putErr
	}
	return writer.RepositoryWriter.PutBlob(ctx, blob, source)
}

func (writer *faultWriter) ResolveXetFile(
	ctx context.Context,
	repo model.RepoKey,
	sum [32]byte,
	size uint64,
) (xethash.Hash, error) {
	if writer.resolveErr != nil {
		return xethash.Hash{}, writer.resolveErr
	}
	return writer.RepositoryWriter.ResolveXetFile(ctx, repo, sum, size)
}

type faultBucket struct {
	BucketService
	resolveErr error
	getErr     error
	openErr    error
	openBody   io.ReadCloser
}

func (store *faultBucket) GetRepository(ctx context.Context, repo model.RepoKey) (model.Repository, error) {
	if store.getErr != nil {
		return model.Repository{}, store.getErr
	}
	return store.BucketService.GetRepository(ctx, repo)
}

func (store *faultBucket) ResolveRevision(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
) (model.Snapshot, error) {
	if store.resolveErr != nil {
		return model.Snapshot{}, store.resolveErr
	}
	return store.BucketService.ResolveRevision(ctx, repo, revision)
}

func (store *faultBucket) OpenFile(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
	path model.FilePath,
	options bucket.OpenOptions,
) (*bucket.FileReader, error) {
	if store.openErr != nil {
		return nil, store.openErr
	}
	opened, err := store.BucketService.OpenFile(ctx, repo, revision, path, options)
	if err != nil || store.openBody == nil {
		return opened, err
	}
	_ = opened.Body.Close()
	opened.Body = store.openBody
	return opened, nil
}

type snapshotReaderFunc func(context.Context, model.RepoKey, model.OID) (model.Snapshot, error)

func (function snapshotReaderFunc) GetSnapshot(ctx context.Context, repo model.RepoKey, oid model.OID) (model.Snapshot, error) {
	return function(ctx, repo, oid)
}

type finalRevisionBucket struct {
	BucketService
	final model.Snapshot
	calls int
}

func (store *finalRevisionBucket) ResolveRevision(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
) (model.Snapshot, error) {
	store.calls++
	if store.calls > 1 {
		return store.final, nil
	}
	return store.BucketService.ResolveRevision(ctx, repo, revision)
}

type resolveThenFailBucket struct {
	BucketService
	calls int
}

func (wrapper *resolveThenFailBucket) ResolveRevision(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
) (model.Snapshot, error) {
	wrapper.calls++
	if wrapper.calls > 1 {
		return model.Snapshot{}, bucket.ErrUnavailable
	}
	return wrapper.BucketService.ResolveRevision(ctx, repo, revision)
}

func TestCommitPreservesBackendFailureDuringFinalRefCheck(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	reader := &resolveThenFailBucket{BucketService: fixture.bucket}
	publisher := &recordingPublisher{delegate: fixture.bucket}
	handler, err := New(Options{
		Bucket: reader, Writer: fixture.bucket, Publisher: publisher, Broker: fixture.handler.broker,
		HubBaseURL: "https://hub.test", CASBaseURL: "https://cas.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "backend failure", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
	)
	response := requestBody(t, handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if publisher.calls != 0 {
		t.Fatalf("publisher calls = %d", publisher.calls)
	}
}

func TestConcurrentCommitsFromOneParentHaveOneWinner(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	makeBody := func(summary, path string) []byte {
		return commitBody(t,
			commitLine("header", commitHeaderDTO{Summary: summary, ParentCommit: fixture.snapshot.OID.String()}),
			commitLine("file", commitFileDTO{Path: path, Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(summary))}),
		)
	}
	left := makeBody("left", "left.bin")
	right := makeBody("right", "right.bin")
	leftDigest := sha256.Sum256(left)
	rightDigest := sha256.Sum256(right)
	ref, _ := model.ParseRefName("main")
	if commitOID(fixture.repo, ref, "user:test", leftDigest, &fixture.snapshot.OID)[0] == commitOID(fixture.repo, ref, "user:test", rightDigest, &fixture.snapshot.OID)[0] {
		t.Fatal("test commits unexpectedly selected the same striped lock")
	}
	publisher := &barrierPublisher{delegate: fixture.bucket, release: make(chan struct{})}
	handler := newWriteTestService(t, fixture, publisher)
	responses := make(chan int, 2)
	var wait sync.WaitGroup
	for _, body := range [][]byte{left, right} {
		body := body
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := requestBody(t, handler, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
			responses <- response.Code
		}()
	}
	wait.Wait()
	close(responses)
	counts := map[int]int{}
	for status := range responses {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("statuses = %#v", counts)
	}
	page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("snapshots = %#v, %v", page, err)
	}
}

func TestCommitOIDIncludesSnapshotAuthor(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	ref, err := model.ParseRefName("main")
	if err != nil {
		t.Fatal(err)
	}
	body := sha256.Sum256([]byte("same wire commit"))
	left := commitOID(fixture.repo, ref, "user:left", body, &fixture.snapshot.OID)
	right := commitOID(fixture.repo, ref, "user:right", body, &fixture.snapshot.OID)
	if left == right {
		t.Fatal("different immutable snapshot authors received one prepared OID")
	}
}

func TestCommitReconcilesLostPublicationResponseByExactReplay(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "prepared", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
	)
	ambiguous := newWriteTestService(t, fixture, publishThenError{delegate: fixture.bucket})
	first := requestBody(t, ambiguous, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous response = %d, %s", first.Code, first.Body.String())
	}

	// A fresh handler models process restart. Exact replay reuses the body-
	// derived prepared OID and recognizes the already-applied target state.
	restarted := newWriteTestService(t, fixture, fixture.bucket)
	replay := requestBody(t, restarted, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if replay.Code != http.StatusOK {
		t.Fatalf("exact replay = %d, %s", replay.Code, replay.Body.String())
	}
	different := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "different", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
	)
	conflict := requestBody(t, restarted, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(different), nil)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("differing replay = %d, %s", conflict.Code, conflict.Body.String())
	}
	page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("snapshots = %#v, %v", page, err)
	}
}

func TestCommitReplaysPersistedIntentAfterPrePublicationFailure(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	intent := &intentPublisher{delegate: fixture.bucket, failBeforePublication: true}
	newHandler := func() *Service {
		handler, err := New(Options{
			Bucket: fixture.bucket, Writer: fixture.bucket, Snapshots: intent, Publisher: intent, Broker: fixture.handler.broker,
			HubBaseURL: "https://hub.test/base", CASBaseURL: "https://cas.test/base",
		})
		if err != nil {
			t.Fatal(err)
		}
		return handler
	}
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "persisted intent", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
	)
	first := requestBody(t, newHandler(), http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-publication failure = %d, %s", first.Code, first.Body.String())
	}
	page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("snapshot published before retry = %#v, %v", page, err)
	}

	intent.mu.Lock()
	intent.failBeforePublication = false
	prepared := model.CloneSnapshot(intent.snapshot)
	intent.mu.Unlock()
	replay := requestBody(t, newHandler(), http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if replay.Code != http.StatusOK {
		t.Fatalf("persisted-intent replay = %d, %s", replay.Code, replay.Body.String())
	}
	intent.mu.Lock()
	published := model.CloneSnapshot(intent.lastPublished)
	intent.mu.Unlock()
	preparedFingerprint, err := model.FingerprintSnapshot(prepared)
	if err != nil {
		t.Fatal(err)
	}
	publishedFingerprint, err := model.FingerprintSnapshot(published)
	if err != nil || publishedFingerprint != preparedFingerprint {
		t.Fatalf("replay changed prepared snapshot: prepared=%#v published=%#v err=%v", prepared, published, err)
	}
}

func TestCommitReplaysRetainedRefLessSnapshotExactly(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	body := commitBody(t,
		commitLine("header", commitHeaderDTO{Summary: "detached prepared", ParentCommit: fixture.snapshot.OID.String()}),
		commitLine("deletedFile", commitDeleteDTO{Path: "config.json"}),
	)
	ambiguous := newWriteTestService(t, fixture, detachedPublisher{delegate: fixture.bucket, lost: true})
	first := requestBody(t, ambiguous, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous response = %d, %s", first.Code, first.Body.String())
	}
	mainRevision, _ := model.ParseRevision("main")
	main, err := fixture.bucket.ResolveRevision(context.Background(), fixture.repo, mainRevision)
	if err != nil || main.OID != fixture.snapshot.OID {
		t.Fatalf("ref-less publication moved main = %#v, %v", main, err)
	}
	page, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("snapshots after ambiguous detached publication = %#v, %v", page, err)
	}

	restarted := newWriteTestService(t, fixture, detachedPublisher{delegate: fixture.bucket})
	replay := requestBody(t, restarted, http.MethodPost, "/api/models/owner/model/commit/main", "Bearer hub-token", bytes.NewReader(body), nil)
	if replay.Code != http.StatusOK {
		t.Fatalf("exact detached replay = %d, %s", replay.Code, replay.Body.String())
	}
	after, err := fixture.bucket.ListSnapshots(context.Background(), fixture.repo, catalog.SnapshotQuery{})
	if err != nil || len(after.Items) != 2 {
		t.Fatalf("snapshots after exact detached replay = %#v, %v", after, err)
	}
}

type recordingPublisher struct {
	mu        sync.Mutex
	calls     int
	snapshots []model.Snapshot
	delegate  SnapshotPublisher
	err       error
}

type barrierPublisher struct {
	mu       sync.Mutex
	calls    int
	release  chan struct{}
	delegate SnapshotPublisher
}

type publishThenError struct{ delegate SnapshotPublisher }

type detachedPublisher struct {
	delegate SnapshotPublisher
	lost     bool
}

type intentPublisher struct {
	mu                    sync.Mutex
	delegate              SnapshotPublisher
	failBeforePublication bool
	snapshot              model.Snapshot
	lastPublished         model.Snapshot
}

func (publisher publishThenError) PublishSnapshot(ctx context.Context, snapshot model.Snapshot, expectation catalog.RefExpectation) error {
	if err := publisher.delegate.PublishSnapshot(ctx, snapshot, expectation); err != nil {
		return err
	}
	return bucket.ErrUnavailable
}

func (publisher detachedPublisher) PublishSnapshot(ctx context.Context, snapshot model.Snapshot, _ catalog.RefExpectation) error {
	if err := publisher.delegate.PublishSnapshot(ctx, snapshot, catalog.NoRefUpdate()); err != nil {
		return err
	}
	if publisher.lost {
		return bucket.ErrUnavailable
	}
	return nil
}

func (publisher *intentPublisher) GetSnapshot(_ context.Context, repo model.RepoKey, oid model.OID) (model.Snapshot, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if publisher.snapshot.Repo != repo || publisher.snapshot.OID != oid {
		return model.Snapshot{}, bucket.ErrNotFound
	}
	return model.CloneSnapshot(publisher.snapshot), nil
}

func (publisher *intentPublisher) PublishSnapshot(ctx context.Context, snapshot model.Snapshot, expectation catalog.RefExpectation) error {
	publisher.mu.Lock()
	if publisher.snapshot.OID.IsZero() {
		publisher.snapshot = model.CloneSnapshot(snapshot)
	}
	fail := publisher.failBeforePublication
	if !fail {
		publisher.lastPublished = model.CloneSnapshot(snapshot)
	}
	publisher.mu.Unlock()
	if fail {
		return bucket.ErrUnavailable
	}
	return publisher.delegate.PublishSnapshot(ctx, snapshot, expectation)
}

func (publisher *barrierPublisher) PublishSnapshot(ctx context.Context, snapshot model.Snapshot, expectation catalog.RefExpectation) error {
	publisher.mu.Lock()
	publisher.calls++
	if publisher.calls == 2 {
		close(publisher.release)
	}
	publisher.mu.Unlock()
	select {
	case <-publisher.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return publisher.delegate.PublishSnapshot(ctx, snapshot, expectation)
}

func (publisher *recordingPublisher) PublishSnapshot(ctx context.Context, snapshot model.Snapshot, expectation catalog.RefExpectation) error {
	publisher.mu.Lock()
	publisher.calls++
	publisher.snapshots = append(publisher.snapshots, model.CloneSnapshot(snapshot))
	publisher.mu.Unlock()
	if publisher.err != nil {
		return publisher.err
	}
	return publisher.delegate.PublishSnapshot(ctx, snapshot, expectation)
}

func newWriteTestService(t *testing.T, fixture handlerFixture, publisher SnapshotPublisher) *Service {
	t.Helper()
	handler, err := New(Options{
		Bucket: fixture.bucket, Writer: fixture.bucket, Publisher: publisher, Broker: fixture.handler.broker,
		HubBaseURL: "https://hub.test/base", CASBaseURL: "https://cas.test/base", CASTokenTTL: fixture.handler.ttl,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func assertPreuploadFile(t *testing.T, got preuploadFileResponseDTO, path, mode string, ignore bool, oid *string) {
	t.Helper()
	if got.Path != path || got.UploadMode != mode || got.ShouldIgnore != ignore {
		t.Fatalf("file = %#v, want path=%q mode=%q ignore=%t", got, path, mode, ignore)
	}
	if !reflect.DeepEqual(got.OID, oid) {
		t.Fatalf("oid = %v, want %v", got.OID, oid)
	}
}

func commitLine(key string, value any) commitEnvelopeDTO {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return commitEnvelopeDTO{Key: key, Value: encoded}
}

func commitBody(t *testing.T, lines ...commitEnvelopeDTO) []byte {
	t.Helper()
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, line := range lines {
		if err := encoder.Encode(line); err != nil {
			t.Fatal(err)
		}
	}
	return body.Bytes()
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func int64Pointer(value int64) *int64 { return &value }

func snapshotPaths(snapshot model.Snapshot) []string {
	result := make([]string, len(snapshot.Files))
	for index, entry := range snapshot.Files {
		result[index] = string(entry.Path)
	}
	return result
}

var _ SnapshotPublisher = (*recordingPublisher)(nil)
var _ SnapshotPublisher = (*barrierPublisher)(nil)
var _ SnapshotPublisher = publishThenError{}
var _ SnapshotPublisher = (*intentPublisher)(nil)
var _ SnapshotReader = (*intentPublisher)(nil)
