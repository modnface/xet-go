package hfcompat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	catalogmemory "github.com/jmwoliver/xet-go/catalog/memory"
	"github.com/jmwoliver/xet-go/content"
	contentmemory "github.com/jmwoliver/xet-go/content/memory"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

type handlerFixture struct {
	handler      *Service
	bucket       *bucket.Service
	manager      *auth.CASTokenManager
	cas          *fixtureCAS
	repo         model.RepoKey
	snapshot     model.Snapshot
	ordinaryBody []byte
	xetBody      []byte
}

type fixtureCAS struct {
	namespace string
	hash      xethash.Hash
	sum       [32]byte
	body      []byte
	opens     int
}

func (cas *fixtureCAS) VerifyFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	size uint64,
	sum *[32]byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if namespace != cas.namespace || hash != cas.hash || size != uint64(len(cas.body)) || sum == nil || *sum != cas.sum {
		return casserver.ErrNotFound
	}
	return nil
}

func (cas *fixtureCAS) ResolveFileInNamespace(
	ctx context.Context,
	namespace string,
	sum [32]byte,
	size uint64,
) (xethash.Hash, error) {
	if err := ctx.Err(); err != nil {
		return xethash.Hash{}, err
	}
	if namespace != cas.namespace || sum != cas.sum || size != uint64(len(cas.body)) {
		return xethash.Hash{}, casserver.ErrNotFound
	}
	return cas.hash, nil
}

func (cas *fixtureCAS) OpenFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	wanted *xetcas.FileRange,
) (*casserver.OpenedFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if namespace != cas.namespace || hash != cas.hash {
		return nil, casserver.ErrNotFound
	}
	cas.opens++
	selected := xetcas.FileRange{Start: 0, End: uint64(len(cas.body))}
	if wanted != nil {
		selected = *wanted
	}
	body := cas.body[selected.Start:selected.End]
	return &casserver.OpenedFile{
		Hash: hash, FileSize: uint64(len(cas.body)), Range: selected, Size: uint64(len(body)),
		SHA256: &cas.sum, Body: io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func newHandlerFixture(t *testing.T, maximum int) handlerFixture {
	t.Helper()
	ctx := context.Background()
	repo, err := model.NewRepoKey("owner", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := auth.RepositoryNamespace(repo)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryBody := []byte("{\"model_type\":\"bert\"}\n")
	ordinarySum := sha256.Sum256(ordinaryBody)
	ordinaryRef, err := model.NewBlobFileRef(ordinarySum, int64(len(ordinaryBody)))
	if err != nil {
		t.Fatal(err)
	}
	xetBody := bytes.Repeat([]byte("xet-model-data"), 100)
	xetSum := sha256.Sum256(xetBody)
	xetHash := xethash.Chunk([]byte("hfcompat Xet file identity"))
	xetRef, err := model.NewXetFileRef(xetHash, int64(len(xetBody)), &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	cas := &fixtureCAS{namespace: namespace, hash: xetHash, sum: xetSum, body: xetBody}
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	service, err := bucket.New(bucket.Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	repository := model.Repository{Key: repo, CreatedAt: time.Unix(1_700_000_000, 123).UTC()}
	if err = service.CreateRepository(ctx, repository); err != nil {
		t.Fatal(err)
	}
	if inserted, putErr := service.PutBlob(
		ctx,
		content.Blob{SHA256: ordinarySum, Size: int64(len(ordinaryBody))},
		bytes.NewReader(ordinaryBody),
	); putErr != nil || !inserted {
		t.Fatalf("put ordinary fixture = %v, %v", inserted, putErr)
	}
	oid, err := model.ParseOID("1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(1_700_000_100, 456).UTC(),
		Author: model.Identity{Name: "Test"}, Message: "publish handler fixture",
		Files: []model.FileEntry{
			{Path: "config.json", Ref: ordinaryRef},
			{Path: "weights/model.bin", Ref: xetRef},
		},
	}
	if err = service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if err = service.CompareAndSwapRef(ctx, repo, "feature/test", nil, oid); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	manager, err := auth.NewCASTokenManager(auth.CASTokenManagerOptions{
		Issuer: "hfcompat-test", Audience: "cas", Now: func() time.Time { return now },
		SigningKey: auth.HMACKey{ID: "test", Secret: bytes.Repeat([]byte{0x61}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewBroker(auth.BrokerOptions{
		Authenticator: auth.StaticTokenAuthenticator{Token: "hub-token", Principal: auth.Principal{Subject: "user:test"}},
		Authorizer: auth.RepositoryAuthorizerFunc(func(_ context.Context, access auth.RepositoryAccess) error {
			if access.Repository.Namespace != repo.Namespace || access.Repository.Type != model.RepoTypeModel ||
				(access.Permission != auth.RepositoryRead && access.Permission != auth.RepositoryWrite) {
				return auth.ErrPermissionDenied
			}
			return nil
		}),
		Tokens: manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Bucket: service, Broker: broker, HubBaseURL: "https://hub.example/root", CASBaseURL: "https://cas.example/cas",
		MaxTreeEntries: maximum,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handlerFixture{handler, service, manager, cas, repo, snapshot, ordinaryBody, xetBody}
}

func request(t *testing.T, handler http.Handler, method, target, credential string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return requestBody(t, handler, method, target, credential, nil, headers)
}

func requestBody(
	t *testing.T,
	handler http.Handler,
	method string,
	target string,
	credential string,
	body io.Reader,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if credential != "" {
		req.Header.Set("Authorization", credential)
	}
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestHandlerWhoamiCreateAndWriteToken(t *testing.T) {
	fixture := newHandlerFixture(t, 0)

	whoami := request(t, fixture.handler, http.MethodGet, "/api/whoami-v2", "Bearer hub-token", nil)
	if whoami.Code != http.StatusOK || whoami.Body.String() != "{\"type\":\"user\",\"name\":\"user:test\"}\n" ||
		strings.Contains(whoami.Body.String(), "hub-token") {
		t.Fatalf("whoami = %d, %#v, %q", whoami.Code, whoami.Header(), whoami.Body.String())
	}
	invalidWhoami := request(t, fixture.handler, http.MethodGet, "/api/whoami-v2", "Bearer wrong", nil)
	if invalidWhoami.Code != http.StatusUnauthorized || invalidWhoami.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("invalid whoami = %d, %#v", invalidWhoami.Code, invalidWhoami.Header())
	}
	whoamiMethod := request(t, fixture.handler, http.MethodPost, "/api/whoami-v2", "Bearer hub-token", nil)
	if whoamiMethod.Code != http.StatusMethodNotAllowed || whoamiMethod.Header().Get("Allow") != "GET" {
		t.Fatalf("whoami method = %d, %#v", whoamiMethod.Code, whoamiMethod.Header())
	}
	createMethod := request(t, fixture.handler, http.MethodGet, "/api/repos/create", "Bearer hub-token", nil)
	if createMethod.Code != http.StatusMethodNotAllowed || createMethod.Header().Get("Allow") != "POST" {
		t.Fatalf("create method = %d, %#v", createMethod.Code, createMethod.Header())
	}
	unauthenticatedCreate := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "", strings.NewReader(`{"name":"created","organization":"owner"}`), nil)
	if unauthenticatedCreate.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated create = %d, %#v", unauthenticatedCreate.Code, unauthenticatedCreate.Header())
	}
	deniedCreate := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"created","organization":"other"}`), nil)
	if deniedCreate.Code != http.StatusNotFound || deniedCreate.Header().Get("X-Error-Code") != "RepoNotFound" {
		t.Fatalf("denied create = %d, %#v", deniedCreate.Code, deniedCreate.Header())
	}

	createBody := `{"name":"created","organization":"owner","type":"model","visibility":"private"}`
	created := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(createBody), nil)
	if created.Code != http.StatusOK || created.Body.String() != "{\"url\":\"https://hub.example/root/owner/created\"}\n" {
		t.Fatalf("create = %d, %#v, %q", created.Code, created.Header(), created.Body.String())
	}
	createdRepo, err := model.NewRepoKey("owner", "created", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fixture.bucket.GetRepository(context.Background(), createdRepo); err != nil || got.Key != createdRepo {
		t.Fatalf("created repository = %#v, %v", got, err)
	}
	replayed := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(createBody), nil)
	if replayed.Code != http.StatusConflict || replayed.Body.String() != created.Body.String() {
		t.Fatalf("create replay = %d, %#v, %q", replayed.Code, replayed.Header(), replayed.Body.String())
	}
	unsupported := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"data","organization":"owner","type":"dataset"}`), nil)
	if unsupported.Code != http.StatusNotImplemented || unsupported.Header().Get("X-Error-Code") != "UnsupportedRepoType" {
		t.Fatalf("unsupported create = %d, %#v", unsupported.Code, unsupported.Header())
	}
	invalid := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"../bad","organization":"owner"}`), nil)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid create = %d, %q", invalid.Code, invalid.Body.String())
	}

	writeToken := request(t, fixture.handler, http.MethodGet, "/api/models/owner/model/xet-write-token/main", "Bearer hub-token", nil)
	var token struct {
		AccessToken string `json:"accessToken"`
		CASURL      string `json:"casUrl"`
		Exp         int64  `json:"exp"`
	}
	if writeToken.Code != http.StatusOK || json.Unmarshal(writeToken.Body.Bytes(), &token) != nil ||
		writeToken.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("write token = %d, %#v, %q", writeToken.Code, writeToken.Header(), writeToken.Body.String())
	}
	claims, err := fixture.manager.VerifyCASToken(context.Background(), token.AccessToken)
	if err != nil || claims.Permissions != auth.CASWrite || claims.Permissions.Allows(auth.CASRead) || token.CASURL != "https://cas.example/cas" {
		t.Fatalf("write token claims = %#v, %v", claims, err)
	}
	authorizer := auth.CASAuthorizer{Verifier: fixture.manager}
	if _, err = authorizer.Authorize(context.Background(), token.AccessToken, casserver.AccessRequest{Operation: casserver.OperationReadFile}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("write token read = %v", err)
	}
	grant, err := authorizer.Authorize(context.Background(), token.AccessToken, casserver.AccessRequest{Operation: casserver.OperationWriteShard})
	if err != nil || grant.Namespace != fixture.cas.namespace {
		t.Fatalf("write token scope = %#v, %v", grant, err)
	}
	other, err := model.NewRepoKey("other", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	otherNamespace, err := auth.RepositoryNamespace(other)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Namespace == otherNamespace {
		t.Fatal("write token reached another repository namespace")
	}
}

func TestWriteRouteRequiresWritePermissionBeforeMethodOrStorage(t *testing.T) {
	repo := testRepoKey(t)
	store := &stubBucket{getErr: bucket.ErrNotFound}
	permissions := make([]auth.RepositoryPermission, 0, 3)
	denied := true
	broker := stubBroker{
		authorize: func(_ context.Context, credential string, got model.RepoKey, permission auth.RepositoryPermission) (auth.RepositoryGrant, error) {
			permissions = append(permissions, permission)
			if credential != "read-only" {
				return auth.RepositoryGrant{}, auth.ErrUnauthenticated
			}
			if got != repo || denied || permission != auth.RepositoryWrite {
				return auth.RepositoryGrant{}, auth.ErrPermissionDenied
			}
			return auth.RepositoryGrant{}, nil
		},
		issue: func(context.Context, auth.RepositoryGrant, auth.CASPermissions, time.Duration) (auth.IssuedCASToken, error) {
			return auth.IssuedCASToken{Value: "write"}, nil
		},
	}
	handler, err := New(Options{Bucket: store, Broker: broker, HubBaseURL: "https://hub.example", CASBaseURL: "https://cas.example"})
	if err != nil {
		t.Fatal(err)
	}
	target := "/api/models/owner/model/xet-write-token/main"
	deniedResponse := request(t, handler, http.MethodGet, target, "Bearer read-only", map[string]string{"X-Request-Id": "concealed"})
	if deniedResponse.Code != http.StatusNotFound || deniedResponse.Header().Get("X-Error-Code") != "RepoNotFound" || store.calls != 0 ||
		len(permissions) != 1 || permissions[0] != auth.RepositoryWrite {
		t.Fatalf("denied write = %d, %#v, calls=%d permissions=%#v", deniedResponse.Code, deniedResponse.Header(), store.calls, permissions)
	}
	denied = false
	missingResponse := request(t, handler, http.MethodGet, target, "Bearer read-only", map[string]string{"X-Request-Id": "concealed"})
	if missingResponse.Code != deniedResponse.Code || missingResponse.Body.String() != deniedResponse.Body.String() ||
		!reflect.DeepEqual(missingResponse.Header(), deniedResponse.Header()) || store.calls != 1 {
		t.Fatalf("concealed responses differ: denied=%#v %q missing=%#v %q", deniedResponse.Header(), deniedResponse.Body.String(), missingResponse.Header(), missingResponse.Body.String())
	}
	unauthenticated := request(t, handler, http.MethodGet, target, "", nil)
	if unauthenticated.Code != http.StatusUnauthorized || store.calls != 1 {
		t.Fatalf("unauthenticated write = %d, calls=%d", unauthenticated.Code, store.calls)
	}
	wrongMethod := request(t, handler, http.MethodPost, target, "Bearer read-only", nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "GET" || store.calls != 1 {
		t.Fatalf("write method = %d, %#v, calls=%d", wrongMethod.Code, wrongMethod.Header(), store.calls)
	}
}

func TestEveryRepositoryWriteRouteDerivesWritePermissionAndExactAllow(t *testing.T) {
	repo := testRepoKey(t)
	tests := []struct {
		name        string
		target      string
		allowed     string
		wrongMethod string
	}{
		{"write token", "/api/models/owner/model/xet-write-token/main", "GET", http.MethodPost},
		{"preupload", "/api/models/owner/model/preupload/main", "POST", http.MethodGet},
		{"commit", "/api/models/owner/model/commit/main", "POST", http.MethodGet},
		{"LFS batch", "/owner/model.git/info/lfs/objects/batch", "POST", http.MethodGet},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &stubBucket{}
			denied := true
			permissions := make([]auth.RepositoryPermission, 0, 3)
			broker := stubBroker{authorize: func(_ context.Context, credential string, got model.RepoKey, permission auth.RepositoryPermission) (auth.RepositoryGrant, error) {
				permissions = append(permissions, permission)
				if credential == "" {
					return auth.RepositoryGrant{}, auth.ErrUnauthenticated
				}
				if got != repo || denied {
					return auth.RepositoryGrant{}, auth.ErrPermissionDenied
				}
				return auth.RepositoryGrant{}, nil
			}}
			handler, err := New(Options{Bucket: store, Broker: broker, HubBaseURL: "https://hub.test", CASBaseURL: "https://cas.test"})
			if err != nil {
				t.Fatal(err)
			}
			method := test.allowed
			concealed := request(t, handler, method, test.target, "Bearer read", map[string]string{"X-Request-Id": "same"})
			if concealed.Code != http.StatusNotFound || concealed.Header().Get("X-Error-Code") != "RepoNotFound" ||
				len(permissions) != 1 || permissions[0] != auth.RepositoryWrite || store.calls != 0 {
				t.Fatalf("concealed = %d, %#v, permissions=%#v, calls=%d", concealed.Code, concealed.Header(), permissions, store.calls)
			}
			unauthenticated := request(t, handler, method, test.target, "", nil)
			if unauthenticated.Code != http.StatusUnauthorized || store.calls != 0 {
				t.Fatalf("unauthenticated = %d, calls=%d", unauthenticated.Code, store.calls)
			}
			denied = false
			wrong := request(t, handler, test.wrongMethod, test.target, "Bearer read", nil)
			if wrong.Code != http.StatusMethodNotAllowed || wrong.Header().Get("Allow") != test.allowed || store.calls != 0 {
				t.Fatalf("wrong method = %d, %#v, calls=%d", wrong.Code, wrong.Header(), store.calls)
			}
		})
	}
}

func TestEveryRepositoryWriteRouteConcealsDeniedAndMissingRepositoriesIdentically(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	lfsHandler, err := New(Options{
		Bucket: fixture.bucket, Broker: fixture.handler.broker, Ingester: XetFileIngestFunc(func(context.Context, model.RepoKey, io.Reader) (XetFileIngestResult, error) {
			return XetFileIngestResult{}, errors.New("unused")
		}),
		HubBaseURL: "https://hub.test", CASBaseURL: "https://cas.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		handler       http.Handler
		method        string
		deniedTarget  string
		missingTarget string
		body          string
		headers       map[string]string
	}{
		{"write token", fixture.handler, http.MethodGet, "/api/models/other/model/xet-write-token/main", "/api/models/owner/missing/xet-write-token/main", "", nil},
		{"preupload", fixture.handler, http.MethodPost, "/api/models/other/model/preupload/main", "/api/models/owner/missing/preupload/main", `{"files":[]}`, nil},
		{"commit", fixture.handler, http.MethodPost, "/api/models/other/model/commit/main", "/api/models/owner/missing/commit/main", "", nil},
		{"LFS batch", lfsHandler, http.MethodPost, "/other/model.git/info/lfs/objects/batch", "/owner/missing.git/info/lfs/objects/batch", "", map[string]string{"Content-Type": lfsMediaType}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := make(map[string]string, len(test.headers)+1)
			for key, value := range test.headers {
				headers[key] = value
			}
			headers["X-Request-Id"] = "concealed-write"
			denied := requestBody(t, test.handler, test.method, test.deniedTarget, "Bearer hub-token", strings.NewReader(test.body), headers)
			missing := requestBody(t, test.handler, test.method, test.missingTarget, "Bearer hub-token", strings.NewReader(test.body), headers)
			if denied.Code != http.StatusNotFound || denied.Header().Get("X-Error-Code") != "RepoNotFound" ||
				missing.Code != denied.Code || missing.Body.String() != denied.Body.String() || !reflect.DeepEqual(missing.Header(), denied.Header()) {
				t.Fatalf("responses differ: denied=%d %#v %q; missing=%d %#v %q",
					denied.Code, denied.Header(), denied.Body.String(), missing.Code, missing.Header(), missing.Body.String())
			}
		})
	}
}

type recordingWriteAudit struct {
	mu     sync.Mutex
	events []WriteAuditEvent
}

func (audit *recordingWriteAudit) RecordHubWrite(_ context.Context, event WriteAuditEvent) {
	audit.mu.Lock()
	audit.events = append(audit.events, event)
	audit.mu.Unlock()
}

func TestWriteAuditRecordsNonSecretOutcomes(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	audit := &recordingWriteAudit{}
	fixture.handler.audit = audit

	read := request(t, fixture.handler, http.MethodGet, "/api/models/owner/model", "Bearer hub-token", nil)
	if read.Code != http.StatusOK {
		t.Fatalf("read status = %d", read.Code)
	}
	writeToken := request(t, fixture.handler, http.MethodGet, "/api/models/owner/model/xet-write-token/main", "Bearer hub-token", map[string]string{"X-Request-Id": "write-token-correlation"})
	if writeToken.Code != http.StatusOK {
		t.Fatalf("write token status = %d", writeToken.Code)
	}
	denied := requestBody(t, fixture.handler, http.MethodPost, "/api/models/other/model/preupload/main", "Bearer hub-token", strings.NewReader(`{"files":[]}`), map[string]string{"X-Request-Id": "denied-correlation"})
	if denied.Code != http.StatusNotFound {
		t.Fatalf("denied status = %d", denied.Code)
	}
	created := requestBody(t, fixture.handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"audited","organization":"owner"}`), map[string]string{"X-Request-Id": "create-correlation"})
	if created.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", created.Code, created.Body.String())
	}

	audit.mu.Lock()
	events := append([]WriteAuditEvent(nil), audit.events...)
	audit.mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("audit events = %#v", events)
	}
	if events[0].Operation != "write-token" || events[0].StatusCode != http.StatusOK ||
		events[0].CorrelationID != "write-token-correlation" || events[0].Principal.Subject != "user:test" || events[0].Repository != fixture.repo {
		t.Fatalf("write-token audit = %#v", events[0])
	}
	other, err := model.NewRepoKey("other", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	if events[1].Operation != "preupload" || events[1].StatusCode != http.StatusNotFound ||
		events[1].CorrelationID != "denied-correlation" || events[1].Principal.Subject != "user:test" || events[1].Repository != other {
		t.Fatalf("denied audit = %#v", events[1])
	}
	createdRepo, err := model.NewRepoKey("owner", "audited", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	if events[2].Operation != "create" || events[2].StatusCode != http.StatusOK ||
		events[2].CorrelationID != "create-correlation" || events[2].Principal.Subject != "user:test" || events[2].Repository != createdRepo {
		t.Fatalf("create audit = %#v", events[2])
	}
	if strings.Contains(fmt.Sprintf("%#v", events), "hub-token") {
		t.Fatal("audit event exposed the Hub credential")
	}
}

func testRepoKey(t *testing.T) model.RepoKey {
	t.Helper()
	repo, err := model.NewRepoKey("owner", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestHandlerPinnedReadWorkflow(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	oid := fixture.snapshot.OID.String()
	modelResponse := request(t, fixture.handler.Handler(), http.MethodGet, "/api/models/owner/model?blobs=true", "Bearer hub-token", nil)
	if modelResponse.Code != http.StatusOK || modelResponse.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("model response = %d, %#v, %s", modelResponse.Code, modelResponse.Header(), modelResponse.Body.String())
	}
	var info modelDTO
	if err := json.Unmarshal(modelResponse.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.ID != "owner/model" || info.ModelID != info.ID || info.Author != "owner" || info.SHA != oid || len(info.Siblings) != 2 ||
		info.Siblings[0].Filename != "config.json" || !strings.HasPrefix(info.Siblings[0].BlobID, "xet-go:file:sha256:") ||
		!strings.HasPrefix(info.Siblings[1].BlobID, "xet-go:file:xet:") {
		t.Fatalf("model info = %#v", info)
	}
	if info.CreatedAt != time.Unix(1_700_000_000, 123).UTC() || info.LastModified != fixture.snapshot.CreatedAt {
		t.Fatalf("model timestamps = %s, %s", info.CreatedAt, info.LastModified)
	}

	revisionResponse := request(t, fixture.handler, http.MethodGet, "/api/models/owner/model/revision/feature%2Ftest?blobs=true", "bearer hub-token", nil)
	if revisionResponse.Code != http.StatusOK {
		t.Fatalf("encoded revision response = %d, %s", revisionResponse.Code, revisionResponse.Body.String())
	}

	treeResponse := request(t, fixture.handler, http.MethodGet, "/api/models/owner/model/tree/main?recursive=true&expand=false", "Bearer hub-token", nil)
	var tree []treeDTO
	if treeResponse.Code != http.StatusOK {
		t.Fatalf("tree response = %d, %s", treeResponse.Code, treeResponse.Body.String())
	}
	if err := json.Unmarshal(treeResponse.Body.Bytes(), &tree); err != nil {
		t.Fatal(err)
	}
	if len(tree) != 3 || tree[0].Path != "config.json" || tree[1].Type != "directory" || tree[1].Path != "weights" ||
		!strings.HasPrefix(tree[1].OID, "xet-go:dir:"+oid+":") || tree[2].XetHash == "" {
		t.Fatalf("tree = %#v", tree)
	}

	ordinaryHead := request(t, fixture.handler, http.MethodHead, "/owner/model/resolve/main/config.json", "Bearer hub-token", map[string]string{"Range": "bytes=1-2"})
	if ordinaryHead.Code != http.StatusOK || ordinaryHead.Body.Len() != 0 || ordinaryHead.Header().Get("Content-Length") != "22" ||
		ordinaryHead.Header().Get("X-Repo-Commit") != oid || ordinaryHead.Header().Get("X-Xet-Hash") != "" || fixture.cas.opens != 0 {
		t.Fatalf("ordinary HEAD = %d, %#v, opens=%d", ordinaryHead.Code, ordinaryHead.Header(), fixture.cas.opens)
	}
	xetHead := request(t, fixture.handler, http.MethodHead, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", nil)
	if xetHead.Code != http.StatusOK || xetHead.Header().Get("Content-Length") != "1400" || fixture.cas.opens != 0 {
		t.Fatalf("Xet HEAD = %d, %#v, opens=%d", xetHead.Code, xetHead.Header(), fixture.cas.opens)
	}
	wantLink := "<https://hub.example/root/api/models/owner/model/xet-read-token/" + oid + ">; rel=\"xet-auth\""
	if xetHead.Header().Get("Link") != wantLink || xetHead.Header().Get("X-Xet-Hash") != fixture.cas.hash.String() ||
		xetHead.Header().Get("ETag") != `"`+hex.EncodeToString(fixture.cas.sum[:])+`"` {
		t.Fatalf("Xet HEAD metadata = %#v", xetHead.Header())
	}

	ordinaryGet := request(t, fixture.handler, http.MethodGet, "/owner/model/resolve/main/config.json", "Bearer hub-token", nil)
	if ordinaryGet.Code != http.StatusOK || !bytes.Equal(ordinaryGet.Body.Bytes(), fixture.ordinaryBody) {
		t.Fatalf("ordinary GET = %d, %q", ordinaryGet.Code, ordinaryGet.Body.Bytes())
	}
	ordinaryRange := request(t, fixture.handler, http.MethodGet, "/owner/model/resolve/main/config.json", "Bearer hub-token", map[string]string{"Range": "bytes=1-4"})
	if ordinaryRange.Code != http.StatusPartialContent || !bytes.Equal(ordinaryRange.Body.Bytes(), fixture.ordinaryBody[1:5]) ||
		ordinaryRange.Header().Get("Content-Range") != "bytes 1-4/22" || ordinaryRange.Header().Get("Content-Length") != "4" {
		t.Fatalf("ordinary range = %d, %#v, %q", ordinaryRange.Code, ordinaryRange.Header(), ordinaryRange.Body.Bytes())
	}
	xetGet := request(t, fixture.handler, http.MethodGet, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", nil)
	if xetGet.Code != http.StatusOK || !bytes.Equal(xetGet.Body.Bytes(), fixture.xetBody) {
		t.Fatalf("Xet GET = %d, %d bytes", xetGet.Code, xetGet.Body.Len())
	}
	xetRange := request(t, fixture.handler, http.MethodGet, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", map[string]string{"Range": "bytes=-7"})
	if xetRange.Code != http.StatusPartialContent || !bytes.Equal(xetRange.Body.Bytes(), fixture.xetBody[len(fixture.xetBody)-7:]) {
		t.Fatalf("Xet suffix GET = %d, %q", xetRange.Code, xetRange.Body.Bytes())
	}

	tokenResponse := request(t, fixture.handler, http.MethodGet, "/api/models/owner/model/xet-read-token/main", "Bearer hub-token", nil)
	var token struct {
		AccessToken string `json:"accessToken"`
		CASURL      string `json:"casUrl"`
		Exp         int64  `json:"exp"`
	}
	if tokenResponse.Code != http.StatusOK || json.Unmarshal(tokenResponse.Body.Bytes(), &token) != nil {
		t.Fatalf("token response = %d, %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	claims, err := fixture.manager.VerifyCASToken(context.Background(), token.AccessToken)
	namespace, namespaceErr := auth.RepositoryNamespace(fixture.repo)
	if err != nil || namespaceErr != nil || token.CASURL != "https://cas.example/cas" || token.Exp != claims.ExpiresAt.Unix() ||
		claims.Namespace != namespace || claims.Permissions != auth.CASRead || claims.Subject != "user:test" {
		t.Fatalf("token/claims = %#v, %#v, verify=%v namespace=%v", token, claims, err, namespaceErr)
	}
}

func TestPerRequestBaseURLsForResolveAndTokens(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	calls := 0
	handler, err := New(Options{
		Bucket: fixture.bucket,
		Broker: fixture.handler.broker,
		BaseURLFunc: func(r *http.Request) (string, string, error) {
			calls++
			prefix := r.Header.Get("X-Test-Prefix")
			return "https://hub.test/" + prefix + "/root", "https://cas.test/" + prefix + "/root", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	oid := fixture.snapshot.OID.String()
	resolveCases := []struct {
		method string
		prefix string
	}{
		{http.MethodHead, "tenant-a"},
		{http.MethodGet, "tenant-b"},
	}
	for _, test := range resolveCases {
		before := calls
		response := request(t, handler, test.method, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", map[string]string{"X-Test-Prefix": test.prefix})
		wantLink := "<https://hub.test/" + test.prefix + "/root/api/models/owner/model/xet-read-token/" + oid + ">; rel=\"xet-auth\""
		if response.Code != http.StatusOK || response.Header().Get("Link") != wantLink || calls != before+1 {
			t.Fatalf("%s resolve = %d, link %q, calls %d", test.method, response.Code, response.Header().Get("Link"), calls-before)
		}
	}

	tokenCases := []struct {
		kind   string
		prefix string
	}{
		{"read", "tenant-a"},
		{"write", "tenant-b"},
	}
	for _, test := range tokenCases {
		before := calls
		response := request(t, handler, http.MethodGet, "/api/models/owner/model/xet-"+test.kind+"-token/main", "Bearer hub-token", map[string]string{"X-Test-Prefix": test.prefix})
		var decoded struct {
			CASURL string `json:"casUrl"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decoded) != nil ||
			decoded.CASURL != "https://cas.test/"+test.prefix+"/root" || calls != before+1 {
			t.Fatalf("%s token = %d, %#v, calls %d", test.kind, response.Code, decoded, calls-before)
		}
	}
}

func TestBaseURLFuncFailureIsInternalAndEmitsNoURL(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	tests := []struct {
		name string
		hub  string
		cas  string
		err  error
	}{
		{name: "userinfo", hub: "https://user@hub.test/base", cas: "https://cas.test/base"},
		{name: "query", hub: "https://hub.test/base?q=1", cas: "https://cas.test/base"},
		{name: "fragment", hub: "https://hub.test/base#fragment", cas: "https://cas.test/base"},
		{name: "trailing slash", hub: "https://hub.test/base/", cas: "https://cas.test/base"},
		{name: "dot component", hub: "https://hub.test/base/../other", cas: "https://cas.test/base"},
		{name: "control character", hub: "https://hub.test/base\nother", cas: "https://cas.test/base"},
		{name: "invalid CAS", hub: "https://hub.test/base", cas: "https://cas.test/base?query=1"},
		{name: "function error", err: errors.New("secret resolver detail")},
		{name: "classified function error", err: fmt.Errorf("secret resolver detail: %w", bucket.ErrUnavailable)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler, err := New(Options{
				Bucket: fixture.bucket,
				Broker: fixture.handler.broker,
				BaseURLFunc: func(*http.Request) (string, string, error) {
					calls++
					return test.hub, test.cas, test.err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			response := request(t, handler, http.MethodGet, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", nil)
			if response.Code != http.StatusInternalServerError || calls != 1 || response.Header().Get("Link") != "" ||
				strings.Contains(response.Body.String(), "secret resolver detail") || strings.Contains(response.Body.String(), "hub.test") {
				t.Fatalf("response = %d, %#v, %q, calls=%d", response.Code, response.Header(), response.Body.String(), calls)
			}
		})
	}
}

func TestBaseURLFuncRunsOnlyForAuthorizedURLProducingRequests(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	calls := 0
	handler, err := New(Options{
		Bucket: fixture.bucket,
		Broker: fixture.handler.broker,
		BaseURLFunc: func(*http.Request) (string, string, error) {
			calls++
			return "https://hub.test/base", "https://cas.test/base", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method     string
		target     string
		credential string
		status     int
	}{
		{http.MethodGet, "/unknown", "", http.StatusNotFound},
		{http.MethodGet, "/api/models/owner/model", "Bearer hub-token", http.StatusOK},
		{http.MethodGet, "/owner/model/resolve/main/weights/model.bin", "", http.StatusUnauthorized},
		{http.MethodPost, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", http.StatusMethodNotAllowed},
	} {
		response := request(t, handler, test.method, test.target, test.credential, nil)
		if response.Code != test.status {
			t.Fatalf("%s %s = %d", test.method, test.target, response.Code)
		}
	}
	deniedCreate := requestBody(t, handler, http.MethodPost, "/api/repos/create", "Bearer hub-token", strings.NewReader(`{"name":"denied","organization":"other"}`), nil)
	if deniedCreate.Code != http.StatusNotFound || calls != 0 {
		t.Fatalf("denied create = %d, calls=%d, body=%q", deniedCreate.Code, calls, deniedCreate.Body.String())
	}
	response := request(t, handler, http.MethodHead, "/owner/model/resolve/main/weights/model.bin", "Bearer hub-token", nil)
	if response.Code != http.StatusOK || calls != 1 {
		t.Fatalf("authorized resolve = %d, calls=%d", response.Code, calls)
	}
}

func TestStaticBaseURLsIgnoreHostAndForwardingHeaders(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	req := httptest.NewRequest(http.MethodHead, "/owner/model/resolve/main/weights/model.bin", nil)
	req.Host = "attacker.example"
	req.Header.Set("Host", "attacker.example")
	req.Header.Set("X-Forwarded-Host", "forwarded-attacker.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("Authorization", "Bearer hub-token")
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, req)
	want := "<https://hub.example/root/api/models/owner/model/xet-read-token/" + fixture.snapshot.OID.String() + ">; rel=\"xet-auth\""
	if recorder.Code != http.StatusOK || recorder.Header().Get("Link") != want {
		t.Fatalf("response = %d, link %q", recorder.Code, recorder.Header().Get("Link"))
	}
	tokenRequest := httptest.NewRequest(http.MethodGet, "/api/models/owner/model/xet-read-token/main", nil)
	tokenRequest.Host = "attacker.example"
	tokenRequest.Header.Set("X-Forwarded-Host", "forwarded-attacker.example")
	tokenRequest.Header.Set("X-Forwarded-Proto", "http")
	tokenRequest.Header.Set("Authorization", "Bearer hub-token")
	tokenRecorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(tokenRecorder, tokenRequest)
	var token struct {
		CASURL string `json:"casUrl"`
	}
	if tokenRecorder.Code != http.StatusOK || json.Unmarshal(tokenRecorder.Body.Bytes(), &token) != nil || token.CASURL != "https://cas.example/cas" {
		t.Fatalf("token response = %d, %#v, %q", tokenRecorder.Code, token, tokenRecorder.Body.String())
	}
}

func TestHandlerReadFailuresAndLimits(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	tests := []struct {
		name    string
		method  string
		target  string
		headers map[string]string
		status  int
		code    string
	}{
		{name: "missing revision metadata", method: http.MethodGet, target: "/api/models/owner/model/revision/missing", status: 404, code: "RevisionNotFound"},
		{name: "missing tree revision", method: http.MethodGet, target: "/api/models/owner/model/tree/missing?recursive=true&expand=false", status: 404, code: "RevisionNotFound"},
		{name: "missing token revision", method: http.MethodGet, target: "/api/models/owner/model/xet-read-token/missing", status: 404, code: "RevisionNotFound"},
		{name: "missing resolve revision", method: http.MethodGet, target: "/owner/model/resolve/missing/config.json", status: 404, code: "RevisionNotFound"},
		{name: "missing file", method: http.MethodGet, target: "/owner/model/resolve/main/missing.json", status: 404, code: "EntryNotFound"},
		{name: "unsupported tree default", method: http.MethodGet, target: "/api/models/owner/model/tree/main", status: 501},
		{name: "unsupported tree duplicate", method: http.MethodGet, target: "/api/models/owner/model/tree/main?recursive=true&recursive=true&expand=false", status: 501},
		{name: "oversized tree query", method: http.MethodGet, target: "/api/models/owner/model/tree/main?recursive=true&expand=false&" + strings.Repeat("extra=x&", 10_000), status: 400},
		{name: "malformed range", method: http.MethodGet, target: "/owner/model/resolve/main/config.json", headers: map[string]string{"Range": "bytes=bad"}, status: 416},
		{name: "past range", method: http.MethodGet, target: "/owner/model/resolve/main/config.json", headers: map[string]string{"Range": "bytes=99-"}, status: 416},
		{name: "token wrong method", method: http.MethodHead, target: "/api/models/owner/model/xet-read-token/main", status: 405},
		{name: "resolve wrong method", method: http.MethodPost, target: "/owner/model/resolve/main/config.json", status: 405},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(t, fixture.handler, test.method, test.target, "Bearer hub-token", test.headers)
			if response.Code != test.status {
				t.Fatalf("response = %d, %#v, %q", response.Code, response.Header(), response.Body.String())
			}
			if response.Header().Get("X-Error-Code") != test.code {
				t.Fatalf("error code = %q, want %q", response.Header().Get("X-Error-Code"), test.code)
			}
			if test.code == "EntryNotFound" && response.Header().Get("X-Repo-Commit") != fixture.snapshot.OID.String() {
				t.Fatalf("missing-entry commit = %q", response.Header().Get("X-Repo-Commit"))
			}
			if test.status == 416 && response.Header().Get("Content-Range") != "bytes */22" {
				t.Fatalf("range failure headers = %#v", response.Header())
			}
		})
	}
	requestWithDuplicateRange := httptest.NewRequest(http.MethodGet, "/owner/model/resolve/main/config.json", nil)
	requestWithDuplicateRange.Header.Set("Authorization", "Bearer hub-token")
	requestWithDuplicateRange.Header.Add("Range", "bytes=0-1")
	requestWithDuplicateRange.Header.Add("Range", "bytes=2-3")
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, requestWithDuplicateRange)
	if recorder.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("duplicate Range response = %d", recorder.Code)
	}

	limited := newHandlerFixture(t, 1)
	for _, target := range []string{
		"/api/models/owner/model",
		"/api/models/owner/model/tree/main?recursive=true&expand=false",
	} {
		response := request(t, limited.handler, http.MethodGet, target, "Bearer hub-token", nil)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("limited %s = %d, %q", target, response.Code, response.Body.String())
		}
	}
	directoryLimited := newHandlerFixture(t, 2)
	response := request(t, directoryLimited.handler, http.MethodGet, "/api/models/owner/model/tree/main?recursive=true&expand=false", "Bearer hub-token", nil)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("incremental directory limit = %d, %q", response.Code, response.Body.String())
	}
}

func TestRevisionAndTokenBackendFailuresAreClassified(t *testing.T) {
	repo := testRepoKey(t)
	oid, err := model.ParseOID(strings.Repeat("5", 40))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{Repo: repo, OID: oid}
	revision, err := model.ParseRevision("main")
	if err != nil {
		t.Fatal(err)
	}
	rt := route{repo: repo, revision: revision}
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	store := &stubBucket{repository: model.Repository{Key: repo}, snapshot: snapshot, resolveErr: bucket.ErrUnavailable}
	service := &Service{bucket: store}
	recorder := httptest.NewRecorder()
	service.failRevision(recorder, request, repo, bucket.ErrUnavailable)
	if recorder.Code != http.StatusServiceUnavailable || store.calls != 0 {
		t.Fatalf("revision backend failure = %d, calls=%d", recorder.Code, store.calls)
	}

	store.resolveErr = nil
	store.getErr = bucket.ErrNotFound
	recorder = httptest.NewRecorder()
	service.failRevision(recorder, request, repo, bucket.ErrNotFound)
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("X-Error-Code") != "RepoNotFound" || store.calls != 1 {
		t.Fatalf("missing repository classification = %d, %#v, calls=%d", recorder.Code, recorder.Header(), store.calls)
	}

	store.getErr = bucket.ErrUnavailable
	recorder = httptest.NewRecorder()
	service.failRevision(recorder, request, repo, bucket.ErrNotFound)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("X-Error-Code") != "" {
		t.Fatalf("repository backend failure = %d, %#v", recorder.Code, recorder.Header())
	}

	store.getErr = nil
	service.broker = stubBroker{
		issue: func(context.Context, auth.RepositoryGrant, auth.CASPermissions, time.Duration) (auth.IssuedCASToken, error) {
			return auth.IssuedCASToken{}, auth.ErrUnavailable
		},
	}
	recorder = httptest.NewRecorder()
	service.token(recorder, request, rt, auth.RepositoryGrant{}, auth.CASRead, baseURLs{cas: "https://cas.test"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("token backend failure = %d, %q", recorder.Code, recorder.Body.String())
	}
}

type stubBucket struct {
	calls      int
	repository model.Repository
	snapshot   model.Snapshot
	getErr     error
	resolveErr error
	open       func(context.Context, model.RepoKey, model.Revision, model.FilePath, bucket.OpenOptions) (*bucket.FileReader, error)
}

func (stub *stubBucket) GetRepository(context.Context, model.RepoKey) (model.Repository, error) {
	stub.calls++
	return stub.repository, stub.getErr
}
func (stub *stubBucket) ResolveRevision(context.Context, model.RepoKey, model.Revision) (model.Snapshot, error) {
	stub.calls++
	return stub.snapshot, stub.resolveErr
}
func (stub *stubBucket) OpenFile(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
	path model.FilePath,
	options bucket.OpenOptions,
) (*bucket.FileReader, error) {
	stub.calls++
	if stub.open == nil {
		return nil, bucket.ErrNotFound
	}
	return stub.open(ctx, repo, revision, path, options)
}

type stubBroker struct {
	authenticate func(context.Context, string) (auth.Principal, error)
	authorize    func(context.Context, string, model.RepoKey, auth.RepositoryPermission) (auth.RepositoryGrant, error)
	issue        func(context.Context, auth.RepositoryGrant, auth.CASPermissions, time.Duration) (auth.IssuedCASToken, error)
}

func (stub stubBroker) Authenticate(ctx context.Context, credential string) (auth.Principal, error) {
	if stub.authenticate == nil {
		return auth.Principal{Subject: "owner"}, nil
	}
	return stub.authenticate(ctx, credential)
}

func (stub stubBroker) AuthorizeRepository(
	ctx context.Context,
	credential string,
	repo model.RepoKey,
	permission auth.RepositoryPermission,
) (auth.RepositoryGrant, error) {
	return stub.authorize(ctx, credential, repo, permission)
}
func (stub stubBroker) IssueCASTokenForGrant(
	ctx context.Context,
	grant auth.RepositoryGrant,
	permissions auth.CASPermissions,
	ttl time.Duration,
) (auth.IssuedCASToken, error) {
	return stub.issue(ctx, grant, permissions, ttl)
}

func TestHandlerAuthenticationConcealsRepositoriesAndMethods(t *testing.T) {
	repo, err := model.NewRepoKey("owner", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	store := &stubBucket{getErr: bucket.ErrNotFound}
	denied := false
	broker := stubBroker{
		authorize: func(_ context.Context, credential string, got model.RepoKey, permission auth.RepositoryPermission) (auth.RepositoryGrant, error) {
			if credential != "valid" {
				return auth.RepositoryGrant{}, auth.ErrUnauthenticated
			}
			if got != repo || permission != auth.RepositoryRead || denied {
				return auth.RepositoryGrant{}, auth.ErrPermissionDenied
			}
			return auth.RepositoryGrant{}, nil
		},
		issue: func(context.Context, auth.RepositoryGrant, auth.CASPermissions, time.Duration) (auth.IssuedCASToken, error) {
			return auth.IssuedCASToken{}, errors.New("unused")
		},
	}
	handler, err := New(Options{Bucket: store, Broker: broker, HubBaseURL: "https://hub.example", CASBaseURL: "https://cas.example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, credential := range map[string]string{
		"missing": "", "wrong scheme": "Basic valid", "empty": "Bearer ", "space": "Bearer two tokens", "comma": "Bearer value,other",
		"bad token": "Bearer invalid", "oversized": "Bearer " + strings.Repeat("x", 16<<10),
	} {
		t.Run(name, func(t *testing.T) {
			before := store.calls
			response := request(t, handler, http.MethodGet, "/api/models/owner/model", credential, nil)
			if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" || store.calls != before {
				t.Fatalf("response = %d, %#v, calls=%d", response.Code, response.Header(), store.calls-before)
			}
		})
	}
	denied = true
	deniedResponse := request(t, handler, http.MethodGet, "/api/models/owner/model", "Bearer valid", nil)
	if deniedResponse.Code != http.StatusNotFound || deniedResponse.Header().Get("X-Error-Code") != "RepoNotFound" || store.calls != 0 {
		t.Fatalf("denied = %d, calls=%d", deniedResponse.Code, store.calls)
	}
	denied = false
	absentResponse := request(t, handler, http.MethodGet, "/api/models/owner/model", "Bearer valid", nil)
	if absentResponse.Code != http.StatusNotFound || absentResponse.Header().Get("X-Error-Code") != "RepoNotFound" ||
		absentResponse.Body.String() != deniedResponse.Body.String() || store.calls != 1 {
		t.Fatalf("absent = %d, %q, calls=%d; denied body=%q", absentResponse.Code, absentResponse.Body.String(), store.calls, deniedResponse.Body.String())
	}
	methodResponse := request(t, handler, http.MethodPost, "/api/models/owner/model", "Bearer valid", nil)
	if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != "GET" || store.calls != 1 {
		t.Fatalf("method = %d, %#v, calls=%d", methodResponse.Code, methodResponse.Header(), store.calls)
	}
	unknown := request(t, handler, http.MethodGet, "/api/datasets/owner/model", "", nil)
	if unknown.Code != http.StatusNotFound || store.calls != 1 {
		t.Fatalf("unknown = %d, calls=%d", unknown.Code, store.calls)
	}
	invalid := request(t, handler, http.MethodGet, "/api/models/owner%2Fbad/model", "", nil)
	if invalid.Code != http.StatusBadRequest || store.calls != 1 {
		t.Fatalf("invalid route = %d, calls=%d", invalid.Code, store.calls)
	}
}

func TestRouteParsingAndIdentifiers(t *testing.T) {
	tests := []struct {
		path       string
		recognized bool
		wantKind   string
		wantRev    string
		wantFile   string
		wantErr    bool
	}{
		{path: "/api/models/owner/model", recognized: true, wantKind: "model"},
		{path: "/api/models/owner/model/revision/feature%2Ftest", recognized: true, wantKind: "revision", wantRev: "feature/test"},
		{path: "/api/models/owner/model/tree/%252F", recognized: true, wantKind: "tree", wantRev: "%2F"},
		{path: "/owner/model/resolve/main/dir/file%20name.json", recognized: true, wantKind: "resolve", wantRev: "main", wantFile: "dir/file name.json"},
		{path: "/api/datasets/owner/model", recognized: false},
		{path: "api/models/owner/model", recognized: false},
		{path: "/api/models/owner", recognized: false},
		{path: "/api/models/owner/model/unknown/value", recognized: false},
		{path: "/api/models/owner/model/revision/%ZZ", recognized: true, wantErr: true},
		{path: "/api/models/owner/model/revision/%3F", recognized: true, wantErr: true},
		{path: "/api/models/owner%2Fx/model", recognized: true, wantErr: true},
		{path: "/api/models/owner/model/revision/", recognized: true, wantErr: true},
		{path: "/owner/model.git/info/lfs/objects/upload/%ZZ", recognized: true, wantErr: true},
		{path: "/owner/model.git/info/lfs/objects/upload/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", recognized: true, wantErr: true},
		{path: "//model.git/info/lfs/objects/batch", recognized: true, wantErr: true},
		{path: "/owner/.git/info/lfs/objects/batch", recognized: true, wantErr: true},
		{path: "/owner/model/resolve/main", recognized: false},
		{path: "/owner/model/resolve/main/", recognized: true, wantErr: true},
		{path: "/owner/model/resolve/main/dir%2Ffile", recognized: true, wantErr: true},
		{path: "/owner/model/resolve/main/../file", recognized: true, wantErr: true},
		{path: "/owner/model/resolve/main/dir//file", recognized: true, wantErr: true},
		{path: "/api/models/-owner/model", recognized: true, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			route, recognized, err := parseRoute(test.path)
			if recognized != test.recognized || (err != nil) != test.wantErr {
				t.Fatalf("parse = %#v, %v, %v", route, recognized, err)
			}
			if err == nil && recognized && (route.kind != test.wantKind || route.revision.String() != test.wantRev || string(route.file) != test.wantFile) {
				t.Fatalf("route = %#v", route)
			}
		})
	}
	body := []byte("body")
	sum := sha256.Sum256(body)
	blob, err := model.NewBlobFileRef(sum, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk(body)
	xet, err := model.NewXetFileRef(hash, int64(len(body)), nil)
	if err != nil {
		t.Fatal(err)
	}
	oid, _ := model.ParseOID("3333333333333333333333333333333333333333")
	if fileID(blob) != "xet-go:file:sha256:"+hex.EncodeToString(sum[:]) || fileID(xet) != "xet-go:file:xet:"+hash.String() ||
		!strings.HasPrefix(dirID(oid, "nested/path"), "xet-go:dir:"+oid.String()+":") || sameFileRef(blob, xet) {
		t.Fatalf("compatibility identifiers or ref equality are invalid")
	}
	blobCopy, _ := model.NewBlobFileRef(sum, int64(len(body)))
	if !sameFileRef(blob, blobCopy) {
		t.Fatal("identical blob refs differ")
	}
	otherSum := sha256.Sum256([]byte("other"))
	otherBlob, _ := model.NewBlobFileRef(otherSum, int64(len(body)))
	sizedBlob, _ := model.NewBlobFileRef(sum, int64(len(body))+1)
	xetWithSum, _ := model.NewXetFileRef(hash, int64(len(body)), &sum)
	otherXet, _ := model.NewXetFileRef(xethash.Chunk([]byte("other")), int64(len(body)), nil)
	if sameFileRef(blob, otherBlob) || sameFileRef(blob, sizedBlob) || sameFileRef(xet, xetWithSum) || sameFileRef(xet, otherXet) ||
		!sameFileRef(xet, xet) {
		t.Fatal("distinct file refs compare equal")
	}
	recorder := httptest.NewRecorder()
	setFileHeaders(recorder, baseURLs{hub: "https://hub"}, route{repo: testRepoKey(t)}, model.Snapshot{OID: oid}, model.FileEntry{Ref: xet}, int64(len(body)), nil)
	if recorder.Header().Get("ETag") != strconv.Quote(hash.String()) {
		t.Fatalf("SHA-less Xet ETag = %q", recorder.Header().Get("ETag"))
	}
}

func TestRangeParsing(t *testing.T) {
	tests := []struct {
		value string
		size  int64
		want  *content.Range
	}{
		{"bytes=0-0", 10, &content.Range{Start: 0, End: 1}},
		{"bytes=2-", 10, &content.Range{Start: 2, End: 10}},
		{"bytes=2-99", 10, &content.Range{Start: 2, End: 10}},
		{"bytes=-3", 10, &content.Range{Start: 7, End: 10}},
		{"bytes=-99", 10, &content.Range{Start: 0, End: 10}},
	}
	for _, test := range tests {
		got, err := parseRange(test.value, test.size)
		if err != nil || got == nil || *got != *test.want || selectedSize(test.size, got) != test.want.Len() {
			t.Errorf("parseRange(%q,%d) = %#v, %v", test.value, test.size, got, err)
		}
	}
	for _, test := range []struct {
		value string
		size  int64
	}{
		{"", 10}, {"items=0-1", 10}, {"bytes=", 10}, {"bytes=1", 10}, {"bytes=1-2,3-4", 10},
		{"bytes=--", 10}, {"bytes=-0", 10}, {"bytes=-1", 0}, {"bytes=10-", 10}, {"bytes=3-2", 10},
		{"bytes=x-2", 10}, {"bytes=0-x", 10}, {"bytes=9223372036854775808-", 10}, {"bytes=-9223372036854775808", 10},
	} {
		if got, err := parseRange(test.value, test.size); !errors.Is(err, errRange) || got != nil {
			t.Errorf("invalid parseRange(%q,%d) = %#v, %v", test.value, test.size, got, err)
		}
	}
	if selectedSize(10, nil) != 10 {
		t.Fatal("full selected size")
	}
}

func TestConstructorAndErrorMapping(t *testing.T) {
	validBucket := &stubBucket{}
	validBroker := stubBroker{
		authorize: func(context.Context, string, model.RepoKey, auth.RepositoryPermission) (auth.RepositoryGrant, error) {
			return auth.RepositoryGrant{}, nil
		},
		issue: func(context.Context, auth.RepositoryGrant, auth.CASPermissions, time.Duration) (auth.IssuedCASToken, error) {
			return auth.IssuedCASToken{}, nil
		},
	}
	for name, options := range map[string]Options{
		"missing bucket":  {Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas"},
		"missing broker":  {Bucket: validBucket, HubBaseURL: "https://hub", CASBaseURL: "https://cas"},
		"missing hub":     {Bucket: validBucket, Broker: validBroker, CASBaseURL: "https://cas"},
		"missing CAS":     {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub"},
		"relative hub":    {Bucket: validBucket, Broker: validBroker, HubBaseURL: "/hub", CASBaseURL: "https://cas"},
		"FTP CAS":         {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "ftp://cas"},
		"userinfo":        {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://user@hub", CASBaseURL: "https://cas"},
		"query":           {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub?q=1", CASBaseURL: "https://cas"},
		"fragment":        {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub#x", CASBaseURL: "https://cas"},
		"root path":       {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub/", CASBaseURL: "https://cas"},
		"escaped path":    {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub/a%20b", CASBaseURL: "https://cas"},
		"trailing path":   {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub/p/", CASBaseURL: "https://cas"},
		"terminal dot":    {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub/p/.", CASBaseURL: "https://cas"},
		"terminal parent": {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub/p/..", CASBaseURL: "https://cas"},
		"empty component": {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub/p//child", CASBaseURL: "https://cas"},
		"short TTL":       {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", CASTokenTTL: time.Second},
		"fractional TTL":  {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", CASTokenTTL: time.Minute + time.Nanosecond},
		"negative max":    {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxTreeEntries: -1},
		"large threshold": {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", LargeFileThreshold: -1},
		"preupload max":   {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxPreuploadFiles: -1},
		"operation max":   {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxCommitOperations: -1},
		"line max":        {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxCommitLineBytes: -1},
		"metadata max":    {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxCommitMetadata: -1},
		"metadata line":   {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxCommitLineBytes: 2, MaxCommitMetadata: 1},
		"path max":        {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxCommitPathBytes: -1},
		"oversized path":  {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxCommitPathBytes: model.MaxPathBytes + 1},
		"file max":        {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxDeclaredFileBytes: -1},
		"LFS batch max":   {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", MaxLFSBatchObjects: -1},
		"LFS TTL":         {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", LFSUploadTTL: time.Second + time.Nanosecond},
		"LFS key":         {Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "https://cas", LFSUploadCapabilityKey: []byte("short")},
		"function and hub": {
			Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub",
			BaseURLFunc: func(*http.Request) (string, string, error) { return "https://hub", "https://cas", nil },
		},
		"function and CAS": {
			Bucket: validBucket, Broker: validBroker, CASBaseURL: "https://cas",
			BaseURLFunc: func(*http.Request) (string, string, error) { return "https://hub", "https://cas", nil },
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(options); err == nil {
				t.Fatal("expected constructor error")
			}
		})
	}
	conflictOptions := Options{
		Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub",
		BaseURLFunc: func(*http.Request) (string, string, error) { return "https://hub", "https://cas", nil },
	}
	if _, err := New(conflictOptions); err == nil || err.Error() != "hfcompat: base URL function and static base URLs are mutually exclusive" {
		t.Fatalf("base URL source conflict = %v", err)
	}
	for _, test := range []struct {
		name    string
		options Options
		want    string
	}{
		{
			name: "missing Hub", options: Options{Bucket: validBucket, Broker: validBroker, CASBaseURL: "https://cas"},
			want: "hfcompat: hub base URL: must be an absolute HTTP(S) URL without userinfo, query, or fragment",
		},
		{
			name: "missing CAS", options: Options{Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub"},
			want: "hfcompat: CAS base URL: must be an absolute HTTP(S) URL without userinfo, query, or fragment",
		},
		{
			name: "malformed Hub", options: Options{Bucket: validBucket, Broker: validBroker, HubBaseURL: "/hub", CASBaseURL: "https://cas"},
			want: "hfcompat: hub base URL: must be an absolute HTTP(S) URL without userinfo, query, or fragment",
		},
		{
			name: "malformed CAS", options: Options{Bucket: validBucket, Broker: validBroker, HubBaseURL: "https://hub", CASBaseURL: "ftp://cas"},
			want: "hfcompat: CAS base URL: must be an absolute HTTP(S) URL without userinfo, query, or fragment",
		},
	} {
		t.Run("message "+test.name, func(t *testing.T) {
			if _, err := New(test.options); err == nil || err.Error() != test.want {
				t.Fatalf("New error = %v, want %q", err, test.want)
			}
		})
	}
	dynamic, err := New(Options{
		Bucket: validBucket, Broker: validBroker,
		BaseURLFunc: func(*http.Request) (string, string, error) { return "https://hub", "https://cas", nil },
	})
	if err != nil || dynamic.hubURL != "" || dynamic.casURL != "" || dynamic.baseURLFunc == nil {
		t.Fatalf("dynamic constructor = %#v, %v", dynamic, err)
	}
	service, err := New(Options{Bucket: validBucket, Broker: validBroker, HubBaseURL: "http://hub/prefix", CASBaseURL: "https://cas/prefix"})
	if err != nil || service.Handler() != service || service.ttl != defaultTokenTTL || service.max != defaultTreeMax ||
		service.large != defaultLargeFileThreshold || service.preuploadMax != defaultPreuploadMax ||
		service.commitOps != defaultCommitOperations || service.lineBytes != defaultCommitLineBytes ||
		service.metadata != defaultCommitMetadata || service.pathBytes != model.MaxPathBytes ||
		service.fileBytes != defaultCommitFileSize || service.lfsBatch != defaultLFSBatchMax || service.lfsTTL != defaultLFSUploadTTL {
		t.Fatalf("valid constructor = %#v, %v", service, err)
	}

	errorsToStatus := []struct {
		err    error
		status int
	}{
		{auth.ErrUnauthenticated, 401}, {auth.ErrPermissionDenied, 404}, {bucket.ErrNotFound, 404},
		{errRange, 416}, {bucket.ErrRangeNotSatisfiable, 416}, {errTreeLimit, 413}, {errCommitTooLarge, 413}, {errInput, 400},
		{bucket.ErrInvalid, 400}, {auth.ErrInvalid, 400}, {bucket.ErrUnsupported, 501}, {bucket.ErrConflict, 409},
		{bucket.ErrContentNotUploaded, 422},
		{bucket.ErrUnavailable, 503}, {auth.ErrUnavailable, 503}, {context.Canceled, 503}, {context.DeadlineExceeded, 504},
		{bucket.ErrCorrupt, 500}, {bucket.ErrInvariant, 500}, {bucket.ErrUnauthenticated, 500}, {bucket.ErrPermissionDenied, 500}, {errors.New("unknown"), 500},
	}
	for _, test := range errorsToStatus {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		service.fail(recorder, req, test.err)
		if recorder.Code != test.status || strings.Contains(recorder.Body.String(), test.err.Error()) {
			t.Errorf("error %v = %d, %q; want %d", test.err, recorder.Code, recorder.Body.String(), test.status)
		}
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	service.fail(recorder, req, bucket.ErrNotFound)
	if recorder.Code != http.StatusNotFound || recorder.Body.Len() != 0 {
		t.Fatalf("HEAD failure = %d, %q", recorder.Code, recorder.Body.String())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	recorder = httptest.NewRecorder()
	service.fail(recorder, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(canceled), context.Canceled)
	if recorder.Body.Len() != 0 {
		t.Fatalf("canceled request response = %q", recorder.Body.String())
	}
	service.json(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), make(chan int))
}

type trackingBody struct {
	reader io.Reader
	err    error
	closed int
}

func (body *trackingBody) Read(buffer []byte) (int, error) {
	if body.reader != nil {
		return body.reader.Read(buffer)
	}
	return 0, body.err
}
func (body *trackingBody) Close() error { body.closed++; return body.err }

type partialErrorReader struct {
	written bool
	err     error
}

func (reader *partialErrorReader) Read(buffer []byte) (int, error) {
	if reader.written {
		return 0, reader.err
	}
	reader.written = true
	buffer[0] = 'b'
	return 1, reader.err
}

type streamStep struct {
	data []byte
	err  error
}

type scriptedStream struct {
	steps    []streamStep
	closeErr error
	closed   int
}

func (stream *scriptedStream) Read(buffer []byte) (int, error) {
	if len(stream.steps) == 0 {
		return 0, io.EOF
	}
	step := stream.steps[0]
	stream.steps = stream.steps[1:]
	if len(step.data) > len(buffer) {
		panic("scripted stream step exceeds buffer")
	}
	return copy(buffer, step.data), step.err
}

func (stream *scriptedStream) Close() error {
	stream.closed++
	return stream.closeErr
}

func TestStreamFileSettlesBoundedDataAndExposesFailures(t *testing.T) {
	failure := errors.New("stream failure")
	noProgress := make([]streamStep, 100)
	tests := []struct {
		name          string
		stream        *scriptedStream
		size          int64
		wantCommitted bool
		wantBody      string
		wantError     bool
	}{
		{name: "empty", stream: &scriptedStream{steps: []streamStep{{err: io.EOF}}}, wantCommitted: true},
		{name: "single read EOF", stream: &scriptedStream{steps: []streamStep{{data: []byte("body"), err: io.EOF}}}, size: 4, wantCommitted: true, wantBody: "body"},
		{name: "single read then EOF", stream: &scriptedStream{steps: []streamStep{{data: []byte("body")}, {err: io.EOF}}}, size: 4, wantCommitted: true, wantBody: "body"},
		{name: "first read error", stream: &scriptedStream{steps: []streamStep{{data: []byte("b"), err: failure}}}, size: 4, wantError: true},
		{name: "short stream", stream: &scriptedStream{steps: []streamStep{{data: []byte("ab")}, {err: io.EOF}}}, size: 4, wantError: true},
		{name: "long stream", stream: &scriptedStream{steps: []streamStep{{data: []byte("abc")}}}, size: 2, wantError: true},
		{name: "close failure", stream: &scriptedStream{steps: []streamStep{{data: []byte("body")}, {err: io.EOF}}, closeErr: failure}, size: 4, wantError: true},
		{name: "no progress", stream: &scriptedStream{steps: noProgress}, size: 1, wantError: true},
		{
			name: "error after commitment",
			stream: &scriptedStream{steps: []streamStep{
				{data: bytes.Repeat([]byte{'a'}, 64<<10)},
				{data: bytes.Repeat([]byte{'b'}, 64<<10)},
				{data: []byte("c"), err: failure},
			}},
			size: 2*(64<<10) + 1, wantCommitted: true,
			wantBody: strings.Repeat("a", 64<<10), wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var destination bytes.Buffer
			commits := 0
			committed, err := streamFile(&destination, test.stream, test.size, func() { commits++ })
			wantCommits := 0
			if test.wantCommitted {
				wantCommits = 1
			}
			if committed != test.wantCommitted || (err != nil) != test.wantError || destination.String() != test.wantBody ||
				test.stream.closed != 1 || commits != wantCommits {
				t.Fatalf(
					"stream = committed %v, err %v, body length %d, closes %d, commits %d",
					committed, err, destination.Len(), test.stream.closed, commits,
				)
			}
		})
	}
	large := bytes.Repeat([]byte("large verified stream"), 8_000)
	stream := &trackingBody{reader: bytes.NewReader(large)}
	var destination bytes.Buffer
	commits := 0
	committed, err := streamFile(&destination, stream, int64(len(large)), func() { commits++ })
	if err != nil || !committed || commits != 1 || stream.closed != 1 || !bytes.Equal(destination.Bytes(), large) {
		t.Fatalf("large stream = committed %v, err %v, bytes %d, closes %d, commits %d", committed, err, destination.Len(), stream.closed, commits)
	}
	if committed, err = streamFile(nil, stream, 0, func() {}); committed || !errors.Is(err, bucket.ErrInvariant) {
		t.Fatalf("invalid stream arguments = %v, %v", committed, err)
	}
	for name, destination := range map[string]io.Writer{
		"invalid count": writerFunc(func(value []byte) (int, error) { return len(value) + 1, nil }),
		"no progress":   writerFunc(func([]byte) (int, error) { return 0, nil }),
		"write failure": writerFunc(func([]byte) (int, error) { return 0, failure }),
	} {
		t.Run("destination "+name, func(t *testing.T) {
			body := &scriptedStream{steps: []streamStep{{data: []byte("body"), err: io.EOF}}}
			committed, err := streamFile(destination, body, 4, func() {})
			if !committed || err == nil || body.closed != 1 {
				t.Fatalf("committed=%v err=%v closes=%d", committed, err, body.closed)
			}
		})
	}
}

type writerFunc func([]byte) (int, error)

func (function writerFunc) Write(value []byte) (int, error) { return function(value) }

func TestResolveRejectsInconsistentStreamsAndClosesBodies(t *testing.T) {
	repo, _ := model.NewRepoKey("owner", "model", model.RepoTypeModel)
	sum := sha256.Sum256([]byte("body"))
	ref, _ := model.NewBlobFileRef(sum, 4)
	oid, _ := model.ParseOID("4444444444444444444444444444444444444444")
	entry := model.FileEntry{Path: "file.bin", Ref: ref}
	snapshot := model.Snapshot{Repo: repo, OID: oid, Files: []model.FileEntry{entry}}
	rt, _, err := parseRoute("/owner/model/resolve/main/file.bin")
	if err != nil {
		t.Fatal(err)
	}
	pinned, _ := model.RevisionFromOID(oid)
	_ = pinned
	for name, result := range map[string]func(*trackingBody) *bucket.FileReader{
		"nil":      func(*trackingBody) *bucket.FileReader { return nil },
		"nil body": func(*trackingBody) *bucket.FileReader { return &bucket.FileReader{} },
		"size": func(body *trackingBody) *bucket.FileReader {
			return &bucket.FileReader{Entry: entry, FileSize: 5, Range: content.Range{End: 4}, Size: 4, Body: body}
		},
		"path": func(body *trackingBody) *bucket.FileReader {
			wrong := entry
			wrong.Path = "wrong"
			return &bucket.FileReader{Entry: wrong, FileSize: 4, Range: content.Range{End: 4}, Size: 4, Body: body}
		},
		"range": func(body *trackingBody) *bucket.FileReader {
			return &bucket.FileReader{Entry: entry, FileSize: 4, Range: content.Range{Start: 1, End: 4}, Size: 3, Body: body}
		},
		"selected size": func(body *trackingBody) *bucket.FileReader {
			return &bucket.FileReader{Entry: entry, FileSize: 4, Range: content.Range{End: 4}, Size: 3, Body: body}
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := &trackingBody{reader: bytes.NewReader([]byte("body"))}
			store := &stubBucket{snapshot: snapshot, open: func(context.Context, model.RepoKey, model.Revision, model.FilePath, bucket.OpenOptions) (*bucket.FileReader, error) {
				return result(body), nil
			}}
			service := &Service{bucket: store, hubURL: "https://hub"}
			recorder := httptest.NewRecorder()
			service.resolve(recorder, httptest.NewRequest(http.MethodGet, "/owner/model/resolve/main/file.bin", nil), rt, baseURLs{hub: service.hubURL})
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, %q", recorder.Code, recorder.Body.String())
			}
			if name != "nil" && name != "nil body" && body.closed != 1 {
				t.Fatalf("body closes = %d", body.closed)
			}
		})
	}
	readFailure := errors.New("read failed")
	body := &trackingBody{err: readFailure}
	store := &stubBucket{snapshot: snapshot, open: func(context.Context, model.RepoKey, model.Revision, model.FilePath, bucket.OpenOptions) (*bucket.FileReader, error) {
		return &bucket.FileReader{Entry: entry, FileSize: 4, Range: content.Range{End: 4}, Size: 4, Body: body}, nil
	}}
	service := &Service{bucket: store, hubURL: "https://hub"}
	recorder := httptest.NewRecorder()
	service.resolve(recorder, httptest.NewRequest(http.MethodGet, "/owner/model/resolve/main/file.bin", nil), rt, baseURLs{hub: service.hubURL})
	if recorder.Code != http.StatusInternalServerError || body.closed != 1 {
		t.Fatalf("midstream failure = %d, %q, closes=%d", recorder.Code, recorder.Body.String(), body.closed)
	}
	partialBody := &trackingBody{reader: &partialErrorReader{err: readFailure}}
	store.open = func(context.Context, model.RepoKey, model.Revision, model.FilePath, bucket.OpenOptions) (*bucket.FileReader, error) {
		return &bucket.FileReader{Entry: entry, FileSize: 4, Range: content.Range{End: 4}, Size: 4, Body: partialBody}, nil
	}
	recorder = httptest.NewRecorder()
	service.resolve(recorder, httptest.NewRequest(http.MethodGet, "/owner/model/resolve/main/file.bin", nil), rt, baseURLs{hub: service.hubURL})
	if recorder.Code != http.StatusInternalServerError || partialBody.closed != 1 ||
		!strings.Contains(recorder.Body.String(), "Internal Server Error") {
		t.Fatalf("first-read stream failure = %d, %q, closes=%d", recorder.Code, recorder.Body.String(), partialBody.closed)
	}
	store.open = func(context.Context, model.RepoKey, model.Revision, model.FilePath, bucket.OpenOptions) (*bucket.FileReader, error) {
		return nil, bucket.ErrUnavailable
	}
	recorder = httptest.NewRecorder()
	service.resolve(recorder, httptest.NewRequest(http.MethodGet, "/owner/model/resolve/main/file.bin", nil), rt, baseURLs{hub: service.hubURL})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("open backend failure = %d, %q", recorder.Code, recorder.Body.String())
	}
}
