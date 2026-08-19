package hfcompat

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
)

const (
	defaultTokenTTL           = 15 * time.Minute
	defaultTreeMax            = 10_000
	defaultLargeFileThreshold = 10 << 20
	defaultPreuploadMax       = 256
	defaultCommitOperations   = 25_000
	defaultCommitLineBytes    = 16 << 20
	defaultCommitMetadata     = 1 << 30
	defaultCommitFileSize     = 1 << 50
	defaultLFSBatchMax        = 256
	defaultLFSUploadTTL       = 15 * time.Minute
)

// BucketService is also the supported host revision-resolution extension
// point. A decorator may redefine mutable and explicit-OID visibility through
// ResolveRevision; resolve handlers pin OpenFile to the returned immutable OID.
type BucketService interface {
	GetRepository(context.Context, model.RepoKey) (model.Repository, error)
	ResolveRevision(context.Context, model.RepoKey, model.Revision) (model.Snapshot, error)
	OpenFile(context.Context, model.RepoKey, model.Revision, model.FilePath, bucket.OpenOptions) (*bucket.FileReader, error)
}

type AccessBroker interface {
	Authenticate(context.Context, string) (auth.Principal, error)
	AuthorizeRepository(context.Context, string, model.RepoKey, auth.RepositoryPermission) (auth.RepositoryGrant, error)
	IssueCASTokenForGrant(context.Context, auth.RepositoryGrant, auth.CASPermissions, time.Duration) (auth.IssuedCASToken, error)
}

type RepositoryWriter interface {
	CreateRepository(context.Context, model.Repository) error
	PutBlob(context.Context, content.Blob, io.Reader) (bool, error)
	ResolveXetFile(context.Context, model.RepoKey, [32]byte, uint64) (xethash.Hash, error)
}

// SnapshotReader retrieves a durable prepared intent or retained immutable
// state by OID. It lets retries reuse the exact canonical snapshot after an
// ambiguous result, including failures before catalog publication.
type SnapshotReader interface {
	GetSnapshot(context.Context, model.RepoKey, model.OID) (model.Snapshot, error)
}

// XetFileIngester streams one verified legacy-LFS object into the repository's
// hosting-neutral Xet namespace. Implementations must return only after the
// file is reconstructable. The Hub/LFS protocol remains owned by hfcompat.
type XetFileIngester interface {
	IngestXetFile(context.Context, model.RepoKey, io.Reader) (XetFileIngestResult, error)
}

type XetFileIngestResult struct {
	Hash   xethash.Hash
	Size   uint64
	SHA256 [32]byte
}

// WriteAuditEvent is the non-secret outcome of one recognized Hub write
// operation. StatusCode is the HTTP status returned to the caller.
type WriteAuditEvent struct {
	Principal     auth.Principal
	Repository    model.RepoKey
	Operation     string
	StatusCode    int
	CorrelationID string
}

// WriteAuditSink observes completed Hub write operations. Implementations must
// return promptly; recording cannot alter a response that has already begun.
type WriteAuditSink interface {
	RecordHubWrite(context.Context, WriteAuditEvent)
}

// SnapshotPublisher publishes one canonical immutable snapshot. hfcompat calls
// it exactly once per non-replayed commit after content verification.
// Implementers may compose additional durable host work with publication.
//
// An ambiguous result must be retried with the same OID, canonical snapshot,
// ref target, and old-OID expectation. Never allocate a replacement OID.
type SnapshotPublisher interface {
	PublishSnapshot(context.Context, model.Snapshot, catalog.RefExpectation) error
}

type Options struct {
	Bucket    BucketService
	Writer    RepositoryWriter
	Snapshots SnapshotReader
	Publisher SnapshotPublisher
	Ingester  XetFileIngester
	Audit     WriteAuditSink
	Broker    AccessBroker

	HubBaseURL string
	CASBaseURL string
	// BaseURLFunc derives the Hub and CAS base URLs for one request. It is called
	// at most once per request, before any absolute URL is emitted, and its results
	// are reused for every URL in that response.
	//
	// Both returned values must satisfy the same rules as HubBaseURL and
	// CASBaseURL: an absolute http or https URL, no userinfo, no query, no
	// fragment, and a canonical non-trailing path. A returned value that fails
	// validation fails the request; it is never emitted.
	//
	// When BaseURLFunc is non-nil it is authoritative and HubBaseURL and
	// CASBaseURL must be empty. When it is nil the static fields are required.
	//
	// Implementations must not derive a URL from request headers unless the
	// embedder trusts its proxy layer to set them. Returned URLs must remain
	// routable for as long as client-followed refresh and upload links are useful.
	BaseURLFunc func(*http.Request) (hub string, cas string, err error)
	CASTokenTTL time.Duration

	MaxTreeEntries       int
	LargeFileThreshold   int64
	MaxPreuploadFiles    int
	MaxCommitOperations  int
	MaxCommitLineBytes   int
	MaxCommitMetadata    int64
	MaxCommitPathBytes   int
	MaxDeclaredFileBytes int64
	MaxLFSBatchObjects   int
	LFSUploadTTL         time.Duration
	// LFSUploadCapabilityKey is a shared 32-byte HMAC key. Configure the same
	// key on every instance that may receive an upload action; nil selects an
	// ephemeral single-instance key.
	LFSUploadCapabilityKey []byte
}

type Service struct {
	bucket       BucketService
	writer       RepositoryWriter
	snapshots    SnapshotReader
	publisher    SnapshotPublisher
	ingester     XetFileIngester
	audit        WriteAuditSink
	broker       AccessBroker
	hubURL       string
	casURL       string
	baseURLFunc  func(*http.Request) (hub string, cas string, err error)
	ttl          time.Duration
	max          int
	large        int64
	preuploadMax int
	commitOps    int
	lineBytes    int
	metadata     int64
	pathBytes    int
	fileBytes    int64
	lfsBatch     int
	lfsTTL       time.Duration
	lfsKey       [32]byte
	lfsMu        sync.Mutex
	lfsUploads   map[string]lfsUploadState
	now          func() time.Time
	commits      [256]sync.Mutex
}

var _ http.Handler = (*Service)(nil)

func New(o Options) (*Service, error) {
	if o.Bucket == nil || o.Broker == nil {
		return nil, fmt.Errorf("hfcompat: bucket and broker are required")
	}
	var hub, cas string
	if o.BaseURLFunc == nil {
		var err error
		hub, err = baseURL(o.HubBaseURL)
		if err != nil {
			return nil, fmt.Errorf("hfcompat: hub base URL: %w", err)
		}
		cas, err = baseURL(o.CASBaseURL)
		if err != nil {
			return nil, fmt.Errorf("hfcompat: CAS base URL: %w", err)
		}
	} else if o.HubBaseURL != "" || o.CASBaseURL != "" {
		return nil, fmt.Errorf("hfcompat: base URL function and static base URLs are mutually exclusive")
	}
	if o.CASTokenTTL == 0 {
		o.CASTokenTTL = defaultTokenTTL
	}
	if o.CASTokenTTL < time.Minute || o.CASTokenTTL%time.Second != 0 {
		return nil, fmt.Errorf("hfcompat: CAS token TTL must be whole seconds and at least 60 seconds")
	}
	if o.MaxTreeEntries == 0 {
		o.MaxTreeEntries = defaultTreeMax
	}
	if o.MaxTreeEntries < 1 {
		return nil, fmt.Errorf("hfcompat: maximum tree entries must be positive")
	}
	if o.LargeFileThreshold == 0 {
		o.LargeFileThreshold = defaultLargeFileThreshold
	}
	if o.MaxPreuploadFiles == 0 {
		o.MaxPreuploadFiles = defaultPreuploadMax
	}
	if o.MaxCommitOperations == 0 {
		o.MaxCommitOperations = defaultCommitOperations
	}
	if o.MaxCommitLineBytes == 0 {
		o.MaxCommitLineBytes = defaultCommitLineBytes
	}
	if o.MaxCommitMetadata == 0 {
		o.MaxCommitMetadata = defaultCommitMetadata
	}
	if o.MaxCommitPathBytes == 0 {
		o.MaxCommitPathBytes = model.MaxPathBytes
	}
	if o.MaxDeclaredFileBytes == 0 {
		o.MaxDeclaredFileBytes = defaultCommitFileSize
	}
	if o.MaxLFSBatchObjects == 0 {
		o.MaxLFSBatchObjects = defaultLFSBatchMax
	}
	if o.LFSUploadTTL == 0 {
		o.LFSUploadTTL = defaultLFSUploadTTL
	}
	if o.LargeFileThreshold < 1 || o.MaxPreuploadFiles < 1 || o.MaxCommitOperations < 1 || o.MaxCommitLineBytes < 1 ||
		o.MaxCommitMetadata < int64(o.MaxCommitLineBytes) || o.MaxCommitPathBytes < 1 || o.MaxCommitPathBytes > model.MaxPathBytes ||
		o.MaxDeclaredFileBytes < 0 || o.MaxLFSBatchObjects < 1 || o.LFSUploadTTL < time.Second || o.LFSUploadTTL%time.Second != 0 {
		return nil, fmt.Errorf("hfcompat: invalid write admission limits")
	}
	if len(o.LFSUploadCapabilityKey) != 0 && len(o.LFSUploadCapabilityKey) != len(Service{}.lfsKey) {
		return nil, fmt.Errorf("hfcompat: LFS upload capability key must be 32 bytes")
	}
	if o.Writer == nil {
		o.Writer, _ = o.Bucket.(RepositoryWriter)
	}
	if o.Snapshots == nil {
		o.Snapshots, _ = o.Writer.(SnapshotReader)
	}
	if o.Snapshots == nil {
		o.Snapshots, _ = o.Bucket.(SnapshotReader)
	}
	if o.Publisher == nil && o.Writer != nil {
		o.Publisher, _ = o.Writer.(SnapshotPublisher)
	}
	service := &Service{
		bucket: o.Bucket, writer: o.Writer, snapshots: o.Snapshots, publisher: o.Publisher,
		ingester: o.Ingester, audit: o.Audit, broker: o.Broker,
		hubURL: hub, casURL: cas, baseURLFunc: o.BaseURLFunc, ttl: o.CASTokenTTL, max: o.MaxTreeEntries,
		large: o.LargeFileThreshold, preuploadMax: o.MaxPreuploadFiles,
		commitOps: o.MaxCommitOperations, lineBytes: o.MaxCommitLineBytes, metadata: o.MaxCommitMetadata,
		pathBytes: o.MaxCommitPathBytes, fileBytes: o.MaxDeclaredFileBytes,
		lfsBatch: o.MaxLFSBatchObjects, lfsTTL: o.LFSUploadTTL, lfsUploads: make(map[string]lfsUploadState),
		now: time.Now,
	}
	if o.Ingester != nil {
		if len(o.LFSUploadCapabilityKey) != 0 {
			copy(service.lfsKey[:], o.LFSUploadCapabilityKey)
		} else if _, err := rand.Read(service.lfsKey[:]); err != nil {
			return nil, fmt.Errorf("hfcompat: initialize LFS upload capabilities: %w", err)
		}
	}
	return service, nil
}

func baseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must be an absolute HTTP(S) URL without userinfo, query, or fragment")
	}
	if u.Path != "" && (u.Path == "/" || strings.HasSuffix(u.Path, "/") || u.EscapedPath() != u.Path ||
		strings.ContainsAny(u.Path, "\\\x00\r\n") || strings.Contains(u.Path, "/./") || strings.Contains(u.Path, "/../")) {
		return "", errors.New("base path must be canonical and nontrailing")
	}
	for _, component := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if u.Path != "" && (component == "" || component == "." || component == "..") {
			return "", errors.New("base path must not contain empty or dot components")
		}
	}
	return u.String(), nil
}

func (s *Service) Handler() http.Handler { return s }

type baseURLs struct {
	hub string
	cas string
}

func (s *Service) resolveBaseURLs(r *http.Request) (baseURLs, error) {
	if s.baseURLFunc == nil {
		return baseURLs{hub: s.hubURL, cas: s.casURL}, nil
	}
	hubValue, casValue, err := s.baseURLFunc(r)
	if err != nil {
		return baseURLs{}, fmt.Errorf("hfcompat: derive base URLs: %w", err)
	}
	hub, err := baseURL(hubValue)
	if err != nil {
		return baseURLs{}, fmt.Errorf("hfcompat: hub base URL: %w", err)
	}
	cas, err := baseURL(casValue)
	if err != nil {
		return baseURLs{}, fmt.Errorf("hfcompat: CAS base URL: %w", err)
	}
	return baseURLs{hub: hub, cas: cas}, nil
}

func routeEmitsAbsoluteURL(kind string) bool {
	switch kind {
	case "commit", "lfs-batch", "read-token", "write-token", "resolve":
		return true
	default:
		return false
	}
}

func (s *Service) failBaseURLResolution(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("hfcompat: request base URL resolution failed: %v", err)
	s.failStatus(w, r, http.StatusInternalServerError)
}

type route struct {
	kind       string
	repo       model.RepoKey
	revision   model.Revision
	file       model.FilePath
	lfsOID     [32]byte
	permission auth.RepositoryPermission
	methods    []string
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	correlationID := requestCorrelationID(r.Header.Get("X-Request-Id"))
	w.Header().Set("X-Request-Id", correlationID)
	rt, recognized, err := parseRoute(r.URL.EscapedPath())
	if !recognized {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, fmt.Errorf("%w: invalid route", errInput))
		return
	}
	var auditEvent *WriteAuditEvent
	if s.audit != nil && isWriteOperation(rt.kind) {
		event := WriteAuditEvent{Repository: rt.repo, Operation: rt.kind, CorrelationID: correlationID}
		auditEvent = &event
		tracked := &auditResponseWriter{ResponseWriter: w}
		w = tracked
		defer func() {
			event.StatusCode = tracked.statusCode()
			s.audit.RecordHubWrite(context.WithoutCancel(r.Context()), event)
		}()
	}
	if rt.kind == "lfs-upload" {
		if !allowsMethod(rt.methods, r.Method) {
			w.Header().Set("Allow", strings.Join(rt.methods, ", "))
			s.failStatus(w, r, http.StatusMethodNotAllowed)
			return
		}
		s.lfsUpload(w, r, rt, auditEvent)
		return
	}
	credential, err := bearer(r.Header.Values("Authorization"))
	if err != nil {
		s.fail(w, r, auth.ErrUnauthenticated)
		return
	}
	var grant auth.RepositoryGrant
	var principal auth.Principal
	if rt.permission == "" {
		principal, err = s.broker.Authenticate(r.Context(), credential)
	} else {
		grant, err = s.broker.AuthorizeRepository(r.Context(), credential, rt.repo, rt.permission)
		principal = grant.Principal()
		if errors.Is(err, auth.ErrPermissionDenied) {
			w.Header().Set("X-Error-Code", "RepoNotFound")
		}
	}
	if auditEvent != nil {
		auditEvent.Principal = principal
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !allowsMethod(rt.methods, r.Method) {
		w.Header().Set("Allow", strings.Join(rt.methods, ", "))
		s.failStatus(w, r, http.StatusMethodNotAllowed)
		return
	}
	var bases baseURLs
	if routeEmitsAbsoluteURL(rt.kind) {
		bases, err = s.resolveBaseURLs(r)
		if err != nil {
			s.failBaseURLResolution(w, r, err)
			return
		}
	}
	switch rt.kind {
	case "whoami":
		s.whoami(w, r, principal)
	case "create":
		s.createRepository(w, r, credential, principal, auditEvent)
	case "preupload":
		s.preupload(w, r, rt)
	case "commit":
		s.commit(w, r, rt, principal, bases)
	case "lfs-batch":
		s.lfsBatchRequest(w, r, rt, principal, bases)
	case "model":
		s.modelInfo(w, r, rt, "main")
	case "revision":
		s.modelInfo(w, r, rt, rt.revision.String())
	case "tree":
		s.tree(w, r, rt)
	case "read-token":
		s.token(w, r, rt, grant, auth.CASRead, bases)
	case "write-token":
		s.token(w, r, rt, grant, auth.CASWrite, bases)
	case "resolve":
		s.resolve(w, r, rt, bases)
	}
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *auditResponseWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *auditResponseWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *auditResponseWriter) statusCode() int {
	if writer.status == 0 {
		return http.StatusOK
	}
	return writer.status
}

func isWriteOperation(kind string) bool {
	switch kind {
	case "create", "preupload", "commit", "write-token", "lfs-batch", "lfs-upload":
		return true
	default:
		return false
	}
}

func requestCorrelationID(value string) string {
	if value != "" && len(value) <= 128 && !strings.ContainsAny(value, " \t\r\n,;") {
		return value
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return "unavailable"
}

func allowsMethod(methods []string, method string) bool {
	for _, allowed := range methods {
		if method == allowed {
			return true
		}
	}
	return false
}

func bearer(values []string) (string, error) {
	if len(values) != 1 {
		return "", auth.ErrUnauthenticated
	}
	v := values[0]
	separator := strings.IndexByte(v, ' ')
	if separator < 0 || !strings.EqualFold(v[:separator], "Bearer") || separator != 6 || len(v) == 7 ||
		len(v) > 16<<10 || strings.ContainsAny(v[7:], " \t\r\n,") {
		return "", auth.ErrUnauthenticated
	}
	return v[7:], nil
}

func parseRoute(escaped string) (route, bool, error) {
	if escaped == "" || escaped[0] != '/' {
		return route{}, false, nil
	}
	if escaped == "/api/whoami-v2" {
		return route{kind: "whoami", methods: []string{http.MethodGet}}, true, nil
	}
	if escaped == "/api/repos/create" {
		return route{kind: "create", methods: []string{http.MethodPost}}, true, nil
	}
	raw := strings.Split(escaped[1:], "/")
	api := len(raw) >= 3 && raw[0] == "api" && raw[1] == "models"
	start := 0
	if api {
		start = 2
	}
	if len(raw) < start+2 {
		return route{}, false, nil
	}
	// Recognition is structural and precedes decoding/authentication.
	kind := ""
	if api {
		switch {
		case len(raw) == start+2:
			kind = "model"
		case len(raw) == start+4 && raw[start+2] == "revision":
			kind = "revision"
		case len(raw) == start+4 && raw[start+2] == "tree":
			kind = "tree"
		case len(raw) == start+4 && raw[start+2] == "xet-read-token":
			kind = "read-token"
		case len(raw) == start+4 && raw[start+2] == "xet-write-token":
			kind = "write-token"
		case len(raw) == start+4 && raw[start+2] == "preupload":
			kind = "preupload"
		case len(raw) == start+4 && raw[start+2] == "commit":
			kind = "commit"
		default:
			return route{}, false, nil
		}
	} else if len(raw) == 6 && strings.HasSuffix(raw[1], ".git") && raw[2] == "info" && raw[3] == "lfs" && raw[4] == "objects" && raw[5] == "batch" {
		kind = "lfs-batch"
		raw[1] = strings.TrimSuffix(raw[1], ".git")
	} else if len(raw) == 7 && strings.HasSuffix(raw[1], ".git") && raw[2] == "info" && raw[3] == "lfs" && raw[4] == "objects" && raw[5] == "upload" {
		kind = "lfs-upload"
		raw[1] = strings.TrimSuffix(raw[1], ".git")
	} else if len(raw) >= 5 && raw[2] == "resolve" {
		kind = "resolve"
	} else {
		return route{}, false, nil
	}
	decode := func(x string, slash bool) (string, error) {
		if x == "" {
			return "", errors.New("empty path component")
		}
		v, e := url.PathUnescape(x)
		if e != nil || (!slash && strings.Contains(v, "/")) {
			return "", errors.New("invalid escaped component")
		}
		return v, e
	}
	ns, e := decode(raw[start], false)
	if e != nil {
		return route{}, true, e
	}
	name, e := decode(raw[start+1], false)
	if e != nil {
		return route{}, true, e
	}
	repo, e := model.NewRepoKey(ns, name, model.RepoTypeModel)
	if e != nil {
		return route{}, true, e
	}
	rt := route{kind: kind, repo: repo, permission: auth.RepositoryRead, methods: []string{http.MethodGet}}
	if kind == "lfs-batch" {
		rt.permission = auth.RepositoryWrite
		rt.methods = []string{http.MethodPost}
		return rt, true, nil
	}
	if kind == "lfs-upload" {
		rt.permission = ""
		rt.methods = []string{http.MethodPut}
		decoded, decodeErr := decode(raw[6], false)
		if decodeErr != nil {
			return route{}, true, decodeErr
		}
		value, decodeErr := hex.DecodeString(decoded)
		if decodeErr != nil || len(value) != len(rt.lfsOID) || decoded != strings.ToLower(decoded) {
			return route{}, true, errors.New("invalid LFS object OID")
		}
		copy(rt.lfsOID[:], value)
		return rt, true, nil
	}
	if kind == "resolve" {
		rt.methods = []string{http.MethodGet, http.MethodHead}
	}
	if kind == "write-token" {
		rt.permission = auth.RepositoryWrite
	}
	if kind == "preupload" || kind == "commit" {
		rt.permission = auth.RepositoryWrite
		rt.methods = []string{http.MethodPost}
	}
	if kind != "model" {
		revIndex := start + 3
		if !api {
			revIndex = 3
		}
		revText, e := decode(raw[revIndex], true)
		if e != nil {
			return route{}, true, e
		}
		rt.revision, e = model.ParseRevision(revText)
		if e != nil {
			return route{}, true, e
		}
	}
	if kind == "resolve" {
		parts := make([]string, 0, len(raw)-4)
		for _, part := range raw[4:] {
			v, e := decode(part, false)
			if e != nil {
				return route{}, true, e
			}
			parts = append(parts, v)
		}
		if len(parts) == 0 {
			return route{}, true, errors.New("missing file")
		}
		rt.file, e = model.ParseFilePath(strings.Join(parts, "/"))
		if e != nil {
			return route{}, true, e
		}
	}
	return rt, true, nil
}

type siblingDTO struct {
	Filename string `json:"rfilename"`
	Size     int64  `json:"size"`
	BlobID   string `json:"blobId"`
}
type modelDTO struct {
	ID           string       `json:"id"`
	ModelID      string       `json:"modelId"`
	Author       string       `json:"author"`
	SHA          string       `json:"sha"`
	CreatedAt    time.Time    `json:"createdAt"`
	LastModified time.Time    `json:"lastModified"`
	Siblings     []siblingDTO `json:"siblings"`
}

func (s *Service) modelInfo(w http.ResponseWriter, r *http.Request, rt route, rev string) {
	repo, err := s.bucket.GetRepository(r.Context(), rt.repo)
	if err != nil {
		s.failNotFound(w, r, err, "RepoNotFound")
		return
	}
	revision, err := model.ParseRevision(rev)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	snap, err := s.bucket.ResolveRevision(r.Context(), rt.repo, revision)
	if err != nil {
		s.failNotFound(w, r, err, "RevisionNotFound")
		return
	}
	if len(snap.Files) > s.max {
		s.fail(w, r, errTreeLimit)
		return
	}
	items := make([]siblingDTO, len(snap.Files))
	for i, f := range snap.Files {
		items[i] = siblingDTO{string(f.Path), f.Ref.FileSize(), fileID(f.Ref)}
	}
	id := string(rt.repo.Namespace) + "/" + string(rt.repo.Name)
	s.json(w, r, modelDTO{id, id, string(rt.repo.Namespace), snap.OID.String(), repo.CreatedAt, snap.CreatedAt, items})
}

type treeDTO struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	OID     string `json:"oid"`
	XetHash string `json:"xetHash,omitempty"`
}

var errTreeLimit = errors.New("hfcompat: tree limit exceeded")
var errInput = errors.New("hfcompat: invalid input")

func (s *Service) tree(w http.ResponseWriter, r *http.Request, rt route) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.fail(w, r, errInput)
		return
	}
	if len(query) != 2 || len(query["recursive"]) != 1 || query["recursive"][0] != "true" ||
		len(query["expand"]) != 1 || query["expand"][0] != "false" {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	snap, err := s.bucket.ResolveRevision(r.Context(), rt.repo, rt.revision)
	if err != nil {
		s.failRevision(w, r, rt.repo, err)
		return
	}
	if len(snap.Files) > s.max {
		s.fail(w, r, errTreeLimit)
		return
	}
	dirs := map[string]struct{}{}
	remainingDirs := s.max - len(snap.Files)
	for _, f := range snap.Files {
		parts := strings.Split(string(f.Path), "/")
		for i := 1; i < len(parts); i++ {
			directory := strings.Join(parts[:i], "/")
			if _, exists := dirs[directory]; exists {
				continue
			}
			if len(dirs) == remainingDirs {
				s.fail(w, r, errTreeLimit)
				return
			}
			dirs[directory] = struct{}{}
		}
	}
	items := make([]treeDTO, 0, len(dirs)+len(snap.Files))
	for d := range dirs {
		items = append(items, treeDTO{"directory", d, 0, dirID(snap.OID, d), ""})
	}
	for _, f := range snap.Files {
		x := ""
		if h, ok := f.Ref.XetHash(); ok {
			x = h.String()
		}
		items = append(items, treeDTO{"file", string(f.Path), f.Ref.FileSize(), fileID(f.Ref), x})
	}
	if len(items) > s.max {
		s.fail(w, r, errTreeLimit)
		return
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Path < items[j].Path || items[i].Path == items[j].Path && items[i].Type < items[j].Type
	})
	s.json(w, r, items)
}

func fileID(ref model.FileRef) string {
	if ref.Kind() == model.FileKindXet {
		h, _ := ref.XetHash()
		return "xet-go:file:xet:" + h.String()
	}
	sum, _ := ref.SHA256()
	return "xet-go:file:sha256:" + hex.EncodeToString(sum[:])
}

func dirID(oid model.OID, p string) string {
	return "xet-go:dir:" + oid.String() + ":" + base64.RawURLEncoding.EncodeToString([]byte(p))
}

func (s *Service) token(
	w http.ResponseWriter,
	r *http.Request,
	rt route,
	g auth.RepositoryGrant,
	permissions auth.CASPermissions,
	bases baseURLs,
) {
	if permissions == auth.CASRead {
		snap, err := s.bucket.ResolveRevision(r.Context(), rt.repo, rt.revision)
		if err != nil {
			s.failRevision(w, r, rt.repo, err)
			return
		}
		_ = snap
	} else if _, err := s.bucket.GetRepository(r.Context(), rt.repo); err != nil {
		s.failNotFound(w, r, err, "RepoNotFound")
		return
	}
	t, err := s.broker.IssueCASTokenForGrant(r.Context(), g, permissions, s.ttl)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	s.json(w, r, struct {
		AccessToken string `json:"accessToken"`
		CASURL      string `json:"casUrl"`
		Exp         int64  `json:"exp"`
	}{t.Value, bases.cas, t.ExpiresAt.Unix()})
}

func (s *Service) resolve(w http.ResponseWriter, r *http.Request, rt route, bases baseURLs) {
	snap, err := s.bucket.ResolveRevision(r.Context(), rt.repo, rt.revision)
	if err != nil {
		s.failRevision(w, r, rt.repo, err)
		return
	}
	var entry model.FileEntry
	found := false
	for _, f := range snap.Files {
		if f.Path == rt.file {
			entry = f
			found = true
			break
		}
	}
	if !found {
		w.Header().Set("X-Repo-Commit", snap.OID.String())
		s.failNotFound(w, r, bucket.ErrNotFound, "EntryNotFound")
		return
	}
	size := entry.Ref.FileSize()
	var selected *content.Range
	status := http.StatusOK
	ranges := r.Header.Values("Range")
	if r.Method == http.MethodGet && len(ranges) > 0 {
		if len(ranges) != 1 {
			err = errRange
		} else {
			selected, err = parseRange(ranges[0], size)
		}
		if err != nil {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			s.fail(w, r, err)
			return
		}
		status = http.StatusPartialContent
	}
	if r.Method == http.MethodHead {
		setFileHeaders(w, bases, rt, snap, entry, size, selected)
		w.WriteHeader(status)
		return
	}
	pinned, _ := model.RevisionFromOID(snap.OID)
	opened, err := s.bucket.OpenFile(r.Context(), rt.repo, pinned, rt.file, bucket.OpenOptions{Range: selected})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	wantedRange := content.Range{Start: 0, End: size}
	if selected != nil {
		wantedRange = *selected
	}
	if opened == nil || opened.Body == nil || opened.FileSize != size || opened.Entry.Path != entry.Path ||
		!sameFileRef(opened.Entry.Ref, entry.Ref) || opened.Range != wantedRange {
		if opened != nil && opened.Body != nil {
			_ = opened.Body.Close()
		}
		s.fail(w, r, bucket.ErrInvariant)
		return
	}
	if opened.Size != selectedSize(size, selected) {
		_ = opened.Body.Close()
		s.fail(w, r, bucket.ErrInvariant)
		return
	}
	committed, err := streamFile(w, opened.Body, opened.Size, func() {
		setFileHeaders(w, bases, rt, snap, entry, size, selected)
		w.WriteHeader(status)
	})
	if err != nil && !committed {
		s.fail(w, r, err)
	}
}

// streamFile retains one bounded chunk until the following read proves it did
// not complete with a source error. Small responses are fully settled and
// closed before their success status is committed; larger responses remain
// streaming, and a terminal integrity error leaves an observably short body.
func streamFile(destination io.Writer, body io.ReadCloser, size int64, commit func()) (committed bool, resultErr error) {
	const bufferSize = 64 << 10
	if destination == nil || body == nil || commit == nil || size < 0 {
		return false, bucket.ErrInvariant
	}
	closed := false
	closeBody := func() error {
		if closed {
			return nil
		}
		closed = true
		return body.Close()
	}
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, closeBody())
		}
	}()
	buffer := make([]byte, bufferSize)
	pending := make([]byte, 0, bufferSize)
	remaining := size
	noProgress := 0
	write := func(value []byte) error {
		for len(value) > 0 {
			n, err := destination.Write(value)
			if n < 0 || n > len(value) {
				return io.ErrShortWrite
			}
			value = value[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
		}
		return nil
	}
	for {
		n, readErr := body.Read(buffer)
		if n < 0 || n > len(buffer) || int64(n) > remaining {
			return committed, fmt.Errorf("%w: file stream exceeded its declared size", bucket.ErrCorrupt)
		}
		remaining -= int64(n)
		if n == 0 && readErr == nil {
			noProgress++
			if noProgress >= 100 {
				return committed, io.ErrNoProgress
			}
			continue
		}
		noProgress = 0
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return committed, readErr
		}
		if errors.Is(readErr, io.EOF) {
			if remaining != 0 {
				return committed, fmt.Errorf("%w: file stream ended with %d bytes missing", bucket.ErrCorrupt, remaining)
			}
			if err := closeBody(); err != nil {
				return committed, err
			}
			if !committed {
				commit()
				committed = true
			}
			if err := write(pending); err != nil {
				return committed, err
			}
			return committed, write(buffer[:n])
		}
		if n == 0 {
			continue
		}
		if len(pending) == 0 {
			pending = append(pending, buffer[:n]...)
			continue
		}
		if !committed {
			commit()
			committed = true
		}
		if err := write(pending); err != nil {
			return committed, err
		}
		pending = append(pending[:0], buffer[:n]...)
	}
}

func setFileHeaders(w http.ResponseWriter, bases baseURLs, rt route, snap model.Snapshot, e model.FileEntry, size int64, rg *content.Range) {
	w.Header().Set("X-Repo-Commit", snap.OID.String())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "private, no-store")
	etag := ""
	if sum, ok := e.Ref.SHA256(); ok {
		etag = hex.EncodeToString(sum[:])
	} else {
		h, _ := e.Ref.XetHash()
		etag = h.String()
	}
	w.Header().Set("ETag", strconv.Quote(etag))
	n := selectedSize(size, rg)
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	if rg != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rg.Start, rg.End-1, size))
	}
	if h, ok := e.Ref.XetHash(); ok {
		w.Header().Set("X-Xet-Hash", h.String())
		link := bases.hub + "/api/models/" + url.PathEscape(string(rt.repo.Namespace)) + "/" + url.PathEscape(string(rt.repo.Name)) + "/xet-read-token/" + snap.OID.String()
		w.Header().Set("Link", "<"+link+">; rel=\"xet-auth\"")
	}
}

func selectedSize(size int64, r *content.Range) int64 {
	if r == nil {
		return size
	}
	return r.End - r.Start
}

func sameFileRef(left, right model.FileRef) bool {
	if left.Kind() != right.Kind() || left.FileSize() != right.FileSize() {
		return false
	}
	leftSum, leftHasSum := left.SHA256()
	rightSum, rightHasSum := right.SHA256()
	if leftHasSum != rightHasSum || leftHasSum && leftSum != rightSum {
		return false
	}
	leftHash, leftHasHash := left.XetHash()
	rightHash, rightHasHash := right.XetHash()
	return leftHasHash == rightHasHash && (!leftHasHash || leftHash == rightHash)
}

var errRange = errors.New("hfcompat: invalid range")

func parseRange(v string, size int64) (*content.Range, error) {
	if !strings.HasPrefix(v, "bytes=") || strings.Contains(v, ",") {
		return nil, errRange
	}
	x := v[6:]
	if strings.Count(x, "-") != 1 {
		return nil, errRange
	}
	p := strings.SplitN(x, "-", 2)
	if p[0] == "" {
		n, e := strconv.ParseUint(p[1], 10, 63)
		if e != nil || n == 0 || size == 0 {
			return nil, errRange
		}
		if n > uint64(size) {
			n = uint64(size)
		}
		return &content.Range{Start: size - int64(n), End: size}, nil
	}
	start, e := strconv.ParseUint(p[0], 10, 63)
	if e != nil || start >= uint64(size) {
		return nil, errRange
	}
	end := uint64(size - 1)
	if p[1] != "" {
		end, e = strconv.ParseUint(p[1], 10, 63)
		if e != nil || end < start {
			return nil, errRange
		}
		if end >= uint64(size) {
			end = uint64(size - 1)
		}
	}
	return &content.Range{Start: int64(start), End: int64(end + 1)}, nil
}

func (s *Service) json(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}
func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		return
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		status = 401
		w.Header().Set("WWW-Authenticate", "Bearer")
	case errors.Is(err, errUploadCapability):
		status = 401
	case errors.Is(err, auth.ErrPermissionDenied), errors.Is(err, bucket.ErrNotFound):
		status = 404
	case errors.Is(err, errRange), errors.Is(err, bucket.ErrRangeNotSatisfiable):
		status = 416
	case errors.Is(err, errTreeLimit):
		status = 413
	case errors.Is(err, errCommitTooLarge):
		status = 413
	case errors.Is(err, errInput), errors.Is(err, errCommitInput), errors.Is(err, bucket.ErrInvalid), errors.Is(err, auth.ErrInvalid):
		status = 400
	case errors.Is(err, bucket.ErrContentNotUploaded):
		status = 422
	case errors.Is(err, bucket.ErrUnsupported):
		status = 501
	case errors.Is(err, bucket.ErrConflict):
		status = 409
	case errors.Is(err, bucket.ErrUnavailable), errors.Is(err, auth.ErrUnavailable), errors.Is(err, context.Canceled):
		status = 503
	case errors.Is(err, context.DeadlineExceeded):
		status = 504
	}
	s.failStatus(w, r, status)
}

func (s *Service) failNotFound(w http.ResponseWriter, r *http.Request, err error, code string) {
	if errors.Is(err, bucket.ErrNotFound) {
		w.Header().Set("X-Error-Code", code)
	}
	s.fail(w, r, err)
}

func (s *Service) failRevision(w http.ResponseWriter, r *http.Request, repo model.RepoKey, err error) {
	if !errors.Is(err, bucket.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	if _, repositoryErr := s.bucket.GetRepository(r.Context(), repo); repositoryErr != nil {
		s.failNotFound(w, r, repositoryErr, "RepoNotFound")
		return
	}
	s.failNotFound(w, r, err, "RevisionNotFound")
}

func (s *Service) failStatus(w http.ResponseWriter, r *http.Request, status int) {
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	http.Error(w, http.StatusText(status), status)
}
