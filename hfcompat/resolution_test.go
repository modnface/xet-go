package hfcompat

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
)

type resolutionDecorator struct {
	underlying *bucket.Service
	snapshot   model.Snapshot
	resolved   []model.Revision
	opened     []model.Revision
}

func (decorator *resolutionDecorator) GetRepository(ctx context.Context, repo model.RepoKey) (model.Repository, error) {
	return decorator.underlying.GetRepository(ctx, repo)
}

func (decorator *resolutionDecorator) ResolveRevision(_ context.Context, _ model.RepoKey, revision model.Revision) (model.Snapshot, error) {
	decorator.resolved = append(decorator.resolved, revision)
	if _, explicit := revision.OID(); explicit {
		return model.Snapshot{}, bucket.ErrNotFound
	}
	return model.CloneSnapshot(decorator.snapshot), nil
}

func (decorator *resolutionDecorator) OpenFile(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
	path model.FilePath,
	options bucket.OpenOptions,
) (*bucket.FileReader, error) {
	decorator.opened = append(decorator.opened, revision)
	return decorator.underlying.OpenFile(ctx, repo, revision, path, options)
}

func TestBucketServiceDecoratorOwnsMutableRevisionResolutionOnEveryReadRoute(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	oid, err := model.ParseOID(strings.Repeat("2", 40))
	if err != nil {
		t.Fatal(err)
	}
	hostSnapshot, err := model.CanonicalSnapshot(model.Snapshot{
		Repo: fixture.repo, OID: oid, Parent: &fixture.snapshot.OID, CreatedAt: time.Unix(1_700_000_200, 0).UTC(),
		Author: model.Identity{Name: "host"}, Message: "host-owned revision",
		Files: []model.FileEntry{fixture.snapshot.Files[0]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.bucket.PublishSnapshot(context.Background(), hostSnapshot, catalog.NoRefUpdate()); err != nil {
		t.Fatal(err)
	}
	decorator := &resolutionDecorator{underlying: fixture.bucket, snapshot: hostSnapshot}
	handler, err := New(Options{
		Bucket: decorator, Writer: fixture.bucket, Publisher: fixture.bucket, Broker: fixture.handler.broker,
		HubBaseURL: "https://hub.test", CASBaseURL: "https://cas.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		method string
		target string
	}{
		{"model", http.MethodGet, "/api/models/owner/model?blobs=true"},
		{"revision", http.MethodGet, "/api/models/owner/model/revision/main?blobs=true"},
		{"tree", http.MethodGet, "/api/models/owner/model/tree/main?recursive=true&expand=false"},
		{"token", http.MethodGet, "/api/models/owner/model/xet-read-token/main"},
		{"resolve", http.MethodGet, "/owner/model/resolve/main/config.json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(t, handler, test.method, test.target, "Bearer hub-token", nil)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if (test.name == "model" || test.name == "revision") && !strings.Contains(response.Body.String(), oid.String()) {
				t.Fatalf("response did not use host OID %s: %s", oid, response.Body.String())
			}
			if test.name == "tree" && strings.Contains(response.Body.String(), "weights/model.bin") {
				t.Fatalf("tree did not use host snapshot: %s", response.Body.String())
			}
		})
	}
	if len(decorator.resolved) != len(tests) {
		t.Fatalf("ResolveRevision calls = %d, want %d: %#v", len(decorator.resolved), len(tests), decorator.resolved)
	}
	for _, revision := range decorator.resolved {
		if ref, ok := revision.Ref(); !ok || ref != "main" {
			t.Fatalf("resolved revision = %q", revision)
		}
	}
	if len(decorator.opened) != 1 {
		t.Fatalf("OpenFile calls = %#v", decorator.opened)
	}
	pinned, ok := decorator.opened[0].OID()
	if !ok || pinned != oid {
		t.Fatalf("OpenFile was not pinned to host OID: %q", decorator.opened[0])
	}
	explicit := request(t, handler, http.MethodGet, "/api/models/owner/model/revision/"+oid.String()+"?blobs=true", "Bearer hub-token", nil)
	if explicit.Code != http.StatusNotFound || explicit.Header().Get("X-Error-Code") != "RevisionNotFound" {
		t.Fatalf("explicit OID visibility policy = %d, %#v", explicit.Code, explicit.Header())
	}
}

var _ BucketService = (*resolutionDecorator)(nil)
