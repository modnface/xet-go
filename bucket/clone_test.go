package bucket

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/catalog/memory"
	contentmemory "github.com/jmwoliver/xet-go/content/memory"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestServiceCloneXetFileDerivesNamespacesAndEnablesSnapshot(t *testing.T) {
	ctx := context.Background()
	sourceRepo := testRepo(t, "source-owner", "model")
	destinationRepo := testRepo(t, "destination-owner", "model")
	thirdRepo := testRepo(t, "third-owner", "model")
	sourceNamespace := mustRepositoryNamespace(t, sourceRepo)
	destinationNamespace := mustRepositoryNamespace(t, destinationRepo)
	store := casserver.NewMemoryStore()
	cas, err := casserver.New(casserver.Options{
		Blobs: store, Index: store,
		Authorizer: casserver.AllowAllAuthorizer{Namespace: sourceNamespace},
		Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
			return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, hash, sum := publishXetFixture(t, ctx, cas)
	tracker := &bucketCloneTracker{Service: cas}
	metadata := memory.New()
	service, err := New(Options{Catalog: metadata, Content: contentmemory.New(), CAS: tracker})
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []model.RepoKey{sourceRepo, destinationRepo, thirdRepo} {
		if err := service.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_500_000, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := model.NewXetFileRef(hash, int64(len(body)), &sum)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{
		Repo: destinationRepo, OID: testOID(t, 'd'), CreatedAt: time.Unix(1_700_500_001, 0),
		Author: model.Identity{Name: "Importer"}, Message: "metadata-only clone",
		Files: []model.FileEntry{{Path: "model.safetensors", Ref: ref}},
	}
	if err := service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); !errors.Is(err, ErrContentNotUploaded) {
		t.Fatalf("snapshot before clone = %v", err)
	}
	if err := service.CloneXetFile(ctx, sourceRepo, destinationRepo, hash, uint64(len(body)), &sum); err != nil {
		t.Fatal(err)
	}
	if tracker.source != sourceNamespace || tracker.destination != destinationNamespace {
		t.Fatalf("derived clone namespaces = %q -> %q", tracker.source, tracker.destination)
	}
	if err := service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatalf("snapshot after clone = %v", err)
	}
	if err := cas.VerifyFileInNamespace(
		ctx, mustRepositoryNamespace(t, thirdRepo), hash, uint64(len(body)), &sum,
	); !errors.Is(err, casserver.ErrNotFound) {
		t.Fatalf("third repository visibility = %v", err)
	}
	if err := service.CloneXetFile(nil, sourceRepo, destinationRepo, hash, uint64(len(body)), &sum); !errors.Is(err, ErrInvalid) { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatalf("nil clone context = %v", err)
	}
	if err := service.CloneXetFile(ctx, model.RepoKey{}, destinationRepo, hash, uint64(len(body)), &sum); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid source repository = %v", err)
	}
}

type bucketCloneTracker struct {
	*casserver.Service
	source      string
	destination string
}

func (tracker *bucketCloneTracker) CloneFileBetweenNamespaces(
	ctx context.Context,
	sourceNamespace string,
	destinationNamespace string,
	hash xethash.Hash,
	size uint64,
	sum *[32]byte,
) error {
	tracker.source = sourceNamespace
	tracker.destination = destinationNamespace
	return tracker.Service.CloneFileBetweenNamespaces(ctx, sourceNamespace, destinationNamespace, hash, size, sum)
}

func TestCloneErrorMapping(t *testing.T) {
	for name, test := range map[string]struct {
		input error
		want  error
	}{
		"missing":  {casserver.ErrNotFound, ErrContentNotUploaded},
		"conflict": {casserver.ErrConflict, ErrConflict},
		"corrupt":  {casserver.ErrCorrupt, ErrCorrupt},
		"invalid":  {casserver.ErrInvalid, ErrInvalid},
		"large":    {casserver.ErrTooLarge, ErrUnsupported},
		"backend":  {errors.New("backend"), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			if err := mapCASCloneError(test.input); !errors.Is(err, test.want) || !errors.Is(err, test.input) {
				t.Fatalf("mapped clone error = %v", err)
			}
		})
	}
	if mapCASCloneError(nil) != nil {
		t.Fatal("nil clone error was not preserved")
	}
}

func TestServiceCloneXetFileRequiresClonerCapability(t *testing.T) {
	cas := casOpenerFunc(func(context.Context, string, xethash.Hash, *xetcas.FileRange) (*casserver.OpenedFile, error) {
		return nil, errors.New("unused")
	})
	service, err := New(Options{Catalog: memory.New(), Content: contentmemory.New(), CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	repo := testRepo(t, "owner", "unsupported-clone")
	if err := service.CloneXetFile(
		context.Background(), repo, repo, xethash.Zero, 0, nil,
	); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing clone capability = %v", err)
	}
}
