package hosted

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/catalog/memory"
	"github.com/jmwoliver/xet-go/content"
	contentmemory "github.com/jmwoliver/xet-go/content/memory"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

type catalogWithoutRefListing struct{ catalog.Catalog }
type contentWithoutBlobListing struct{ content.Store }

func TestServiceComposesTypedAndSeparateHTTPBoundaries(t *testing.T) {
	options, manager := validOptions(t)
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := model.NewRepoKey("owner", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.CreateRepository(context.Background(), model.Repository{Key: repo, CreatedAt: time.Unix(1_700_000_000, 0)}); err != nil {
		t.Fatal(err)
	}

	hubRequest := httptest.NewRequest(http.MethodGet, "/api/models/owner/model?blobs=true", nil)
	hubResponse := httptest.NewRecorder()
	service.HubHandler().ServeHTTP(hubResponse, hubRequest)
	if hubResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated Hub status = %d", hubResponse.Code)
	}
	hubRequest = httptest.NewRequest(http.MethodGet, "/api/models/owner/model?blobs=true", nil)
	hubRequest.Header.Set("Authorization", "Bearer hub-secret")
	hubResponse = httptest.NewRecorder()
	service.HubHandler().ServeHTTP(hubResponse, hubRequest)
	if hubResponse.Code != http.StatusNotFound || hubResponse.Header().Get("X-Error-Code") != "RevisionNotFound" {
		t.Fatalf("authenticated Hub response = %d, %#v", hubResponse.Code, hubResponse.Header())
	}

	file := xethash.Chunk([]byte("missing file"))
	casRequest := httptest.NewRequest(http.MethodGet, "/v2/reconstructions/"+file.String(), nil)
	casResponse := httptest.NewRecorder()
	service.CASHandler().ServeHTTP(casResponse, casRequest)
	if casResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated CAS status = %d", casResponse.Code)
	}
	namespace, err := auth.RepositoryNamespace(repo)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.IssueCASToken(context.Background(), auth.CASTokenRequest{
		Principal: auth.Principal{Subject: "user:test"}, Namespace: namespace, Permissions: auth.CASRead,
	})
	if err != nil {
		t.Fatal(err)
	}
	casRequest = httptest.NewRequest(http.MethodGet, "/v2/reconstructions/"+file.String(), nil)
	casRequest.Header.Set("Authorization", "Bearer "+issued.Value)
	casResponse = httptest.NewRecorder()
	service.CASHandler().ServeHTTP(casResponse, casRequest)
	if casResponse.Code != http.StatusNotFound {
		t.Fatalf("authenticated missing CAS status = %d, %s", casResponse.Code, casResponse.Body.String())
	}

	page, err := service.AuditCASInventory(context.Background(), casserver.AuditRequest{
		Kind: casserver.AuditKindBlobXorb, Page: casserver.PageRequest{Limit: 1},
	})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("CAS inventory = %#v, %v", page, err)
	}
	payloads, err := service.AuditCASBlobPayloads(context.Background(), casserver.PayloadAuditRequest{
		Kind: casserver.BlobXorb, Page: casserver.PageRequest{Limit: 1},
	})
	if err != nil || len(payloads.Items) != 0 {
		t.Fatalf("CAS payload audit = %#v, %v", payloads, err)
	}
	ordinary, err := service.AuditContentInventory(context.Background(), content.PageRequest{Limit: 1})
	if err != nil || len(ordinary.Items) != 0 {
		t.Fatalf("ordinary content inventory = %#v, %v", ordinary, err)
	}
}

func TestNewRejectsIncoherentCapabilities(t *testing.T) {
	valid, _ := validOptions(t)
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"CAS authorizer", func(options *Options) { options.CAS.Authorizer = casserver.AllowAllAuthorizer{} }},
		{"token authority", func(options *Options) { options.CASTokens = nil }},
		{"Hub authenticator", func(options *Options) { options.HubAuthenticator = nil }},
		{"repository authorizer", func(options *Options) { options.RepositoryAuthorizer = nil }},
		{"catalog", func(options *Options) { options.Catalog = nil }},
		{"catalog ref listing", func(options *Options) { options.Catalog = catalogWithoutRefListing{options.Catalog} }},
		{"content", func(options *Options) { options.Content = nil }},
		{"content inventory", func(options *Options) { options.Content = contentWithoutBlobListing{options.Content} }},
		{"blobs", func(options *Options) { options.CAS.Blobs = nil }},
		{"index", func(options *Options) { options.CAS.Index = nil }},
		{"signer", func(options *Options) { options.CAS.Signer = nil }},
		{"Hub URL", func(options *Options) { options.HubBaseURL = "relative" }},
		{"CAS URL", func(options *Options) { options.CASBaseURL = "relative" }},
		{"LFS capability key", func(options *Options) { options.LFSUploadCapabilityKey = []byte("short") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrInvalid) {
				t.Fatalf("New error = %v", err)
			}
		})
	}
}

func validOptions(t *testing.T) (Options, *auth.CASTokenManager) {
	t.Helper()
	manager, err := auth.NewCASTokenManager(auth.CASTokenManagerOptions{
		Issuer: "hosted-test", Audience: "cas", SigningKey: auth.HMACKey{ID: "test-key", Secret: bytes.Repeat([]byte{0x7a}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := casserver.NewMemoryStore()
	return Options{
		Catalog: memory.New(), Content: contentmemory.New(),
		CAS: casserver.Options{
			Blobs: store, Index: store,
			Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
				return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Minute)}, nil
			}),
		},
		HubAuthenticator: auth.StaticTokenAuthenticator{Token: "hub-secret", Principal: auth.Principal{Subject: "user:test"}},
		RepositoryAuthorizer: auth.RepositoryAuthorizerFunc(func(context.Context, auth.RepositoryAccess) error {
			return nil
		}),
		CASTokens:  manager,
		HubBaseURL: "https://hub.example", CASBaseURL: "https://cas.example",
	}, manager
}
