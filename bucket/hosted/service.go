// Package hosted composes the hosting-neutral bucket, authentication, Xet CAS,
// and Hugging Face compatibility boundaries into one embeddable service.
package hosted

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/hfcompat"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
)

var ErrInvalid = errors.New("hosted bucket: invalid configuration")

// CASTokens is one coherent CAS credential authority. Implementations may
// delegate signing and verification internally, but both operations must use
// the same format, audience, and active key set.
type CASTokens interface {
	auth.CASTokenIssuer
	auth.CASTokenVerifier
}

// BucketDecorator wraps the Hub-facing revision resolution and read service.
// The typed Service and Hub writer continue to use the composed bucket.Service.
type BucketDecorator func(hfcompat.BucketService) hfcompat.BucketService

// SnapshotPublisherDecorator wraps the composed default (or explicitly
// supplied) publisher after bucket.Service has been constructed.
type SnapshotPublisherDecorator func(hfcompat.SnapshotPublisher) hfcompat.SnapshotPublisher

// Options is one coherent hosting capability bundle. CAS.Authorizer must be
// nil: Service always installs the verifier-backed scoped authorizer so a
// separately supplied CAS policy cannot drift from Hub token issuance.
type Options struct {
	Catalog catalog.Catalog
	Content content.Store
	CAS     casserver.Options

	HubAuthenticator     auth.HubAuthenticator
	RepositoryAuthorizer auth.RepositoryAuthorizer
	CASTokens            CASTokens
	LFSIngester          hfcompat.XetFileIngester
	BucketDecorator      BucketDecorator
	SnapshotReader       hfcompat.SnapshotReader
	SnapshotPublisher    hfcompat.SnapshotPublisher
	PublisherDecorator   SnapshotPublisherDecorator
	WriteAudit           hfcompat.WriteAuditSink

	HubBaseURL string
	CASBaseURL string
	// BaseURLFunc derives the authoritative Hub and CAS base URLs for each
	// request. It is forwarded verbatim to hfcompat; when set, both static base
	// URL fields must be empty.
	BaseURLFunc    func(*http.Request) (hub string, cas string, err error)
	CASTokenTTL    time.Duration
	MaxTreeEntries int

	LargeFileThreshold     int64
	MaxPreuploadFiles      int
	MaxCommitOperations    int
	MaxCommitLineBytes     int
	MaxCommitMetadata      int64
	MaxCommitPathBytes     int
	MaxDeclaredFileBytes   int64
	MaxLFSBatchObjects     int
	LFSUploadTTL           time.Duration
	LFSUploadCapabilityKey []byte
}

// Service exposes the typed bucket API through its embedded Service while
// retaining separate Hub-compatible and CAS HTTP mounts. Administrative audit
// methods are read-only and do not establish reachability or deletion safety.
type Service struct {
	*bucket.Service
	hub      *hfcompat.Service
	cas      *casserver.Service
	ordinary content.BlobLister
}

func New(options Options) (*Service, error) {
	if options.CAS.Authorizer != nil {
		return nil, fmt.Errorf("%w: CAS authorizer is owned by the composition", ErrInvalid)
	}
	if options.CASTokens == nil {
		return nil, fmt.Errorf("%w: CAS token authority is required", ErrInvalid)
	}
	if _, ok := options.Catalog.(catalog.RefLister); !ok {
		return nil, fmt.Errorf("%w: catalog ref inventory is required", ErrInvalid)
	}
	ordinary, ok := options.Content.(content.BlobLister)
	if !ok {
		return nil, fmt.Errorf("%w: ordinary content inventory is required", ErrInvalid)
	}

	broker, err := auth.NewBroker(auth.BrokerOptions{
		Authenticator: options.HubAuthenticator,
		Authorizer:    options.RepositoryAuthorizer,
		Tokens:        options.CASTokens,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: authentication: %w", ErrInvalid, err)
	}

	casOptions := options.CAS
	casOptions.Authorizer = auth.CASAuthorizer{Verifier: options.CASTokens}
	cas, err := casserver.New(casOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: CAS: %w", ErrInvalid, err)
	}
	core, err := bucket.New(bucket.Options{Catalog: options.Catalog, Content: options.Content, CAS: cas})
	if err != nil {
		return nil, fmt.Errorf("%w: bucket: %w", ErrInvalid, err)
	}
	hubBucket := hfcompat.BucketService(core)
	if options.BucketDecorator != nil {
		hubBucket = options.BucketDecorator(hubBucket)
		if hubBucket == nil {
			return nil, fmt.Errorf("%w: bucket decorator returned nil", ErrInvalid)
		}
	}
	publisher := options.SnapshotPublisher
	if publisher == nil {
		publisher = core
	}
	if options.PublisherDecorator != nil {
		publisher = options.PublisherDecorator(publisher)
		if publisher == nil {
			return nil, fmt.Errorf("%w: publisher decorator returned nil", ErrInvalid)
		}
	}
	snapshots := options.SnapshotReader
	if snapshots == nil {
		snapshots = core
	}
	hub, err := hfcompat.New(hfcompat.Options{
		Bucket: hubBucket, Writer: core, Snapshots: snapshots, Publisher: publisher, Audit: options.WriteAudit, Broker: broker,
		HubBaseURL: options.HubBaseURL, CASBaseURL: options.CASBaseURL, BaseURLFunc: options.BaseURLFunc,
		CASTokenTTL: options.CASTokenTTL, MaxTreeEntries: options.MaxTreeEntries, Ingester: options.LFSIngester,
		LargeFileThreshold: options.LargeFileThreshold, MaxPreuploadFiles: options.MaxPreuploadFiles,
		MaxCommitOperations: options.MaxCommitOperations, MaxCommitLineBytes: options.MaxCommitLineBytes,
		MaxCommitMetadata: options.MaxCommitMetadata, MaxCommitPathBytes: options.MaxCommitPathBytes,
		MaxDeclaredFileBytes: options.MaxDeclaredFileBytes, MaxLFSBatchObjects: options.MaxLFSBatchObjects,
		LFSUploadTTL: options.LFSUploadTTL, LFSUploadCapabilityKey: options.LFSUploadCapabilityKey,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Hub compatibility: %w", ErrInvalid, err)
	}
	return &Service{Service: core, hub: hub, cas: cas, ordinary: ordinary}, nil
}

func (service *Service) HubHandler() http.Handler { return service.hub.Handler() }

func (service *Service) CASHandler() http.Handler { return service.cas.Handler() }

func (service *Service) AuditCASInventory(
	ctx context.Context,
	request casserver.AuditRequest,
) (casserver.AuditPage, error) {
	return service.cas.AuditInventory(ctx, request)
}

func (service *Service) AuditCASBlobPayloads(
	ctx context.Context,
	request casserver.PayloadAuditRequest,
) (casserver.PayloadAuditPage, error) {
	return service.cas.AuditBlobPayloads(ctx, request)
}

// AuditContentInventory returns one bounded page of physical ordinary blobs.
// It is read-only and does not establish catalog reachability or deletion
// safety.
func (service *Service) AuditContentInventory(
	ctx context.Context,
	request content.PageRequest,
) (content.BlobPage, error) {
	return service.ordinary.ListBlobs(ctx, request)
}
