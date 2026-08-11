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

	HubBaseURL     string
	CASBaseURL     string
	CASTokenTTL    time.Duration
	MaxTreeEntries int
}

// Service exposes the typed bucket API through its embedded Service while
// retaining separate Hub-compatible and CAS HTTP mounts. Administrative audit
// methods are read-only and do not establish reachability or deletion safety.
type Service struct {
	*bucket.Service
	hub *hfcompat.Service
	cas *casserver.Service
}

func New(options Options) (*Service, error) {
	if options.CAS.Authorizer != nil {
		return nil, fmt.Errorf("%w: CAS authorizer is owned by the composition", ErrInvalid)
	}
	if options.CASTokens == nil {
		return nil, fmt.Errorf("%w: CAS token authority is required", ErrInvalid)
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
	hub, err := hfcompat.New(hfcompat.Options{
		Bucket: core, Broker: broker, HubBaseURL: options.HubBaseURL, CASBaseURL: options.CASBaseURL,
		CASTokenTTL: options.CASTokenTTL, MaxTreeEntries: options.MaxTreeEntries,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Hub compatibility: %w", ErrInvalid, err)
	}
	return &Service{Service: core, hub: hub, cas: cas}, nil
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
