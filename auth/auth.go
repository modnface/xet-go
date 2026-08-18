// Package auth defines hosting-neutral Hub authentication, repository policy,
// and scoped CAS credential exchange. Object-store signed URLs are deliberately
// outside this package: they are separate per-object capabilities.
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jmwoliver/xet-go/model"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
)

var (
	ErrInvalid          = errors.New("auth: invalid input")
	ErrUnauthenticated  = errors.New("auth: unauthenticated")
	ErrPermissionDenied = errors.New("auth: permission denied")
	ErrUnavailable      = errors.New("auth: backend unavailable")
)

const maxOpaqueIDBytes = 256

// Principal is an authenticated hosting identity. Subject must be a stable,
// non-secret identifier suitable for token claims and audit records.
type Principal struct{ Subject string }

func (principal Principal) Validate() error {
	return validateOpaqueID("principal subject", principal.Subject, maxOpaqueIDBytes)
}

// HubAuthenticator validates a user/tool credential presented to repository
// routes. Implementations must not treat the returned Subject as a credential.
type HubAuthenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

type HubAuthenticatorFunc func(context.Context, string) (Principal, error)

func (function HubAuthenticatorFunc) Authenticate(ctx context.Context, credential string) (Principal, error) {
	return function(ctx, credential)
}

type RepositoryPermission string

const (
	RepositoryRead  RepositoryPermission = "read"
	RepositoryWrite RepositoryPermission = "write"
)

type RepositoryAccess struct {
	Principal  Principal
	Repository model.RepoKey
	Permission RepositoryPermission
}

// RepositoryAuthorizer applies hosting policy after identity authentication.
// A not-found-hiding policy may return ErrPermissionDenied for absent repos.
type RepositoryAuthorizer interface {
	AuthorizeRepository(context.Context, RepositoryAccess) error
}

type RepositoryAuthorizerFunc func(context.Context, RepositoryAccess) error

func (function RepositoryAuthorizerFunc) AuthorizeRepository(ctx context.Context, request RepositoryAccess) error {
	return function(ctx, request)
}

// StaticTokenAuthenticator is an explicit single-principal local policy. It is
// suitable for private deployments and tests, not multi-user administration.
type StaticTokenAuthenticator struct {
	Token     string
	Principal Principal
}

func (authenticator StaticTokenAuthenticator) Authenticate(ctx context.Context, credential string) (Principal, error) {
	if err := validContext(ctx); err != nil {
		return Principal{}, err
	}
	if authenticator.Token == "" || authenticator.Principal.Validate() != nil {
		return Principal{}, fmt.Errorf("%w: invalid static authenticator configuration", ErrUnavailable)
	}
	if credential == "" || len(credential) != len(authenticator.Token) ||
		subtle.ConstantTimeCompare([]byte(credential), []byte(authenticator.Token)) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	return authenticator.Principal, nil
}

// RepositoryNamespace is the canonical, injective logical CAS namespace for a
// repository. Token exchange and trusted bucket reads must use this mapping.
func RepositoryNamespace(repository model.RepoKey) (string, error) {
	if err := model.ValidateRepoKey(repository); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	payload := string(repository.Type) + "\x00" + string(repository.Namespace) + "\x00" + string(repository.Name)
	return "repo-v1-" + base64.RawURLEncoding.EncodeToString([]byte(payload)), nil
}

type BrokerOptions struct {
	Authenticator HubAuthenticator
	Authorizer    RepositoryAuthorizer
	Tokens        CASTokenIssuer
}

// Broker authenticates a Hub credential, applies repository policy, derives
// the repository CAS namespace, and issues the least requested CAS authority.
type Broker struct {
	authenticator HubAuthenticator
	authorizer    RepositoryAuthorizer
	tokens        CASTokenIssuer
}

// RepositoryGrant is an opaque, broker-bound repository authorization result.
// It can be narrowed into a scoped CAS token without repeating Hub
// authentication or repository policy. Callers cannot construct or widen it.
type RepositoryGrant struct {
	broker       *Broker
	principal    Principal
	repository   model.RepoKey
	readAllowed  bool
	writeAllowed bool
}

// Principal returns the authenticated non-secret identity bound to the grant.
func (grant RepositoryGrant) Principal() Principal { return grant.principal }

func NewBroker(options BrokerOptions) (*Broker, error) {
	if options.Authenticator == nil || options.Authorizer == nil || options.Tokens == nil {
		return nil, fmt.Errorf("%w: authenticator, repository authorizer, and token issuer are required", ErrInvalid)
	}
	return &Broker{authenticator: options.Authenticator, authorizer: options.Authorizer, tokens: options.Tokens}, nil
}

// Authenticate validates one Hub credential without applying repository
// policy. It is intended for authenticated routes such as whoami that do not
// name a repository.
func (broker *Broker) Authenticate(ctx context.Context, hubCredential string) (Principal, error) {
	if err := validContext(ctx); err != nil {
		return Principal{}, err
	}
	if broker == nil || broker.authenticator == nil {
		return Principal{}, fmt.Errorf("%w: token broker is not configured", ErrUnavailable)
	}
	principal, err := broker.authenticator.Authenticate(ctx, hubCredential)
	if err != nil {
		return Principal{}, mapAuthenticationError(ctx, err)
	}
	if err = principal.Validate(); err != nil {
		return Principal{}, fmt.Errorf("%w: authenticator returned an invalid principal", ErrUnavailable)
	}
	return principal, nil
}

// AuthorizeRepository authenticates one Hub credential and applies one
// repository permission without consulting repository storage.
func (broker *Broker) AuthorizeRepository(
	ctx context.Context,
	hubCredential string,
	repository model.RepoKey,
	permission RepositoryPermission,
) (RepositoryGrant, error) {
	return broker.authorizeRepository(ctx, hubCredential, repository, []RepositoryPermission{permission})
}

func (broker *Broker) IssueCASToken(
	ctx context.Context,
	hubCredential string,
	repository model.RepoKey,
	permissions CASPermissions,
	ttl time.Duration,
) (IssuedCASToken, error) {
	if err := validContext(ctx); err != nil {
		return IssuedCASToken{}, err
	}
	if broker == nil || broker.authenticator == nil || broker.authorizer == nil || broker.tokens == nil {
		return IssuedCASToken{}, fmt.Errorf("%w: token broker is not configured", ErrUnavailable)
	}
	if err := model.ValidateRepoKey(repository); err != nil {
		return IssuedCASToken{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !permissions.Valid() {
		return IssuedCASToken{}, fmt.Errorf("%w: invalid CAS permissions", ErrInvalid)
	}
	wanted := make([]RepositoryPermission, 0, 2)
	if permissions.Allows(CASRead) {
		wanted = append(wanted, RepositoryRead)
	}
	if permissions.Allows(CASWrite) {
		wanted = append(wanted, RepositoryWrite)
	}
	grant, err := broker.authorizeRepository(ctx, hubCredential, repository, wanted)
	if err != nil {
		return IssuedCASToken{}, err
	}
	return broker.IssueCASTokenForGrant(ctx, grant, permissions, ttl)
}

// IssueCASTokenForGrant narrows one authorization result into a CAS token.
// Grants are valid only with the Broker that produced them, and repository
// write permission does not implicitly grant repository or CAS read access.
func (broker *Broker) IssueCASTokenForGrant(
	ctx context.Context,
	grant RepositoryGrant,
	permissions CASPermissions,
	ttl time.Duration,
) (IssuedCASToken, error) {
	if err := validContext(ctx); err != nil {
		return IssuedCASToken{}, err
	}
	if broker == nil || broker.tokens == nil {
		return IssuedCASToken{}, fmt.Errorf("%w: token broker is not configured", ErrUnavailable)
	}
	if !permissions.Valid() {
		return IssuedCASToken{}, fmt.Errorf("%w: invalid CAS permissions", ErrInvalid)
	}
	if grant.broker != broker || grant.principal.Validate() != nil || model.ValidateRepoKey(grant.repository) != nil {
		return IssuedCASToken{}, fmt.Errorf("%w: invalid or foreign repository grant", ErrInvalid)
	}
	if permissions.Allows(CASRead) && !grant.readAllowed || permissions.Allows(CASWrite) && !grant.writeAllowed {
		return IssuedCASToken{}, ErrPermissionDenied
	}
	namespace, err := RepositoryNamespace(grant.repository)
	if err != nil {
		return IssuedCASToken{}, err
	}
	return broker.tokens.IssueCASToken(ctx, CASTokenRequest{
		Principal: grant.principal, Namespace: namespace, Permissions: permissions, TTL: ttl,
	})
}

func (broker *Broker) authorizeRepository(
	ctx context.Context,
	hubCredential string,
	repository model.RepoKey,
	permissions []RepositoryPermission,
) (RepositoryGrant, error) {
	if err := validContext(ctx); err != nil {
		return RepositoryGrant{}, err
	}
	if broker == nil || broker.authenticator == nil || broker.authorizer == nil || broker.tokens == nil {
		return RepositoryGrant{}, fmt.Errorf("%w: token broker is not configured", ErrUnavailable)
	}
	if err := model.ValidateRepoKey(repository); err != nil {
		return RepositoryGrant{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(permissions) == 0 {
		return RepositoryGrant{}, fmt.Errorf("%w: repository permission is required", ErrInvalid)
	}
	for _, permission := range permissions {
		if permission != RepositoryRead && permission != RepositoryWrite {
			return RepositoryGrant{}, fmt.Errorf("%w: invalid repository permission", ErrInvalid)
		}
	}
	principal, err := broker.Authenticate(ctx, hubCredential)
	if err != nil {
		return RepositoryGrant{}, err
	}
	grant := RepositoryGrant{broker: broker, principal: principal, repository: repository}
	for _, permission := range permissions {
		err = broker.authorizer.AuthorizeRepository(ctx, RepositoryAccess{
			Principal: principal, Repository: repository, Permission: permission,
		})
		if err != nil {
			// Preserve the already-authenticated non-secret identity for callers
			// that audit concealed authorization failures. No denied permission is
			// marked on the grant, so it cannot be narrowed into a CAS token.
			return grant, mapAuthorizationError(ctx, err)
		}
		switch permission {
		case RepositoryRead:
			grant.readAllowed = true
		case RepositoryWrite:
			grant.writeAllowed = true
		}
	}
	return grant, nil
}

// CASAuthorizer adapts verified CAS claims to the low-level server's generic
// operation/namespace grant. Unknown future operations fail closed.
type CASAuthorizer struct{ Verifier CASTokenVerifier }

var _ casserver.Authorizer = CASAuthorizer{}

func (authorizer CASAuthorizer) Authorize(
	ctx context.Context,
	credential string,
	request casserver.AccessRequest,
) (casserver.Grant, error) {
	if authorizer.Verifier == nil {
		return casserver.Grant{}, fmt.Errorf("%w: CAS token verifier is not configured", ErrUnavailable)
	}
	if credential == "" {
		return casserver.Grant{}, casserver.ErrUnauthorized
	}
	claims, err := authorizer.Verifier.VerifyCASToken(ctx, credential)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrInvalid) {
			return casserver.Grant{}, casserver.ErrUnauthorized
		}
		if errors.Is(err, ErrPermissionDenied) {
			return casserver.Grant{}, casserver.ErrForbidden
		}
		return casserver.Grant{}, err
	}
	required := CASPermissions(0)
	switch request.Operation {
	case casserver.OperationReadFile, casserver.OperationReadXorb:
		required = CASRead
	case casserver.OperationReadDedup:
		// Global deduplication lookup is part of the official upload flow as
		// well as a read operation. Either narrowly scoped permission may use
		// it; the returned grant remains confined to the token namespace.
		if !claims.Permissions.Allows(CASRead) && !claims.Permissions.Allows(CASWrite) {
			return casserver.Grant{}, fmt.Errorf("%w: CAS token does not permit the operation", casserver.ErrForbidden)
		}
		return casserver.Grant{Namespace: claims.Namespace}, nil
	case casserver.OperationWriteXorb, casserver.OperationWriteShard:
		required = CASWrite
	default:
		return casserver.Grant{}, casserver.ErrForbidden
	}
	if !claims.Permissions.Allows(required) {
		return casserver.Grant{}, casserver.ErrForbidden
	}
	return casserver.Grant{Namespace: claims.Namespace}, nil
}

func validContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalid)
	}
	return ctx.Err()
}

func validateOpaqueID(name, value string, maximum int) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: invalid %s", ErrInvalid, name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%w: invalid %s", ErrInvalid, name)
		}
	}
	return nil
}

func mapAuthenticationError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return ErrUnauthenticated
	case errors.Is(err, ErrInvalid):
		return ErrUnauthenticated
	case errors.Is(err, ErrUnavailable):
		return err
	default:
		return fmt.Errorf("%w: authenticate principal", ErrUnavailable)
	}
}

func mapAuthorizationError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrUnauthenticated):
		return ErrPermissionDenied
	case errors.Is(err, ErrInvalid):
		return fmt.Errorf("%w: repository policy rejected an invalid request", ErrUnavailable)
	case errors.Is(err, ErrUnavailable):
		return err
	default:
		return fmt.Errorf("%w: authorize repository", ErrUnavailable)
	}
}
