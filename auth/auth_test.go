package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/model"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
)

func TestPrincipalStaticAuthenticationAndRepositoryNamespace(t *testing.T) {
	for _, subject := range []string{"user:alice", "organization/example", "δοκιμή"} {
		if err := (Principal{Subject: subject}).Validate(); err != nil {
			t.Fatalf("valid subject %q = %v", subject, err)
		}
	}
	for _, subject := range []string{"", " leading", "trailing ", "line\nbreak", string([]byte{0xff}), strings.Repeat("x", maxOpaqueIDBytes+1)} {
		if err := (Principal{Subject: subject}).Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid subject %q = %v", subject, err)
		}
	}
	authenticator := StaticTokenAuthenticator{Token: "hub-secret", Principal: Principal{Subject: "user:alice"}}
	principal, err := authenticator.Authenticate(context.Background(), "hub-secret")
	if err != nil || principal.Subject != "user:alice" {
		t.Fatalf("static authentication = %#v, %v", principal, err)
	}
	for _, credential := range []string{"", "hub-secreu", "different-length"} {
		if _, err := authenticator.Authenticate(context.Background(), credential); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("bad static credential = %v", err)
		}
	}
	if _, err := (StaticTokenAuthenticator{}).Authenticate(context.Background(), "token"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid static configuration = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authenticator.Authenticate(canceled, "hub-secret"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled static authentication = %v", err)
	}

	first := testRepo(t, "owner", "model")
	second := testRepo(t, "owner", "other")
	firstNamespace, err := RepositoryNamespace(first)
	if err != nil || firstNamespace == "" || strings.Contains(firstNamespace, "/") {
		t.Fatalf("first namespace = %q, %v", firstNamespace, err)
	}
	secondNamespace, err := RepositoryNamespace(second)
	if err != nil || secondNamespace == firstNamespace {
		t.Fatalf("second namespace = %q, %v", secondNamespace, err)
	}
	if _, err := RepositoryNamespace(model.RepoKey{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid repository = %v", err)
	}
}

func TestBrokerAppliesAuthenticationPolicyAndScope(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	manager := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "miniface", Audience: "cas", SigningKey: HMACKey{ID: "key", Secret: bytes.Repeat([]byte{9}, minimumKeyBytes)},
	})
	repository := testRepo(t, "owner", "model")
	var accesses []RepositoryAccess
	policy := RepositoryAuthorizerFunc(func(_ context.Context, access RepositoryAccess) error {
		accesses = append(accesses, access)
		if access.Repository != repository || access.Principal.Subject != "user:alice" {
			return ErrPermissionDenied
		}
		return nil
	})
	broker, err := NewBroker(BrokerOptions{
		Authenticator: StaticTokenAuthenticator{Token: "hub-token", Principal: Principal{Subject: "user:alice"}},
		Authorizer:    policy, Tokens: manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := broker.Authenticate(context.Background(), "hub-token")
	if err != nil || principal.Subject != "user:alice" || len(accesses) != 0 {
		t.Fatalf("broker authentication = %#v, %v; accesses=%#v", principal, err, accesses)
	}
	issued, err := broker.IssueCASToken(context.Background(), "hub-token", repository, CASRead|CASWrite, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(accesses) != 2 || accesses[0].Permission != RepositoryRead || accesses[1].Permission != RepositoryWrite {
		t.Fatalf("repository policy requests = %#v", accesses)
	}
	claims, err := manager.VerifyCASToken(context.Background(), issued.Value)
	wantNamespace, namespaceErr := RepositoryNamespace(repository)
	if err != nil || namespaceErr != nil || claims.Namespace != wantNamespace || claims.Subject != "user:alice" || claims.Permissions != CASRead|CASWrite {
		t.Fatalf("broker token = %#v, verify=%v namespace=%v", claims, err, namespaceErr)
	}
	if _, err := broker.IssueCASToken(context.Background(), "wrong", repository, CASRead, 0); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong Hub token = %v", err)
	}
	denied, err := NewBroker(BrokerOptions{
		Authenticator: StaticTokenAuthenticator{Token: "hub-token", Principal: Principal{Subject: "user:alice"}},
		Authorizer:    RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return ErrPermissionDenied }),
		Tokens:        manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.IssueCASToken(context.Background(), "hub-token", repository, CASWrite, 0); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("denied repository = %v", err)
	}
	if _, err := broker.IssueCASToken(context.Background(), "hub-token", model.RepoKey{}, CASRead, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid repository = %v", err)
	}
	if _, err := broker.IssueCASToken(context.Background(), "hub-token", repository, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid permissions = %v", err)
	}
}

func TestBrokerRepositoryGrantNarrowsWithoutReauthentication(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	manager := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "miniface", Audience: "cas", SigningKey: HMACKey{ID: "key", Secret: bytes.Repeat([]byte{0x31}, minimumKeyBytes)},
	})
	repository := testRepo(t, "owner", "grant-model")
	authentications, authorizations := 0, 0
	broker, err := NewBroker(BrokerOptions{
		Authenticator: HubAuthenticatorFunc(func(context.Context, string) (Principal, error) {
			authentications++
			return Principal{Subject: "user:grant"}, nil
		}),
		Authorizer: RepositoryAuthorizerFunc(func(_ context.Context, access RepositoryAccess) error {
			authorizations++
			if access.Repository != repository || access.Permission != RepositoryRead {
				return ErrPermissionDenied
			}
			return nil
		}),
		Tokens: manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := broker.AuthorizeRepository(context.Background(), "hub-token", repository, RepositoryRead)
	if err != nil || authentications != 1 || authorizations != 1 {
		t.Fatalf("repository grant = %#v, %v; authentication=%d authorization=%d", grant, err, authentications, authorizations)
	}
	issued, err := broker.IssueCASTokenForGrant(context.Background(), grant, CASRead, time.Minute)
	if err != nil || authentications != 1 || authorizations != 1 {
		t.Fatalf("grant token = %#v, %v; authentication=%d authorization=%d", issued, err, authentications, authorizations)
	}
	claims, err := manager.VerifyCASToken(context.Background(), issued.Value)
	wantNamespace, namespaceErr := RepositoryNamespace(repository)
	if err != nil || namespaceErr != nil || claims.Subject != "user:grant" || claims.Namespace != wantNamespace || claims.Permissions != CASRead {
		t.Fatalf("grant claims = %#v, verify=%v namespace=%v", claims, err, namespaceErr)
	}
	if _, err := broker.IssueCASTokenForGrant(context.Background(), grant, CASWrite, 0); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("widen read grant to write = %v", err)
	}
	deniedGrant, err := broker.AuthorizeRepository(context.Background(), "hub-token", repository, RepositoryWrite)
	if !errors.Is(err, ErrPermissionDenied) || deniedGrant.Principal().Subject != "user:grant" {
		t.Fatalf("denied grant identity = %#v, %v", deniedGrant.Principal(), err)
	}
	if _, err = broker.IssueCASTokenForGrant(context.Background(), deniedGrant, CASWrite, time.Minute); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("narrow denied grant = %v", err)
	}
	if _, err := broker.IssueCASTokenForGrant(context.Background(), RepositoryGrant{}, CASRead, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero grant = %v", err)
	}
	other, err := NewBroker(BrokerOptions{
		Authenticator: StaticTokenAuthenticator{Token: "unused", Principal: Principal{Subject: "other"}},
		Authorizer:    RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return nil }),
		Tokens:        manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.IssueCASTokenForGrant(context.Background(), grant, CASRead, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign grant = %v", err)
	}
	if _, err := broker.AuthorizeRepository(context.Background(), "hub-token", repository, RepositoryPermission("delete")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid repository permission = %v", err)
	}
	if _, err := broker.IssueCASTokenForGrant(context.Background(), grant, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid narrowed permissions = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := broker.IssueCASTokenForGrant(canceled, grant, CASRead, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled grant token = %v", err)
	}
	var nilBroker *Broker
	if _, err := nilBroker.Authenticate(context.Background(), "hub-token"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil broker authentication = %v", err)
	}
	if _, err := nilBroker.AuthorizeRepository(context.Background(), "hub-token", repository, RepositoryRead); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil broker authorization = %v", err)
	}
	if _, err := nilBroker.IssueCASTokenForGrant(context.Background(), grant, CASRead, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil broker grant token = %v", err)
	}
}

func TestBrokerIssuesTokenForMaximumWidthRepositoryKey(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	manager := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "miniface", Audience: "cas", SigningKey: HMACKey{ID: "key", Secret: bytes.Repeat([]byte{0x19}, minimumKeyBytes)},
	})
	component := strings.Repeat("𐐀", model.MaxNamespaceRunes)
	repository := testRepo(t, component, component)
	broker, err := NewBroker(BrokerOptions{
		Authenticator: StaticTokenAuthenticator{Token: "hub-token", Principal: Principal{Subject: "user"}},
		Authorizer:    RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return nil }),
		Tokens:        manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := broker.IssueCASToken(context.Background(), "hub-token", repository, CASRead, 0)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := manager.VerifyCASToken(context.Background(), issued.Value)
	want, namespaceErr := RepositoryNamespace(repository)
	if err != nil || namespaceErr != nil || claims.Namespace != want || len(want) <= 512 {
		t.Fatalf("maximum repository namespace: length=%d claims=%#v verify=%v namespace=%v", len(want), claims, err, namespaceErr)
	}
}

func TestBrokerAndCASAuthorizerErrorBoundaries(t *testing.T) {
	for name, options := range map[string]BrokerOptions{
		"all":           {},
		"authenticator": {Authorizer: RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return nil }), Tokens: tokenIssuerFunc(nil)},
		"authorizer":    {Authenticator: HubAuthenticatorFunc(func(context.Context, string) (Principal, error) { return Principal{Subject: "user"}, nil }), Tokens: tokenIssuerFunc(nil)},
		"tokens":        {Authenticator: HubAuthenticatorFunc(func(context.Context, string) (Principal, error) { return Principal{Subject: "user"}, nil }), Authorizer: RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return nil })},
	} {
		if _, err := NewBroker(options); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing %s = %v", name, err)
		}
	}
	repository := testRepo(t, "owner", "model")
	tests := []struct {
		name           string
		authentication error
		authorization  error
		want           error
	}{
		{name: "unknown authentication", authentication: errors.New("backend"), want: ErrUnavailable},
		{name: "invalid authentication", authentication: ErrInvalid, want: ErrUnauthenticated},
		{name: "unavailable authentication", authentication: ErrUnavailable, want: ErrUnavailable},
		{name: "unknown authorization", authorization: errors.New("backend"), want: ErrUnavailable},
		{name: "invalid authorization", authorization: ErrInvalid, want: ErrUnavailable},
		{name: "unauthenticated authorization", authorization: ErrUnauthenticated, want: ErrPermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker, err := NewBroker(BrokerOptions{
				Authenticator: HubAuthenticatorFunc(func(context.Context, string) (Principal, error) {
					if test.authentication != nil {
						return Principal{}, test.authentication
					}
					return Principal{Subject: "user"}, nil
				}),
				Authorizer: RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return test.authorization }),
				Tokens: tokenIssuerFunc(func(context.Context, CASTokenRequest) (IssuedCASToken, error) {
					return IssuedCASToken{Value: "token"}, nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := broker.IssueCASToken(context.Background(), "credential", repository, CASRead, 0); !errors.Is(err, test.want) {
				t.Fatalf("broker error = %v", err)
			}
		})
	}
	invalidPrincipal, err := NewBroker(BrokerOptions{
		Authenticator: HubAuthenticatorFunc(func(context.Context, string) (Principal, error) { return Principal{}, nil }),
		Authorizer:    RepositoryAuthorizerFunc(func(context.Context, RepositoryAccess) error { return nil }),
		Tokens:        tokenIssuerFunc(func(context.Context, CASTokenRequest) (IssuedCASToken, error) { return IssuedCASToken{}, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalidPrincipal.IssueCASToken(context.Background(), "credential", repository, CASRead, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid principal = %v", err)
	}
	var nilBroker *Broker
	if _, err := nilBroker.IssueCASToken(context.Background(), "credential", repository, CASRead, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil broker = %v", err)
	}
	if _, err := nilBroker.IssueCASToken(nil, "credential", repository, CASRead, 0); !errors.Is(err, ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatalf("nil context = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := invalidPrincipal.IssueCASToken(canceled, "credential", repository, CASRead, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled broker = %v", err)
	}

	authorizer := CASAuthorizer{Verifier: tokenVerifierFunc(func(context.Context, string) (CASTokenClaims, error) {
		return CASTokenClaims{}, ErrPermissionDenied
	})}
	if _, err := authorizer.Authorize(context.Background(), "token", casserver.AccessRequest{Operation: casserver.OperationReadFile}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("verifier denial = %v", err)
	}
	authorizer.Verifier = tokenVerifierFunc(func(context.Context, string) (CASTokenClaims, error) { return CASTokenClaims{}, ErrInvalid })
	if _, err := authorizer.Authorize(context.Background(), "token", casserver.AccessRequest{Operation: casserver.OperationReadFile}); !errors.Is(err, casserver.ErrUnauthorized) {
		t.Fatalf("invalid credential = %v", err)
	}
	backend := errors.New("verifier backend")
	authorizer.Verifier = tokenVerifierFunc(func(context.Context, string) (CASTokenClaims, error) { return CASTokenClaims{}, backend })
	if _, err := authorizer.Authorize(context.Background(), "token", casserver.AccessRequest{Operation: casserver.OperationReadFile}); !errors.Is(err, backend) {
		t.Fatalf("verifier backend = %v", err)
	}
	if _, err := (CASAuthorizer{}).Authorize(context.Background(), "token", casserver.AccessRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing verifier = %v", err)
	}
	authorizer.Verifier = tokenVerifierFunc(func(context.Context, string) (CASTokenClaims, error) {
		return CASTokenClaims{Namespace: "scope"}, nil
	})
	if _, err := authorizer.Authorize(context.Background(), "token", casserver.AccessRequest{Operation: casserver.OperationReadDedup}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("permissionless dedup = %v", err)
	}

	canceledErr, cancelErr := context.WithCancel(context.Background())
	cancelErr()
	if err := mapAuthenticationError(canceledErr, ErrUnavailable); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authentication mapping = %v", err)
	}
	if err := mapAuthorizationError(canceledErr, ErrUnavailable); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authorization mapping = %v", err)
	}
	if err := mapAuthorizationError(context.Background(), ErrUnavailable); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable authorization mapping = %v", err)
	}
}

func testRepo(t *testing.T, namespace, name string) model.RepoKey {
	t.Helper()
	repository, err := model.NewRepoKey(namespace, name, model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

type tokenIssuerFunc func(context.Context, CASTokenRequest) (IssuedCASToken, error)

func (function tokenIssuerFunc) IssueCASToken(ctx context.Context, request CASTokenRequest) (IssuedCASToken, error) {
	if function == nil {
		return IssuedCASToken{}, fmt.Errorf("unused")
	}
	return function(ctx, request)
}

type tokenVerifierFunc func(context.Context, string) (CASTokenClaims, error)

func (function tokenVerifierFunc) VerifyCASToken(ctx context.Context, token string) (CASTokenClaims, error) {
	return function(ctx, token)
}
