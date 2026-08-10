package server

import (
	"context"
	"crypto/subtle"
)

// AllowAllAuthorizer is an explicit test/development policy. Production
// callers should inject a credential and reachability-aware implementation.
type AllowAllAuthorizer struct{ Namespace string }

func (a AllowAllAuthorizer) Authorize(context.Context, string, AccessRequest) (Grant, error) {
	return Grant(a), nil
}

// StaticTokenAuthorizer is a small local deployment policy. It compares the
// complete bearer token in constant time and grants all CAS operations.
type StaticTokenAuthorizer struct {
	Token     string
	Namespace string
}

func (a StaticTokenAuthorizer) Authorize(_ context.Context, credential string, _ AccessRequest) (Grant, error) {
	if credential == "" {
		return Grant{}, ErrUnauthorized
	}
	if len(credential) != len(a.Token) || subtle.ConstantTimeCompare([]byte(credential), []byte(a.Token)) != 1 {
		return Grant{}, ErrForbidden
	}
	return Grant{Namespace: a.Namespace}, nil
}
