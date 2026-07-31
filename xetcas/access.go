package xetcas

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"
)

// Access is the authority requested from a CASAccessProvider.
type Access uint8

const (
	AccessRead Access = iota
	AccessWrite
)

// CASAccess contains an already-issued Xet CAS endpoint and optional bearer
// token. Token acquisition is intentionally outside this module.
type CASAccess struct {
	Endpoint    *url.URL
	BearerToken string
	ExpiresAt   time.Time
}

// CASAccessProvider supplies read or write access and invalidates credentials
// rejected by CAS. Implementations may call a hosting provider's token broker.
type CASAccessProvider interface {
	Access(context.Context, Access) (CASAccess, error)
	Invalidate(Access)
}

// StaticAccessProvider is useful for local services and already-issued tokens.
type StaticAccessProvider struct {
	Read  CASAccess
	Write CASAccess
}

func NewStaticAccess(endpoint *url.URL, bearerToken string) *StaticAccessProvider {
	access := CASAccess{Endpoint: cloneURL(endpoint), BearerToken: bearerToken}
	return &StaticAccessProvider{Read: access, Write: access}
}

func (p *StaticAccessProvider) Access(_ context.Context, mode Access) (CASAccess, error) {
	if p == nil {
		return CASAccess{}, errors.New("xet CAS: nil static access provider")
	}
	switch mode {
	case AccessRead:
		return cloneAccess(p.Read), nil
	case AccessWrite:
		return cloneAccess(p.Write), nil
	default:
		return CASAccess{}, fmt.Errorf("xet CAS: invalid access mode %d", mode)
	}
}

func (*StaticAccessProvider) Invalidate(Access) {}

type accessEntry struct {
	value      CASAccess
	valid      bool
	refreshing chan struct{}
}

type accessCache struct {
	provider      CASAccessProvider
	refreshBefore time.Duration
	now           func() time.Time
	mu            sync.Mutex
	entries       [2]accessEntry
}

func (c *accessCache) get(ctx context.Context, mode Access) (CASAccess, error) {
	if mode != AccessRead && mode != AccessWrite {
		return CASAccess{}, fmt.Errorf("xet CAS: invalid access mode %d", mode)
	}
	for {
		c.mu.Lock()
		entry := &c.entries[mode]
		if entry.valid && (entry.value.ExpiresAt.IsZero() || entry.value.ExpiresAt.After(c.now().Add(c.refreshBefore))) {
			value := cloneAccess(entry.value)
			c.mu.Unlock()
			return value, nil
		}
		if entry.refreshing != nil {
			ready := entry.refreshing
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return CASAccess{}, ctx.Err()
			case <-ready:
				continue
			}
		}
		ready := make(chan struct{})
		entry.refreshing = ready
		c.mu.Unlock()

		value, err := c.provider.Access(ctx, mode)
		if err == nil {
			err = validateAccess(value, c.now())
		}

		c.mu.Lock()
		entry = &c.entries[mode]
		if err == nil {
			entry.value = cloneAccess(value)
			entry.valid = true
		} else {
			entry.valid = false
		}
		entry.refreshing = nil
		close(ready)
		c.mu.Unlock()
		if err != nil {
			return CASAccess{}, fmt.Errorf("xet CAS: obtain access: %w", err)
		}
		return cloneAccess(value), nil
	}
}

func (c *accessCache) invalidate(mode Access) {
	if mode != AccessRead && mode != AccessWrite {
		return
	}
	c.mu.Lock()
	c.entries[mode].valid = false
	c.mu.Unlock()
	c.provider.Invalidate(mode)
}

func validateAccess(access CASAccess, now time.Time) error {
	if access.Endpoint == nil {
		return errors.New("access endpoint is nil")
	}
	if (access.Endpoint.Scheme != "http" && access.Endpoint.Scheme != "https") || access.Endpoint.Host == "" {
		return errors.New("access endpoint must be an absolute HTTP(S) URL")
	}
	if access.Endpoint.User != nil {
		return errors.New("access endpoint must not contain user information")
	}
	if access.Endpoint.RawQuery != "" || access.Endpoint.Fragment != "" {
		return errors.New("access endpoint must not contain a query or fragment")
	}
	if !access.ExpiresAt.IsZero() && !access.ExpiresAt.After(now) {
		return errors.New("access is already expired")
	}
	return nil
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	copy := *u
	return &copy
}

func cloneAccess(access CASAccess) CASAccess {
	access.Endpoint = cloneURL(access.Endpoint)
	return access
}
