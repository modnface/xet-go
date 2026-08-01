package xetcas

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

const (
	defaultInitialUploadConcurrency   = 2
	defaultInitialDownloadConcurrency = 4
	defaultMinimumConcurrency         = 1
	defaultMaximumConcurrency         = 64
)

// ConcurrencyPolicy configures one adaptive request limiter. The zero value
// selects the official xet-core starting point (2 uploads or 4 downloads), a
// minimum of 1, and a maximum of 64. Setting all three fields equal provides a
// fixed limit.
type ConcurrencyPolicy struct {
	Initial int
	Minimum int
	Maximum int
}

type adaptiveLimiter struct {
	mu          sync.Mutex
	limit       int
	minimum     int
	maximum     int
	inFlight    int
	successes   int
	stateChange chan struct{}
}

type concurrencyPermit struct {
	limiter *adaptiveLimiter
	once    sync.Once
}

func normalizeConcurrency(policy ConcurrencyPolicy, defaultInitial int) (ConcurrencyPolicy, error) {
	if policy.Initial < 0 || policy.Minimum < 0 || policy.Maximum < 0 {
		return ConcurrencyPolicy{}, errors.New("xet CAS: concurrency values must not be negative")
	}
	if policy.Minimum == 0 {
		policy.Minimum = defaultMinimumConcurrency
	}
	if policy.Maximum == 0 {
		policy.Maximum = defaultMaximumConcurrency
	}
	if policy.Initial == 0 {
		policy.Initial = defaultInitial
	}
	if policy.Minimum < 1 || policy.Maximum < policy.Minimum || policy.Initial < policy.Minimum || policy.Initial > policy.Maximum {
		return ConcurrencyPolicy{}, fmt.Errorf("xet CAS: invalid concurrency policy initial=%d minimum=%d maximum=%d",
			policy.Initial, policy.Minimum, policy.Maximum)
	}
	return policy, nil
}

func newAdaptiveLimiter(policy ConcurrencyPolicy) *adaptiveLimiter {
	return &adaptiveLimiter{
		limit: policy.Initial, minimum: policy.Minimum, maximum: policy.Maximum,
		stateChange: make(chan struct{}),
	}
}

func (l *adaptiveLimiter) acquire(ctx context.Context) (*concurrencyPermit, error) {
	if l == nil {
		return nil, errors.New("xet CAS: nil concurrency limiter")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.inFlight < l.limit {
			l.inFlight++
			l.mu.Unlock()
			return &concurrencyPermit{limiter: l}, nil
		}
		changed := l.stateChange
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

// done uses additive increase and multiplicative decrease. One full current
// window of successes earns one additional permit; congestion halves the
// current limit, rounded up, without revoking already active permits.
func (p *concurrencyPermit) done(success, congestion bool) {
	if p == nil || p.limiter == nil {
		return
	}
	p.once.Do(func() {
		l := p.limiter
		l.mu.Lock()
		l.inFlight--
		if congestion {
			l.limit = max(l.minimum, (l.limit+1)/2)
			l.successes = 0
		} else if success {
			l.successes++
			if l.successes >= l.limit && l.limit < l.maximum {
				l.limit++
				l.successes = 0
			}
		} else {
			l.successes = 0
		}
		close(l.stateChange)
		l.stateChange = make(chan struct{})
		l.mu.Unlock()
	})
}

func (l *adaptiveLimiter) snapshot() (limit, inFlight int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit, l.inFlight
}
