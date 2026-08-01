package xetcas

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
)

func TestAdaptiveLimiterIncreaseDecreaseAndCancellation(t *testing.T) {
	limiter := newAdaptiveLimiter(ConcurrencyPolicy{Initial: 2, Minimum: 1, Maximum: 4})
	first, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if limit, active := limiter.snapshot(); limit != 2 || active != 2 {
		t.Fatalf("initial limit=%d active=%d", limit, active)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := limiter.acquire(ctx); err == nil {
		t.Fatal("canceled permit wait succeeded")
	}
	first.done(true, false)
	second.done(true, false)
	if limit, active := limiter.snapshot(); limit != 3 || active != 0 {
		t.Fatalf("increased limit=%d active=%d", limit, active)
	}

	permits := make([]*concurrencyPermit, 3)
	for i := range permits {
		permits[i], err = limiter.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	permits[0].done(false, true)
	permits[0].done(false, true) // release is idempotent
	if limit, active := limiter.snapshot(); limit != 2 || active != 2 {
		t.Fatalf("reduced limit=%d active=%d", limit, active)
	}
	permits[1].done(false, false)
	permits[2].done(false, false)
}

func TestConcurrencyPolicyValidation(t *testing.T) {
	upload, err := normalizeConcurrency(ConcurrencyPolicy{}, defaultInitialUploadConcurrency)
	if err != nil || upload != (ConcurrencyPolicy{Initial: 2, Minimum: 1, Maximum: 64}) {
		t.Fatalf("upload defaults=%+v error=%v", upload, err)
	}
	download, err := normalizeConcurrency(ConcurrencyPolicy{}, defaultInitialDownloadConcurrency)
	if err != nil || download.Initial != 4 {
		t.Fatalf("download defaults=%+v error=%v", download, err)
	}
	for _, invalid := range []ConcurrencyPolicy{
		{Initial: -1}, {Initial: 1, Minimum: 2, Maximum: 3}, {Initial: 4, Minimum: 1, Maximum: 3},
		{Initial: 1, Minimum: 3, Maximum: 2},
	} {
		if _, err := normalizeConcurrency(invalid, 2); err == nil {
			t.Errorf("accepted invalid policy %+v", invalid)
		}
	}
}

func TestUploadLimiterBacksOffBeforeRetry(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"was_inserted":true}`)
	}))
	defer server.Close()
	var limitDuringBackoff int
	var limiter *adaptiveLimiter
	client := testClient(t, serverURL(t, server.URL), "", Options{
		UploadConcurrency: ConcurrencyPolicy{Initial: 2, Minimum: 1, Maximum: 4},
		Retry: RetryPolicy{Sleep: func(context.Context, time.Duration) error {
			limitDuringBackoff, _ = limiter.snapshot()
			return nil
		}},
	})
	limiter = client.uploadLimiter
	inserted, err := client.UploadXorb(context.Background(), DefaultPrefix, xethash.Zero, []byte("xorb"))
	if err != nil || !inserted {
		t.Fatalf("inserted=%v error=%v", inserted, err)
	}
	if limitDuringBackoff != 1 || requests.Load() != 2 {
		t.Fatalf("limit during backoff=%d requests=%d", limitDuringBackoff, requests.Load())
	}
}

func TestDownloadLimiterBoundsConcurrentSignedFetches(t *testing.T) {
	entered := make(chan struct{}, 3)
	release := make(chan struct{}, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "x")
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		DownloadConcurrency: ConcurrencyPolicy{Initial: 2, Minimum: 2, Maximum: 2},
	})
	errorsOut := make(chan error, 3)
	var group sync.WaitGroup
	for range 3 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := client.FetchRanges(context.Background(), server.URL, []HTTPRange{{Start: 0, End: 0}})
			errorsOut <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("two requests did not enter fixed limiter")
		}
	}
	select {
	case <-entered:
		t.Fatal("third request exceeded fixed concurrency limit")
	case <-time.After(25 * time.Millisecond):
	}
	release <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("third request did not enter after permit release")
	}
	release <- struct{}{}
	release <- struct{}{}
	group.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
}
