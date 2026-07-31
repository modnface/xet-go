package conformance_test

import (
	"bytes"
	"context"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	xet "github.com/jacobwoliver/xet-go"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xorb"
)

// TestOfficialRustLocalCASRoundTrip is gated because it talks to an
// independently built binary at the pinned official xet-core revision.
func TestOfficialRustLocalCASRoundTrip(t *testing.T) {
	rawEndpoint := os.Getenv("XET_LOCAL_CAS_ENDPOINT")
	if rawEndpoint == "" {
		t.Skip("set XET_LOCAL_CAS_ENDPOINT to a pinned xet-core local_cas_server")
	}
	endpoint, err := url.Parse(rawEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := xetcas.New(xetcas.NewStaticAccess(endpoint, ""), xetcas.Options{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Retry: xetcas.RetryPolicy{
			MaxAttempts:    4,
			InitialBackoff: 5 * time.Millisecond,
			MaximumBackoff: 50 * time.Millisecond,
		},
		SessionID: "xet-go-official-local-cas",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := xet.NewClient(protocol, xet.Options{
		Compression:         xorb.None,
		CompressionSet:      true,
		UploadConcurrency:   3,
		DownloadConcurrency: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3<<20+719)
	rng := rand.New(rand.NewSource(0x584554))
	_, _ = rng.Read(data)
	copy(data[1<<20:2<<20], data[:1<<20])

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	upload, err := client.Upload(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var full bytes.Buffer
	if _, err := client.Download(ctx, upload.File, &full); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full.Bytes(), data) {
		t.Fatal("official Rust CAS whole-file round trip differs")
	}
	rangeValue := xetcas.FileRange{Start: 123_456, End: 2_345_678}
	var partial bytes.Buffer
	if _, err := client.DownloadRange(ctx, upload.File.Hash, rangeValue, &partial); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(partial.Bytes(), data[rangeValue.Start:rangeValue.End]) {
		t.Fatal("official Rust CAS range round trip differs")
	}
}
