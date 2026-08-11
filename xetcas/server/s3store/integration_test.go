package s3store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
)

// TestS3CompatibleIntegration is an opt-in contract against a real
// S3-compatible endpoint. The named bucket must already exist. The test uses a
// unique prefix and removes every object it creates.
//
// Required environment:
//
//	XET_S3_INTEGRATION=1
//	XET_S3_ENDPOINT=http://127.0.0.1:9000
//	XET_S3_BUCKET=xet-go-test
//	XET_S3_ACCESS_KEY=...
//	XET_S3_SECRET_KEY=...
//
// XET_S3_REGION defaults to us-east-1. XET_S3_PATH_STYLE defaults to true and
// may be set to false for providers that require virtual-hosted buckets.
func TestS3CompatibleIntegration(t *testing.T) {
	if os.Getenv("XET_S3_INTEGRATION") != "1" {
		t.Skip("set XET_S3_INTEGRATION=1 to test a real S3-compatible endpoint")
	}
	endpoint := requiredEnvironment(t, "XET_S3_ENDPOINT")
	bucket := requiredEnvironment(t, "XET_S3_BUCKET")
	accessKey := requiredEnvironment(t, "XET_S3_ACCESS_KEY")
	secretKey := requiredEnvironment(t, "XET_S3_SECRET_KEY")
	region := os.Getenv("XET_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	pathStyle := os.Getenv("XET_S3_PATH_STYLE") != "false"
	client := awss3.NewFromConfig(aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	}, func(options *awss3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = pathStyle
	})
	if os.Getenv("XET_S3_CREATE_BUCKET") == "1" {
		ensureIntegrationBucket(t, client, bucket)
	}
	prefix := fmt.Sprintf("xet-go-integration/%d", time.Now().UnixNano())
	store, err := New(client, Options{
		Bucket: bucket, Prefix: prefix, TempDirectory: t.TempDir(), PresignExpiry: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keys := []casserver.BlobKey{
		testKey(casserver.BlobXorb, "S3 integration xorb"),
		testKey(casserver.BlobShard, "S3 integration shard"),
	}
	for _, key := range keys {
		objectKey, keyErr := store.objectKey(key)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		t.Cleanup(func() {
			cleanup, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cleanupCancel()
			if _, deleteErr := client.DeleteObject(cleanup, &awss3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: aws.String(objectKey),
			}); deleteErr != nil {
				t.Error("failed to remove S3 integration object")
			}
		})
	}

	body := bytes.Repeat([]byte("canonical S3 range payload"), 1_000)
	if inserted, err := store.PutIfAbsent(ctx, keys[0], bytes.NewReader(body), int64(len(body))); err != nil || !inserted {
		t.Fatalf("conditional insertion = %v, %v", inserted, err)
	}
	if inserted, err := store.PutIfAbsent(ctx, keys[0], bytes.NewReader(body), int64(len(body))); err != nil || inserted {
		t.Fatalf("idempotent insertion = %v, %v", inserted, err)
	}
	conflict := append([]byte(nil), body...)
	conflict[len(conflict)/2] ^= 0xff
	if _, err := store.PutIfAbsent(ctx, keys[0], bytes.NewReader(conflict), int64(len(conflict))); err == nil {
		t.Fatal("conflicting immutable insertion succeeded")
	}
	if inserted, err := store.PutIfAbsent(ctx, keys[1], bytes.NewReader([]byte("shard")), 5); err != nil || !inserted {
		t.Fatalf("shard insertion = %v, %v", inserted, err)
	}

	info, found, err := store.Head(ctx, keys[0])
	if err != nil || !found || info.Size != int64(len(body)) {
		t.Fatalf("head = %#v, %v, %v", info, found, err)
	}
	wanted := xetcas.HTTPRange{Start: 100, End: 1_999}
	reader, err := store.Get(ctx, keys[0], &wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, body[wanted.Start:wanted.End+1]) {
		t.Fatalf("range read = %d bytes, %v, %v", len(got), readErr, closeErr)
	}
	page, err := store.ListBlobs(ctx, casserver.BlobXorb, casserver.PageRequest{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Key != keys[0] {
		t.Fatalf("Xorb inventory = %#v, %v", page, err)
	}

	signed, err := store.SignRange(ctx, keys[0], wanted)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, signed.URL, nil)
	if err != nil {
		t.Fatal("could not construct signed range request")
	}
	request.Header.Set("Range", httpRange(wanted))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("signed range request failed")
	}
	got, readErr = io.ReadAll(response.Body)
	closeErr = response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusPartialContent ||
		!bytes.Equal(got, body[wanted.Start:wanted.End+1]) {
		t.Fatalf("signed range response = status %d, %d bytes, %v, %v",
			response.StatusCode, len(got), readErr, closeErr)
	}
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when XET_S3_INTEGRATION=1", name)
	}
	return value
}

func ensureIntegrationBucket(t testing.TB, client *awss3.Client, bucket string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String(bucket)}); err == nil {
		return
	}
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		// Package tests may race to create one shared ephemeral CI bucket.
		if _, headErr := client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String(bucket)}); headErr != nil {
			t.Fatal("create S3 integration bucket")
		}
	}
}
