package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmwoliver/xet-go/content"
)

// TestS3CompatibleIntegration runs the content.Store contract against a real
// S3-compatible endpoint. It uses a unique prefix and removes all test objects.
// Required environment variables match xetcas/server/s3store integration tests.
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
	client := awss3.NewFromConfig(aws.Config{
		Region: region, Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	}, func(options *awss3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = os.Getenv("XET_S3_PATH_STYLE") != "false"
	})
	if os.Getenv("XET_S3_CREATE_BUCKET") == "1" {
		ensureIntegrationBucket(t, client, bucket)
	}
	options := Options{
		Bucket: bucket, Prefix: fmt.Sprintf("xet-go-content-integration/%d", time.Now().UnixNano()),
		TempDirectory: t.TempDir(),
	}
	store, err := New(client, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := bytes.Repeat([]byte("ordinary S3-compatible content"), 1_000)
	blob, empty := testBlob(body), testBlob(nil)
	for _, key := range []string{store.objectKey(blob.SHA256), store.objectKey(empty.SHA256)} {
		key := key
		t.Cleanup(func() {
			cleanup, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cleanupCancel()
			if _, deleteErr := client.DeleteObject(cleanup, &awss3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: aws.String(key),
			}); deleteErr != nil {
				t.Error("failed to remove S3 content integration object")
			}
		})
	}
	if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || !inserted {
		t.Fatalf("first publication = %v, %v", inserted, err)
	}
	if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || inserted {
		t.Fatalf("idempotent publication = %v, %v", inserted, err)
	}
	if info, found, err := store.Head(ctx, blob.SHA256); err != nil || !found || info.Size != blob.Size {
		t.Fatalf("head = %#v, %v, %v", info, found, err)
	}
	assertIntegrationRead(t, ctx, store, blob, nil, body)
	wanted := content.Range{Start: 101, End: 2_003}
	assertIntegrationRead(t, ctx, store, blob, &wanted, body[wanted.Start:wanted.End])
	if inserted, err := store.Put(ctx, empty, bytes.NewReader(nil)); err != nil || !inserted {
		t.Fatalf("empty publication = %v, %v", inserted, err)
	}
	assertIntegrationRead(t, ctx, store, empty, nil, nil)
	expected := []content.Blob{blob, empty}
	sort.Slice(expected, func(i, j int) bool {
		return bytes.Compare(expected[i].SHA256[:], expected[j].SHA256[:]) < 0
	})
	first, err := store.ListBlobs(ctx, content.PageRequest{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.Items[0] != expected[0] || first.NextCursor == "" {
		t.Fatalf("first inventory page = %#v, %v", first, err)
	}
	reopened, err := New(client, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.ListBlobs(ctx, content.PageRequest{Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0] != expected[1] || second.NextCursor != "" {
		t.Fatalf("restarted inventory page = %#v, %v", second, err)
	}
}

func assertIntegrationRead(
	t *testing.T,
	ctx context.Context,
	store *Store,
	blob content.Blob,
	wanted *content.Range,
	expected []byte,
) {
	t.Helper()
	reader, err := store.Open(ctx, blob, wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, expected) {
		t.Fatalf("read = %d bytes, %v, %v", len(got), readErr, closeErr)
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
		if _, headErr := client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String(bucket)}); headErr != nil {
			t.Fatal("create S3 integration bucket")
		}
	}
}
