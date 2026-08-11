package bucket_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	catalogpostgres "github.com/jmwoliver/xet-go/catalog/postgres"
	"github.com/jmwoliver/xet-go/content"
	contents3 "github.com/jmwoliver/xet-go/content/s3"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xetcas/server/postgresstore"
	"github.com/jmwoliver/xet-go/xetcas/server/s3store"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

// TestRemoteBucketComposition exercises the complete durable deployment profile.
func TestRemoteBucketComposition(t *testing.T) {
	if os.Getenv("XET_S3_INTEGRATION") != "1" || os.Getenv("XET_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set both XET_S3_INTEGRATION=1 and XET_POSTGRES_INTEGRATION=1")
	}
	required := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s is required", name)
		}
		return value
	}
	dsn, endpoint, s3Bucket := required("XET_POSTGRES_DSN"), required("XET_S3_ENDPOINT"), required("XET_S3_BUCKET")
	region := os.Getenv("XET_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := awss3.NewFromConfig(aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(required("XET_S3_ACCESS_KEY"), required("XET_S3_SECRET_KEY"), "")}, func(o *awss3.Options) {
		o.BaseEndpoint, o.UsePathStyle = aws.String(endpoint), os.Getenv("XET_S3_PATH_STYLE") != "false"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: &s3Bucket}); err != nil {
		if os.Getenv("XET_S3_CREATE_BUCKET") != "1" {
			t.Fatal("integration S3 bucket does not exist")
		}
		if _, err = client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: &s3Bucket}); err != nil {
			t.Fatal("create integration S3 bucket")
		}
	}
	unique := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano())
	catalogSchema, casSchema := "bucket_catalog_"+unique, "bucket_cas_"+unique
	rootPrefix := "xet-go-bucket-profile/" + unique
	cleanupPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open PostgreSQL cleanup pool")
	}
	t.Cleanup(func() {
		defer cleanupPool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		for _, schema := range []string{catalogSchema, casSchema} {
			if _, err := cleanupPool.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
				t.Errorf("drop PostgreSQL schema %s", schema)
			}
		}
	})
	t.Cleanup(func() { cleanupBucketPrefix(t, client, s3Bucket, rootPrefix) })

	repoA, err := model.NewRepoKey("integration", "repo-a", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	repoB, err := model.NewRepoKey("integration", "repo-b", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewCASTokenManager(auth.CASTokenManagerOptions{Issuer: "bucket-integration", Audience: "cas", SigningKey: auth.HMACKey{ID: "test-key", Secret: bytes.Repeat([]byte{0x51}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewBroker(auth.BrokerOptions{
		Authenticator: auth.StaticTokenAuthenticator{Token: "hub-integration-credential", Principal: auth.Principal{Subject: "integration-user"}},
		Authorizer:    auth.RepositoryAuthorizerFunc(func(context.Context, auth.RepositoryAccess) error { return nil }), Tokens: manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(repo model.RepoKey, permissions auth.CASPermissions) string {
		issued, issueErr := broker.IssueCASToken(ctx, "hub-integration-credential", repo, permissions, time.Minute)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return issued.Value
	}
	writeA, readA := issue(repoA, auth.CASWrite), issue(repoA, auth.CASRead)
	// Include read so this write credential can prove its namespace resolves no
	// repo-A file rather than failing merely on operation permissions.
	writeB := issue(repoB, auth.CASRead|auth.CASWrite)

	type profile struct {
		catalog *catalogpostgres.Store
		index   *postgresstore.Store
		pool    *pgxpool.Pool
		cas     *casserver.Service
		bucket  *bucket.Service
	}
	openProfile := func() profile {
		pool, openErr := pgxpool.New(ctx, dsn)
		if openErr != nil {
			t.Fatal("open PostgreSQL pool")
		}
		metadata, openErr := catalogpostgres.New(ctx, pool, catalogpostgres.Options{Schema: catalogSchema})
		if openErr != nil {
			pool.Close()
			t.Fatal(openErr)
		}
		index, openErr := postgresstore.New(ctx, pool, postgresstore.Options{Schema: casSchema})
		if openErr != nil {
			pool.Close()
			t.Fatal(openErr)
		}
		ordinary, openErr := contents3.New(client, contents3.Options{Bucket: s3Bucket, Prefix: rootPrefix + "/ordinary", TempDirectory: t.TempDir()})
		if openErr != nil {
			t.Fatal(openErr)
		}
		blobs, openErr := s3store.New(client, s3store.Options{Bucket: s3Bucket, Prefix: rootPrefix + "/cas", TempDirectory: t.TempDir(), PresignExpiry: time.Minute})
		if openErr != nil {
			t.Fatal(openErr)
		}
		cas, openErr := casserver.New(casserver.Options{Blobs: blobs, Index: index, Signer: blobs, Authorizer: auth.CASAuthorizer{Verifier: manager}})
		if openErr != nil {
			t.Fatal(openErr)
		}
		composed, openErr := bucket.New(bucket.Options{Catalog: metadata, Content: ordinary, CAS: cas})
		if openErr != nil {
			t.Fatal(openErr)
		}
		return profile{metadata, index, pool, cas, composed}
	}
	closeProfile := func(p profile) { _ = p.catalog.Close(); _ = p.index.Close(); p.pool.Close() }
	p := openProfile()
	defer func() { closeProfile(p) }()
	for _, repo := range []model.RepoKey{repoA, repoB} {
		if err := p.bucket.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	chunks := [][]byte{bytes.Repeat([]byte("remote-a"), 700), bytes.Repeat([]byte("remote-b"), 900)}
	object, err := xorb.Encode(chunks, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	var xetBody []byte
	nodes, hashes := make([]xethash.Node, len(chunks)), make([]xethash.Hash, len(chunks))
	for i, chunk := range chunks {
		hashes[i] = xethash.Chunk(chunk)
		nodes[i] = xethash.Node{Hash: hashes[i], Size: uint64(len(chunk))}
		xetBody = append(xetBody, chunk...)
	}
	xetSum := sha256.Sum256(xetBody)
	fileHash := xethash.File(nodes)
	shardBody, err := shard.EncodeUpload(shard.Shard{Files: []shard.File{{Hash: fileHash, Terms: []shard.Term{{XorbHash: object.Hash, UnpackedBytes: uint32(len(xetBody)), Start: 0, End: uint32(len(chunks)), Verification: xethash.Verification(hashes)}}, SHA256: &xetSum}}, Xorbs: []shard.Xorb{xorbInfo}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.cas.UploadXorb(ctx, readA, xetcas.DefaultXorbPrefix, object.Hash, bytes.NewReader(object.Body), int64(len(object.Body))); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("read-token upload = %v", err)
	}
	if _, err = p.cas.UploadXorb(ctx, writeA, xetcas.DefaultXorbPrefix, object.Hash, bytes.NewReader(object.Body), int64(len(object.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err = p.cas.UploadShard(ctx, writeA, bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	if _, err = p.cas.OpenFile(ctx, writeB, fileHash, nil); !errors.Is(err, casserver.ErrNotFound) {
		t.Fatalf("repo-B token addressed repo-A index = %v", err)
	}

	ordinaryBody := []byte("remote ordinary model configuration\n")
	ordinarySum := sha256.Sum256(ordinaryBody)
	if inserted, err := p.bucket.PutBlob(ctx, content.Blob{SHA256: ordinarySum, Size: int64(len(ordinaryBody))}, bytes.NewReader(ordinaryBody)); err != nil || !inserted {
		t.Fatalf("put ordinary blob = %v, %v", inserted, err)
	}
	ordinaryRef, err := model.NewBlobFileRef(ordinarySum, int64(len(ordinaryBody)))
	if err != nil {
		t.Fatal(err)
	}
	xetRef, err := model.NewXetFileRef(fileHash, int64(len(xetBody)), &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := model.ParseOID("1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{
		Repo: repoA, OID: oid, CreatedAt: time.Now(), Author: model.Identity{Name: "Integration"},
		Message: "publish remote profile fixture",
		Files:   []model.FileEntry{{Path: "config.json", Ref: ordinaryRef}, {Path: "weights.bin", Ref: xetRef}},
	}
	if err := p.bucket.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	assertRemoteFile(t, ctx, p.bucket, repoA, "main", "config.json", nil, ordinaryBody)
	r := content.Range{Start: 37, End: int64(len(xetBody) - 29)}
	assertRemoteFile(t, ctx, p.bucket, repoA, "main", "weights.bin", nil, xetBody)
	assertRemoteFile(t, ctx, p.bucket, repoA, "main", "weights.bin", &r, xetBody[r.Start:r.End])
	denied := snapshot
	denied.Repo = repoB
	denied.OID, err = model.ParseOID("2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.bucket.PublishSnapshot(ctx, denied, catalog.ExpectRef("main", nil)); !errors.Is(err, bucket.ErrContentNotUploaded) {
		t.Fatalf("cross-repository publication = %v", err)
	}
	if _, err := p.bucket.GetRef(ctx, repoB, "main"); !errors.Is(err, bucket.ErrNotFound) {
		t.Fatalf("repo-B ref after rejected publication = %v", err)
	}

	closeProfile(p)
	p = openProfile()
	immutable, err := model.ParseRevision(oid.String())
	if err != nil {
		t.Fatal(err)
	}
	assertRemoteFile(t, ctx, p.bucket, repoA, immutable.String(), "config.json", nil, ordinaryBody)
	assertRemoteFile(t, ctx, p.bucket, repoA, "main", "weights.bin", nil, xetBody)
}

func assertRemoteFile(t *testing.T, ctx context.Context, service *bucket.Service, repo model.RepoKey, revisionText, path string, requested *content.Range, want []byte) {
	t.Helper()
	revision, err := model.ParseRevision(revisionText)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := service.OpenFile(ctx, repo, revision, model.FilePath(path), bucket.OpenOptions{Range: requested})
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(opened.Body)
	closeErr := opened.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("open %s = %d bytes, read %v, close %v; want %d bytes", path, len(got), readErr, closeErr, len(want))
	}
}

func cleanupBucketPrefix(t *testing.T, client *awss3.Client, bucketName, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{Bucket: &bucketName, Prefix: &prefix})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Errorf("list integration S3 objects")
			return
		}
		objects := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, object := range page.Contents {
			objects = append(objects, types.ObjectIdentifier{Key: object.Key})
		}
		if len(objects) > 0 {
			if _, err := client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{Bucket: &bucketName, Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}}); err != nil {
				t.Errorf("delete integration S3 objects")
				return
			}
		}
	}
}
