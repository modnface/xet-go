package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xetcas/server/postgresstore"
	"github.com/jmwoliver/xet-go/xetcas/server/s3store"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

const remoteHelperMode = "XET_REMOTE_PROFILE_HELPER"

type remoteConfiguration struct {
	dsn, endpoint, bucket, accessKey, secretKey, region string
	pathStyle                                           bool
}

func remoteIntegrationConfiguration(t testing.TB) remoteConfiguration {
	t.Helper()
	required := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s is required for the remote-profile integration", name)
		}
		return value
	}
	region := os.Getenv("XET_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	return remoteConfiguration{
		dsn: required("XET_POSTGRES_DSN"), endpoint: required("XET_S3_ENDPOINT"),
		bucket: required("XET_S3_BUCKET"), accessKey: required("XET_S3_ACCESS_KEY"),
		secretKey: required("XET_S3_SECRET_KEY"), region: region,
		pathStyle: os.Getenv("XET_S3_PATH_STYLE") != "false",
	}
}

func newRemoteS3(t testing.TB, configuration remoteConfiguration, prefix string) (*awss3.Client, *s3store.Store) {
	t.Helper()
	client := awss3.NewFromConfig(aws.Config{
		Region: configuration.region,
		Credentials: credentials.NewStaticCredentialsProvider(
			configuration.accessKey, configuration.secretKey, "",
		),
	}, func(options *awss3.Options) {
		options.BaseEndpoint = aws.String(configuration.endpoint)
		options.UsePathStyle = configuration.pathStyle
	})
	store, err := s3store.New(client, s3store.Options{
		Bucket: configuration.bucket, Prefix: prefix, TempDirectory: t.TempDir(), PresignExpiry: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, store
}

func ensureRemoteBucket(t testing.TB, client *awss3.Client, bucket string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String(bucket)}); err == nil {
		return
	}
	if os.Getenv("XET_S3_CREATE_BUCKET") != "1" {
		t.Fatal("remote-profile S3 bucket does not exist")
	}
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		if _, headErr := client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String(bucket)}); headErr != nil {
			t.Fatal("create remote-profile S3 bucket")
		}
	}
}

func newRemoteIndex(
	t testing.TB,
	configuration remoteConfiguration,
	schema string,
) (*pgxpool.Pool, *postgresstore.Store) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), configuration.dsn)
	if err != nil {
		t.Fatal("open remote-profile PostgreSQL pool")
	}
	store, err := postgresstore.New(context.Background(), pool, postgresstore.Options{Schema: schema})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool, store
}

func newRemoteService(
	t testing.TB,
	blobs casserver.BlobStore,
	signer casserver.RangeURLSigner,
	index casserver.IndexStore,
	namespace string,
	now time.Time,
) *casserver.Service {
	t.Helper()
	options := casserver.Options{
		Blobs: blobs, Index: index, Signer: signer,
		Authorizer:           casserver.AllowAllAuthorizer{Namespace: namespace},
		DedupProtectionKey:   xethash.Chunk([]byte("remote-profile-dedup-protection")),
		StagingProtectionTTL: 3 * time.Second,
		ReadLeaseTTL:         3 * time.Second,
	}
	if !now.IsZero() {
		options.Now = func() time.Time { return now }
	}
	service, err := casserver.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type remoteFixture struct {
	object    *xorb.Object
	shard     shard.Shard
	shardBody []byte
	shardKey  casserver.BlobKey
	contents  []byte
}

func makeRemoteFixture(t testing.TB, seed string) remoteFixture {
	t.Helper()
	chunks := [][]byte{
		bytes.Repeat([]byte(seed+"-remote-a"), 2_000),
		bytes.Repeat([]byte(seed+"-remote-b"), 2_300),
		bytes.Repeat([]byte(seed+"-remote-c"), 1_700),
	}
	object, err := xorb.Encode(chunks, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]xethash.Node, len(chunks))
	hashes := make([]xethash.Hash, len(chunks))
	var contents []byte
	for index, chunk := range chunks {
		hashes[index] = xethash.Chunk(chunk)
		nodes[index] = xethash.Node{Hash: hashes[index], Size: uint64(len(chunk))}
		contents = append(contents, chunk...)
	}
	sum := sha256.Sum256(contents)
	value := shard.Shard{
		Files: []shard.File{{
			Hash: xethash.File(nodes),
			Terms: []shard.Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(contents)), Start: 0, End: uint32(len(chunks)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []shard.Xorb{xorbInfo},
	}
	body, err := shard.EncodeUpload(value)
	if err != nil {
		t.Fatal(err)
	}
	full, err := shard.EncodeFull(value)
	if err != nil {
		t.Fatal(err)
	}
	return remoteFixture{
		object: object, shard: value, shardBody: body,
		shardKey: casserver.BlobKey{Kind: casserver.BlobShard, Hash: xethash.Chunk(full)},
		contents: contents,
	}
}

type faultIndex struct {
	*postgresstore.Store
	putStageErr, publishShardErr, deleteStageErr, deleteStageAppliedErr error
}

func (f *faultIndex) PutBlobStage(ctx context.Context, stage casserver.BlobStage) error {
	if f.putStageErr != nil {
		return f.putStageErr
	}
	return f.Store.PutBlobStage(ctx, stage)
}

func (f *faultIndex) PublishShard(ctx context.Context, publication casserver.ShardPublication) error {
	if f.publishShardErr != nil {
		return f.publishShardErr
	}
	return f.Store.PublishShard(ctx, publication)
}

func (f *faultIndex) DeleteBlobStage(
	ctx context.Context,
	namespace string,
	id casserver.ProtectionID,
) error {
	if f.deleteStageErr != nil {
		return f.deleteStageErr
	}
	if err := f.Store.DeleteBlobStage(ctx, namespace, id); err != nil {
		return err
	}
	return f.deleteStageAppliedErr
}

type appliedBlobFailure struct {
	casserver.BlobStore
	err error
}

func (s appliedBlobFailure) PutIfAbsent(
	ctx context.Context,
	key casserver.BlobKey,
	body io.Reader,
	size int64,
) (bool, error) {
	if _, err := s.BlobStore.PutIfAbsent(ctx, key, body, size); err != nil {
		return false, err
	}
	return false, s.err
}

type processBarrierBlobStore struct {
	casserver.BlobStore
	directory, participant string
}

func (s processBarrierBlobStore) PutIfAbsent(
	ctx context.Context,
	key casserver.BlobKey,
	body io.Reader,
	size int64,
) (bool, error) {
	ready := filepath.Join(s.directory, "ready-"+string(key.Kind)+"-"+s.participant)
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		return false, fmt.Errorf("write remote-profile process barrier: %w", err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		bothReady := true
		for _, participant := range []string{"0", "1"} {
			if _, err := os.Stat(filepath.Join(s.directory, "ready-"+string(key.Kind)+"-"+participant)); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return false, fmt.Errorf("inspect remote-profile process barrier: %w", err)
				}
				bothReady = false
			}
		}
		if bothReady {
			return s.BlobStore.PutIfAbsent(ctx, key, body, size)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
		}
	}
}

type remoteProcessResult struct {
	XorbInserted  bool `json:"xorb_inserted"`
	ShardInserted bool `json:"shard_inserted"`
}

// TestRemoteProfileProcessHelper is entered only by subprocesses launched by
// TestS3PostgreSQLRemoteProfile. Two independent processes race the same
// idempotent publication against one S3 prefix and PostgreSQL schema.
func TestRemoteProfileProcessHelper(t *testing.T) {
	if os.Getenv(remoteHelperMode) != "upload" {
		t.Skip("remote-profile subprocess helper")
	}
	configuration := remoteIntegrationConfiguration(t)
	schema, prefix := os.Getenv("XET_REMOTE_PROFILE_SCHEMA"), os.Getenv("XET_REMOTE_PROFILE_PREFIX")
	barrier, participant := os.Getenv("XET_REMOTE_PROFILE_BARRIER"), os.Getenv("XET_REMOTE_PROFILE_PARTICIPANT")
	if schema == "" || prefix == "" || barrier == "" || participant == "" {
		t.Fatal("remote-profile subprocess schema, prefix, barrier, and participant are required")
	}
	_, blobs := newRemoteS3(t, configuration, prefix)
	pool, index := newRemoteIndex(t, configuration, schema)
	defer pool.Close()
	barrierBlobs := processBarrierBlobStore{
		BlobStore: blobs, directory: barrier, participant: participant,
	}
	service := newRemoteService(t, barrierBlobs, blobs, index, "remote-process", time.Time{})
	fixture := makeRemoteFixture(t, "multiprocess")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	xorbInserted, err := service.UploadXorb(
		ctx, "", xetcas.DefaultXorbPrefix, fixture.object.Hash,
		bytes.NewReader(fixture.object.Body), int64(len(fixture.object.Body)),
	)
	if err != nil {
		t.Fatal(err)
	}
	shardResult, err := service.UploadShard(
		ctx, "", bytes.NewReader(fixture.shardBody), int64(len(fixture.shardBody)),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(remoteProcessResult{
		XorbInserted: xorbInserted, ShardInserted: shardResult.Inserted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(barrier, "result-"+participant+".json"), result, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestS3PostgreSQLRemoteProfile(t *testing.T) {
	if os.Getenv("XET_S3_INTEGRATION") != "1" || os.Getenv("XET_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set both XET_S3_INTEGRATION=1 and XET_POSTGRES_INTEGRATION=1")
	}
	configuration := remoteIntegrationConfiguration(t)
	unique := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano())
	schema := "xet_remote_test_" + unique
	prefix := "xet-go-remote-profile/" + unique
	rootClient, blobs := newRemoteS3(t, configuration, prefix)
	ensureRemoteBucket(t, rootClient, configuration.bucket)
	cleanupPool, err := pgxpool.New(context.Background(), configuration.dsn)
	if err != nil {
		t.Fatal("open cleanup PostgreSQL pool")
	}
	t.Cleanup(func() {
		defer cleanupPool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, dropErr := cleanupPool.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); dropErr != nil {
			t.Error("drop remote-profile PostgreSQL schema")
		}
	})
	t.Cleanup(func() { cleanupRemoteObjects(t, rootClient, configuration.bucket, prefix) })

	pool, index := newRemoteIndex(t, configuration, schema)
	defer func() { pool.Close() }()
	restart := func() {
		pool.Close()
		_, blobs = newRemoteS3(t, configuration, prefix)
		pool, index = newRemoteIndex(t, configuration, schema)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fixedNow := time.Date(2026, time.August, 11, 3, 0, 0, 123, time.UTC)
	fault := errors.New("injected remote publication failure")

	t.Run("stage failure writes no object", func(t *testing.T) {
		fixture := makeRemoteFixture(t, "stage-failure")
		faulted := &faultIndex{Store: index, putStageErr: fault}
		service := newRemoteService(t, blobs, blobs, faulted, "remote-fault", fixedNow)
		if _, err := service.UploadXorb(
			ctx, "", xetcas.DefaultXorbPrefix, fixture.object.Hash,
			bytes.NewReader(fixture.object.Body), int64(len(fixture.object.Body)),
		); !errors.Is(err, fault) {
			t.Fatalf("stage failure = %v", err)
		}
		key := casserver.BlobKey{Kind: casserver.BlobXorb, Hash: fixture.object.Hash}
		if _, found, err := blobs.Head(ctx, key); err != nil || found {
			t.Fatalf("object after stage failure = %v, %v", found, err)
		}
		if stages, err := index.ListBlobStages(ctx, nil, casserver.PageRequest{}); err != nil || len(stages.Items) != 0 {
			t.Fatalf("stages after stage failure = %#v, %v", stages, err)
		}
	})

	t.Run("applied blob with lost response recovers after restart", func(t *testing.T) {
		fixture := makeRemoteFixture(t, "blob-ambiguity")
		ambiguous := appliedBlobFailure{BlobStore: blobs, err: fault}
		service := newRemoteService(t, ambiguous, blobs, index, "remote-fault", fixedNow)
		if _, err := service.UploadXorb(
			ctx, "", xetcas.DefaultXorbPrefix, fixture.object.Hash,
			bytes.NewReader(fixture.object.Body), int64(len(fixture.object.Body)),
		); !errors.Is(err, fault) {
			t.Fatalf("ambiguous blob write = %v", err)
		}
		key := casserver.BlobKey{Kind: casserver.BlobXorb, Hash: fixture.object.Hash}
		if _, found, err := blobs.Head(ctx, key); err != nil || !found {
			t.Fatalf("applied ambiguous object = %v, %v", found, err)
		}
		if _, found, err := index.GetXorb(ctx, fixture.object.Hash); err != nil || found {
			t.Fatalf("index before recovery = %v, %v", found, err)
		}
		stage := requireOneRemoteStage(t, ctx, index)
		restart()
		recoverOneRemoteStage(t, ctx, blobs, index, stage.ExpiresAt)
		if _, found, err := index.GetXorb(ctx, fixture.object.Hash); err != nil || !found {
			t.Fatalf("index after recovery = %v, %v", found, err)
		}
	})

	var shardFixture remoteFixture
	t.Run("failed shard index publication recovers after restart", func(t *testing.T) {
		shardFixture = makeRemoteFixture(t, "shard-publication")
		service := newRemoteService(t, blobs, blobs, index, "remote-fault", fixedNow)
		if _, err := service.UploadXorb(
			ctx, "", xetcas.DefaultXorbPrefix, shardFixture.object.Hash,
			bytes.NewReader(shardFixture.object.Body), int64(len(shardFixture.object.Body)),
		); err != nil {
			t.Fatal(err)
		}
		faulted := &faultIndex{Store: index, publishShardErr: fault}
		service = newRemoteService(t, blobs, blobs, faulted, "remote-fault", fixedNow)
		if _, err := service.UploadShard(
			ctx, "", bytes.NewReader(shardFixture.shardBody), int64(len(shardFixture.shardBody)),
		); !errors.Is(err, fault) {
			t.Fatalf("failed shard publication = %v", err)
		}
		if _, found, err := blobs.Head(ctx, shardFixture.shardKey); err != nil || !found {
			t.Fatalf("shard object before recovery = %v, %v", found, err)
		}
		fileHash := shardFixture.shard.Files[0].Hash
		if _, found, err := index.GetFile(ctx, "remote-fault", fileHash); err != nil || found {
			t.Fatalf("file before recovery = %v, %v", found, err)
		}
		stage := requireOneRemoteStage(t, ctx, index)
		restart()
		recoverOneRemoteStage(t, ctx, blobs, index, stage.ExpiresAt)
		assertRemoteFile(t, ctx, blobs, index, "remote-fault", shardFixture)
	})

	t.Run("failed stage deletion retains a recovery root", func(t *testing.T) {
		fixture := makeRemoteFixture(t, "delete-ambiguity")
		faulted := &faultIndex{Store: index, deleteStageErr: fault}
		service := newRemoteService(t, blobs, blobs, faulted, "remote-fault", fixedNow)
		if _, err := service.UploadXorb(
			ctx, "", xetcas.DefaultXorbPrefix, fixture.object.Hash,
			bytes.NewReader(fixture.object.Body), int64(len(fixture.object.Body)),
		); !errors.Is(err, fault) {
			t.Fatalf("failed stage deletion = %v", err)
		}
		if _, found, err := index.GetXorb(ctx, fixture.object.Hash); err != nil || !found {
			t.Fatalf("published index before retry = %v, %v", found, err)
		}
		stage := requireOneRemoteStage(t, ctx, index)
		restart()
		recoverOneRemoteStage(t, ctx, blobs, index, stage.ExpiresAt)
	})

	t.Run("applied stage deletion with lost response retries idempotently", func(t *testing.T) {
		fixture := makeRemoteFixture(t, "delete-applied-ambiguity")
		faulted := &faultIndex{Store: index, deleteStageAppliedErr: fault}
		service := newRemoteService(t, blobs, blobs, faulted, "remote-fault", fixedNow)
		if _, err := service.UploadXorb(
			ctx, "", xetcas.DefaultXorbPrefix, fixture.object.Hash,
			bytes.NewReader(fixture.object.Body), int64(len(fixture.object.Body)),
		); !errors.Is(err, fault) {
			t.Fatalf("ambiguous applied stage deletion = %v", err)
		}
		if _, found, err := index.GetXorb(ctx, fixture.object.Hash); err != nil || !found {
			t.Fatalf("published index before retry = %v, %v", found, err)
		}
		if stages, err := index.ListBlobStages(ctx, nil, casserver.PageRequest{}); err != nil || len(stages.Items) != 0 {
			t.Fatalf("stages after applied deletion = %#v, %v", stages, err)
		}
		restart()
		service = newRemoteService(t, blobs, blobs, index, "remote-fault", fixedNow)
		inserted, err := service.UploadXorb(
			ctx, "", xetcas.DefaultXorbPrefix, fixture.object.Hash,
			bytes.NewReader(fixture.object.Body), int64(len(fixture.object.Body)),
		)
		if err != nil || inserted {
			t.Fatalf("retry after applied stage deletion = %v, %v", inserted, err)
		}
	})

	pool.Close()
	runRemoteProfileProcesses(t, ctx, schema, prefix, t.TempDir())
	_, blobs = newRemoteS3(t, configuration, prefix)
	pool, index = newRemoteIndex(t, configuration, schema)
	multiprocessFixture := makeRemoteFixture(t, "multiprocess")
	assertRemoteFile(t, ctx, blobs, index, "remote-process", multiprocessFixture)
	if stages, err := index.ListBlobStages(ctx, nil, casserver.PageRequest{}); err != nil || len(stages.Items) != 0 {
		t.Fatalf("stages after all remote publications = %#v, %v", stages, err)
	}
}

func requireOneRemoteStage(
	t testing.TB,
	ctx context.Context,
	index *postgresstore.Store,
) casserver.BlobStage {
	t.Helper()
	stages, err := index.ListBlobStages(ctx, nil, casserver.PageRequest{})
	if err != nil || len(stages.Items) != 1 {
		t.Fatalf("remote publication stages = %#v, %v", stages, err)
	}
	return stages.Items[0]
}

func recoverOneRemoteStage(
	t testing.TB,
	ctx context.Context,
	blobs *s3store.Store,
	index *postgresstore.Store,
	cutoff time.Time,
) {
	t.Helper()
	service := newRemoteService(t, blobs, blobs, index, "unused-recovery-scope", time.Time{})
	page, err := service.RecoverExpiredBlobStages(ctx, cutoff, casserver.PageRequest{})
	if err != nil || len(page.Items) != 1 ||
		page.Items[0].Status != casserver.BlobStageRecoveryPublishedRemoved || page.NextCursor != "" {
		t.Fatalf("remote stage recovery = %#v, %v", page, err)
	}
}

func assertRemoteFile(
	t testing.TB,
	ctx context.Context,
	blobs *s3store.Store,
	index *postgresstore.Store,
	namespace string,
	fixture remoteFixture,
) {
	t.Helper()
	service := newRemoteService(t, blobs, blobs, index, namespace, time.Time{})
	fileHash := fixture.shard.Files[0].Hash
	opened, err := service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(opened.Body)
	closeErr := opened.Body.Close()
	if errors.Join(readErr, closeErr) != nil || !bytes.Equal(got, fixture.contents) {
		t.Fatalf("remote full file = %d bytes, %v, %v", len(got), readErr, closeErr)
	}
	wanted := xetcas.FileRange{Start: 97, End: uint64(len(fixture.contents) - 113)}
	opened, err = service.OpenFile(ctx, "", fileHash, &wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr = io.ReadAll(opened.Body)
	closeErr = opened.Body.Close()
	if errors.Join(readErr, closeErr) != nil || !bytes.Equal(got, fixture.contents[wanted.Start:wanted.End]) {
		t.Fatalf("remote ranged file = %d bytes, %v, %v", len(got), readErr, closeErr)
	}
	other := newRemoteService(t, blobs, blobs, index, namespace+"-other", time.Time{})
	if _, err := other.OpenFile(ctx, "", fileHash, nil); !errors.Is(err, casserver.ErrNotFound) {
		t.Fatalf("cross-namespace remote file = %v", err)
	}
}

func runRemoteProfileProcesses(
	t testing.TB,
	ctx context.Context,
	schema, prefix, barrier string,
) {
	t.Helper()
	childContext, cancelChildren := context.WithCancel(ctx)
	defer cancelChildren()
	commands := make([]*exec.Cmd, 2)
	outputs := make([]bytes.Buffer, len(commands))
	started := 0
	var startError error
	for index := range commands {
		command := exec.CommandContext(
			childContext, os.Args[0], "-test.run=^TestRemoteProfileProcessHelper$", "-test.count=1", "-test.timeout=90s",
		)
		command.Env = append(os.Environ(),
			remoteHelperMode+"=upload",
			"XET_REMOTE_PROFILE_SCHEMA="+schema,
			"XET_REMOTE_PROFILE_PREFIX="+prefix,
			"XET_REMOTE_PROFILE_BARRIER="+barrier,
			fmt.Sprintf("XET_REMOTE_PROFILE_PARTICIPANT=%d", index),
		)
		command.Stdout, command.Stderr = &outputs[index], &outputs[index]
		if err := command.Start(); err != nil {
			startError = err
			cancelChildren()
			break
		}
		commands[index] = command
		started++
	}
	type processWait struct {
		index int
		err   error
	}
	waits := make(chan processWait, started)
	for index := range started {
		go func() { waits <- processWait{index: index, err: commands[index].Wait()} }()
	}
	var failures []string
	for range started {
		result := <-waits
		if result.err != nil {
			cancelChildren()
			failures = append(failures, fmt.Sprintf(
				"process %d: %v\n%s", result.index, result.err,
				strings.TrimSpace(outputs[result.index].String()),
			))
		}
	}
	if startError != nil {
		failures = append(failures, "start process: "+startError.Error())
	}
	if len(failures) != 0 {
		t.Fatalf("remote-profile processes failed:\n%s", strings.Join(failures, "\n"))
	}
	results := make([]remoteProcessResult, len(commands))
	for index := range results {
		body, err := os.ReadFile(filepath.Join(barrier, fmt.Sprintf("result-%d.json", index)))
		if err != nil || json.Unmarshal(body, &results[index]) != nil {
			t.Fatalf("remote-profile process %d result is invalid", index)
		}
	}
	if results[0].XorbInserted == results[1].XorbInserted ||
		results[0].ShardInserted == results[1].ShardInserted {
		t.Fatalf("remote-profile insert ownership = %#v", results)
	}
}

func cleanupRemoteObjects(t testing.TB, client *awss3.Client, bucket, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Error("list remote-profile S3 cleanup objects")
			return
		}
		for _, object := range page.Contents {
			if object.Key == nil {
				continue
			}
			if _, err := client.DeleteObject(ctx, &awss3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: object.Key,
			}); err != nil {
				t.Error("delete remote-profile S3 cleanup object")
			}
		}
	}
}
