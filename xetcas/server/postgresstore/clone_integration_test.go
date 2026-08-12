package postgresstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func TestPostgreSQLCloneFileBetweenNamespacesIntegration(t *testing.T) {
	if os.Getenv("XET_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set XET_POSTGRES_INTEGRATION=1 with XET_POSTGRES_DSN to run")
	}
	dsn := os.Getenv("XET_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("XET_POSTGRES_DSN is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect PostgreSQL")
	}
	defer pool.Close()
	schema := "xet_cas_clone_" + randomIdentifier(t)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	index, err := New(ctx, pool, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	blobs := server.NewMemoryStore()
	service, err := server.New(server.Options{
		Blobs: blobs, Index: index,
		Authorizer: server.AllowAllAuthorizer{Namespace: "postgres-source"},
		Signer: server.RangeURLSignerFunc(func(context.Context, server.BlobKey, xetcas.HTTPRange) (server.SignedRange, error) {
			return server.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	chunks := [][]byte{bytes.Repeat([]byte("postgres-clone-a"), 200), bytes.Repeat([]byte("postgres-clone-b"), 300)}
	object, err := xorb.Encode(chunks, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, object.Hash,
		bytes.NewReader(object.Body), int64(len(object.Body))); err != nil {
		t.Fatal(err)
	}
	metadata, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	var logical []byte
	nodes := make([]xethash.Node, len(chunks))
	hashes := make([]xethash.Hash, len(chunks))
	for i, chunk := range chunks {
		logical = append(logical, chunk...)
		hashes[i] = xethash.Chunk(chunk)
		nodes[i] = xethash.Node{Hash: hashes[i], Size: uint64(len(chunk))}
	}
	hash := xethash.File(nodes)
	sum := sha256.Sum256(logical)
	shardBody, err := shard.EncodeUpload(shard.Shard{
		Xorbs: []shard.Xorb{metadata},
		Files: []shard.File{{Hash: hash, SHA256: &sum, Terms: []shard.Term{{
			XorbHash: object.Hash, Start: 0, End: uint32(len(chunks)), UnpackedBytes: uint32(len(logical)),
			Verification: xethash.Verification(hashes),
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}

	const destination = "postgres-destination"
	for range 2 {
		if err := service.CloneFileBetweenNamespaces(
			ctx, "postgres-source", destination, hash, uint64(len(logical)), &sum,
		); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := service.OpenFileInNamespace(ctx, destination, hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(opened.Body)
	closeErr := opened.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, logical) {
		t.Fatalf("PostgreSQL cloned stream = %d bytes, %v, %v", len(got), readErr, closeErr)
	}

	const conflictNamespace = "postgres-conflict"
	other := xethash.Chunk([]byte("other PostgreSQL file"))
	if err := index.PutSHA256(ctx, conflictNamespace, sum, uint64(len(logical)), other); err != nil {
		t.Fatal(err)
	}
	if err := service.CloneFileBetweenNamespaces(
		ctx, "postgres-source", conflictNamespace, hash, uint64(len(logical)), &sum,
	); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("PostgreSQL destination conflict = %v", err)
	}
	if _, found, err := index.GetFile(ctx, conflictNamespace, hash); err != nil || found {
		t.Fatalf("PostgreSQL file visible after conflict = %v, %v", found, err)
	}
	source, found, err := index.GetFile(ctx, "postgres-source", hash)
	if err != nil || !found {
		t.Fatalf("PostgreSQL source file = %#v, %v, %v", source, found, err)
	}
	if _, found, err := index.GetShard(ctx, conflictNamespace, source.Shard.Hash); err != nil || found {
		t.Fatalf("PostgreSQL shard visible after conflict = %v, %v", found, err)
	}
}
