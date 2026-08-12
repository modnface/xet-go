package hosted

import (
	"context"
	"errors"
	"testing"

	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestServiceExposesTrustedBucketCloneCapability(t *testing.T) {
	options, _ := validOptions(t)
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	var _ interface {
		CloneXetFile(context.Context, model.RepoKey, model.RepoKey, xethash.Hash, uint64, *[32]byte) error
	} = service
	source, err := model.NewRepoKey("owner", "source", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := model.NewRepoKey("owner", "destination", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	missing := xethash.Chunk([]byte("missing hosted clone source"))
	if err := service.CloneXetFile(
		context.Background(), source, destination, missing, 123, nil,
	); !errors.Is(err, bucket.ErrContentNotUploaded) {
		t.Fatalf("hosted clone wiring = %v", err)
	}
}
