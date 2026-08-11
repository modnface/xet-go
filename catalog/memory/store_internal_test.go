package memory

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
)

func TestCursorValidationRejectsMalformedState(t *testing.T) {
	for _, value := range []string{"", "model\x00team", "dataset\x00team\x00repo", "model\x00../bad\x00repo"} {
		if validRepositorySortKey(value) {
			t.Fatalf("invalid repository sort key accepted: %q", value)
		}
	}
	for _, value := range []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{"kind":"repositories","unknown":true}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"kind":"repositories"}{}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"kind":"repositories"}garbage`)),
	} {
		if _, err := decodeCursor(value); err == nil {
			t.Fatalf("invalid cursor accepted: %q", value)
		}
	}
	if _, _, err := prepareSnapshotQuery(testRepoKey(), catalog.SnapshotQuery{
		Cursor: encodeCursor(cursor{Kind: "snapshots", Repository: "wrong", Last: "bad"}),
	}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("mismatched snapshot cursor = %v", err)
	}
	for _, value := range []cursor{
		{Kind: "snapshots", Repository: repositorySortKey(testRepoKey()), SnapshotOID: "bad"},
		{Kind: "snapshots", Repository: repositorySortKey(testRepoKey()), SnapshotUnixNanoseconds: int64Pointer(1), SnapshotOID: "bad"},
		{Kind: "files", Repository: repositorySortKey(testRepoKey()), Last: "bad", SnapshotOID: "bad"},
	} {
		if value.Kind == "snapshots" {
			if _, _, err := prepareSnapshotQuery(testRepoKey(), catalog.SnapshotQuery{Cursor: encodeCursor(value)}); !errors.Is(err, catalog.ErrInvalid) {
				t.Fatalf("invalid snapshot cursor %#v = %v", value, err)
			}
		} else if _, _, _, err := prepareFileQuery(testRepoKey(), catalog.FileQuery{Cursor: encodeCursor(value)}); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid file cursor %#v = %v", value, err)
		}
	}
}

func int64Pointer(value int64) *int64 { return &value }

func testRepoKey() (key model.RepoKey) {
	key, _ = model.NewRepoKey("team", "repo", model.RepoTypeModel)
	return key
}
