package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/xethash"
)

func testOID(t testing.TB, value byte) OID {
	t.Helper()
	text := strings.Repeat(hex.EncodeToString([]byte{value}), 20)
	oid, err := ParseOID(text)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func testSnapshot(t testing.TB) Snapshot {
	t.Helper()
	repo, err := NewRepoKey("team", "Model_1", RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	blobSum := sha256.Sum256([]byte("config"))
	xetSum := sha256.Sum256([]byte("weights"))
	blobRef, err := NewBlobFileRef(blobSum, 6)
	if err != nil {
		t.Fatal(err)
	}
	xetRef, err := NewXetFileRef(xethash.Chunk([]byte("weights")), 7, &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{
		Repo: repo, OID: testOID(t, 1), CreatedAt: time.Date(2026, 8, 11, 12, 30, 0, 123, time.FixedZone("offset", 3600)),
		Author: Identity{Name: "Miniface", Email: "operator@example.com"}, Message: "Initial model",
		Files: []FileEntry{
			{Path: "weights/model.safetensors", Ref: xetRef},
			{Path: "config.json", Ref: blobRef},
		},
	}
}

func TestRepoKeyValidation(t *testing.T) {
	for _, valid := range []RepoKey{
		{Namespace: "team", Name: "model", Type: RepoTypeModel},
		{Namespace: "Équipe", Name: "模型_1", Type: RepoTypeModel},
		{Namespace: "_team_", Name: "Model.Name", Type: RepoTypeModel},
	} {
		if err := ValidateRepoKey(valid); err != nil {
			t.Fatalf("valid key %#v: %v", valid, err)
		}
	}
	for name, invalid := range map[string]RepoKey{
		"type":       {Namespace: "team", Name: "model", Type: "dataset"},
		"empty":      {Name: "model", Type: RepoTypeModel},
		"slash":      {Namespace: "team/a", Name: "model", Type: RepoTypeModel},
		"leading":    {Namespace: "team", Name: ".model", Type: RepoTypeModel},
		"reserved":   {Namespace: "team", Name: "model..v2", Type: RepoTypeModel},
		"git suffix": {Namespace: "team", Name: "model.git", Type: RepoTypeModel},
		"decomposed": {Namespace: Namespace("E\u0301quipe"), Name: "model", Type: RepoTypeModel},
		"oversized":  {Namespace: "team", Name: RepoName(strings.Repeat("a", MaxRepoNameRunes+1)), Type: RepoTypeModel},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRepoKey(invalid); err == nil {
				t.Fatalf("invalid key accepted: %#v", invalid)
			}
		})
	}
	upper := RepoKey{Namespace: "Team", Name: "Model", Type: RepoTypeModel}
	lower := RepoKey{Namespace: "team", Name: "model", Type: RepoTypeModel}
	if err := ValidateRepoKey(upper); err != nil || upper == lower {
		t.Fatalf("case-sensitive keys = %#v/%#v, %v", upper, lower, err)
	}
	if _, err := NewRepoKey("../bad", "model", RepoTypeModel); err == nil {
		t.Fatal("NewRepoKey accepted invalid namespace")
	}
	if _, err := NewRepoKey("team", "../bad", RepoTypeModel); err == nil {
		t.Fatal("NewRepoKey accepted invalid name")
	}
	if _, err := NewRepoKey("team", "model", "dataset"); err == nil {
		t.Fatal("NewRepoKey accepted unsupported type")
	}
	if _, err := ParseNamespace("../bad"); err == nil {
		t.Fatal("ParseNamespace accepted invalid value")
	}
	if _, err := ParseRepoName("../bad"); err == nil {
		t.Fatal("ParseRepoName accepted invalid value")
	}
}

func TestOIDAndRevisionParsing(t *testing.T) {
	oid := testOID(t, 0xab)
	if oid.String() != strings.Repeat("ab", 20) {
		t.Fatalf("OID text = %q", oid)
	}
	for _, invalid := range []string{"", strings.Repeat("0", 40), strings.Repeat("A", 40), strings.Repeat("a", 39), strings.Repeat("g", 40)} {
		if _, err := ParseOID(invalid); err == nil {
			t.Fatalf("invalid OID %q accepted", invalid)
		}
	}
	revision, err := ParseRevision(oid.String())
	if parsed, ok := revision.OID(); err != nil || !ok || parsed != oid {
		t.Fatalf("OID revision = %v/%v, %v", parsed, ok, err)
	}
	revision, err = ParseRevision("feature/model-v2")
	if parsed, ok := revision.Ref(); err != nil || !ok || parsed != "feature/model-v2" {
		t.Fatalf("ref revision = %v/%v, %v", parsed, ok, err)
	}
	if _, err := ParseRefName(oid.String()); err == nil {
		t.Fatal("OID-like ref accepted")
	}
	upperOIDLike := strings.Repeat("AB", 20)
	if ref, err := ParseRefName(upperOIDLike); err != nil || string(ref) != upperOIDLike {
		t.Fatalf("distinguishable uppercase ref = %q, %v", ref, err)
	}
	fromOID, err := RevisionFromOID(oid)
	if err != nil || fromOID.String() != oid.String() {
		t.Fatalf("RevisionFromOID = %q, %v", fromOID, err)
	}
	if _, ok := fromOID.Ref(); ok {
		t.Fatal("OID revision exposed ref")
	}
	if _, err := RevisionFromOID(OID{}); err == nil {
		t.Fatal("RevisionFromOID accepted zero")
	}
	fromRef, err := RevisionFromRef("main")
	if err != nil || fromRef.String() != "main" {
		t.Fatalf("RevisionFromRef = %q, %v", fromRef, err)
	}
	if _, ok := fromRef.OID(); ok {
		t.Fatal("ref revision exposed OID")
	}
	if _, err := RevisionFromRef("../bad"); err == nil {
		t.Fatal("RevisionFromRef accepted invalid ref")
	}
	if (Revision{}).String() != "" {
		t.Fatal("zero revision has nonempty text")
	}
	if _, err := ParseRevision("../bad"); err == nil {
		t.Fatal("ParseRevision accepted invalid revision")
	}
}

func TestPathAndRefValidation(t *testing.T) {
	for _, valid := range []string{"config.json", "tokenizer/模型.json", ".hidden"} {
		if path, err := ParseFilePath(valid); err != nil || string(path) != valid {
			t.Fatalf("valid path %q = %q, %v", valid, path, err)
		}
	}
	for _, invalid := range []string{"", "/root", "trailing/", "a//b", "a/../b", "a/.git/b", "a/.cache/b", "a\\b", "E\u0301.json", "a\x00b", "a\u200bb"} {
		if _, err := ParseFilePath(invalid); err == nil {
			t.Fatalf("invalid path %q accepted", invalid)
		}
	}
	for _, valid := range []string{"main", "feature/model-v2", "版本/一"} {
		if ref, err := ParseRefName(valid); err != nil || string(ref) != valid {
			t.Fatalf("valid ref %q = %q, %v", valid, ref, err)
		}
	}
	for _, invalid := range []string{"", "/main", "main/", "a//b", "a..b", "@", "a.lock", "a/@{b", "a b", "a~b", ".hidden/main", "a\ufeffb"} {
		if _, err := ParseRefName(invalid); err == nil {
			t.Fatalf("invalid ref %q accepted", invalid)
		}
	}
	for _, valid := range []string{"", "token", "tokenizer/"} {
		if prefix, err := ParseFilePrefix(valid); err != nil || string(prefix) != valid {
			t.Fatalf("valid prefix %q = %q, %v", valid, prefix, err)
		}
	}
	for _, invalid := range []string{"/", "tokenizer//", "../models", "a\\b"} {
		if _, err := ParseFilePrefix(invalid); err == nil {
			t.Fatalf("invalid prefix %q accepted", invalid)
		}
	}
}

func TestFileRefInvariants(t *testing.T) {
	zeroSHA := [32]byte{}
	blob, err := NewBlobFileRef(zeroSHA, 0)
	if err != nil {
		t.Fatalf("zero-byte blob with explicit zero SHA: %v", err)
	}
	if sum, present := blob.SHA256(); !present || sum != zeroSHA || blob.Kind() != FileKindBlob || blob.FileSize() != 0 {
		t.Fatalf("blob reference = %#v, %x/%v", blob, sum, present)
	}
	if _, present := blob.XetHash(); present {
		t.Fatal("blob exposes Xet identity")
	}

	empty, err := NewXetFileRef(xethash.Zero, 0, nil)
	if err != nil {
		t.Fatalf("empty Xet file: %v", err)
	}
	if sum, present := empty.SHA256(); present || sum != zeroSHA {
		t.Fatalf("absent Xet SHA = %x/%v", sum, present)
	}
	withSHA, err := NewXetFileRef(xethash.Zero, 0, &zeroSHA)
	if err != nil {
		t.Fatalf("empty Xet file with SHA: %v", err)
	}
	zeroSHA[0] = 1
	if sum, present := withSHA.SHA256(); !present || sum != ([32]byte{}) {
		t.Fatalf("Xet SHA aliases constructor input: %x/%v", sum, present)
	}
	if _, err := NewXetFileRef(xethash.Zero, 1, nil); err == nil {
		t.Fatal("nonempty Xet file accepted with zero identity")
	}
	if _, err := NewXetFileRef(xethash.Chunk([]byte("x")), 0, nil); err == nil {
		t.Fatal("empty Xet file accepted with nonzero identity")
	}
	if _, err := NewBlobFileRef([32]byte{}, -1); err == nil {
		t.Fatal("negative blob accepted")
	}
}

func TestCanonicalSnapshotAndFingerprint(t *testing.T) {
	snapshot := testSnapshot(t)
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Files[0].Path != "config.json" || canonical.Files[1].Path != "weights/model.safetensors" ||
		canonical.CreatedAt.Location() != time.UTC {
		t.Fatalf("canonical snapshot = %#v", canonical)
	}
	digest, err := FingerprintSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "362fbbf4c5ee8ec46256dce813ca0ec4f670415f61be246f71257ccb586356d6"
	if hex.EncodeToString(digest[:]) != expected {
		t.Fatalf("snapshot digest = %x, want %s", digest, expected)
	}
	reordered := snapshot
	reordered.Files = []FileEntry{snapshot.Files[1], snapshot.Files[0]}
	reorderedDigest, err := FingerprintSnapshot(reordered)
	if err != nil || reorderedDigest != digest {
		t.Fatalf("reordered digest = %x, %v", reorderedDigest, err)
	}
	reordered.Message = "Changed"
	changed, err := FingerprintSnapshot(reordered)
	if err != nil || changed == digest {
		t.Fatalf("changed digest = %x, %v", changed, err)
	}
	reordered.Message = snapshot.Message
	reordered.OID = testOID(t, 2)
	otherOID, err := FingerprintSnapshot(reordered)
	if err != nil || otherOID != digest {
		t.Fatalf("OID affected immutable digest = %x, %v", otherOID, err)
	}
	parent := testOID(t, 9)
	withParent := snapshot
	withParent.Parent = &parent
	withParent.OID = testOID(t, 10)
	info := withParent.Info()
	if info.Parent == nil || *info.Parent != parent || info.FileCount != 2 {
		t.Fatalf("snapshot info = %#v", info)
	}
	parent = testOID(t, 11)
	if *info.Parent == parent {
		t.Fatal("snapshot info aliases parent")
	}
	emptyRef, err := NewXetFileRef(xethash.Zero, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	withParent.Files = []FileEntry{{Path: "empty", Ref: emptyRef}}
	if _, err := FingerprintSnapshot(withParent); err != nil {
		t.Fatalf("fingerprint parent and absent SHA: %v", err)
	}
}

func TestCanonicalSnapshotRejectsInvalidAndClones(t *testing.T) {
	snapshot := testSnapshot(t)
	duplicate := snapshot
	duplicate.Files = append(append([]FileEntry(nil), snapshot.Files...), snapshot.Files[0])
	if _, err := CanonicalSnapshot(duplicate); err == nil {
		t.Fatal("duplicate path accepted")
	}
	for name, mutate := range map[string]func(*Snapshot){
		"invalid repo":    func(value *Snapshot) { value.Repo.Name = "../bad" },
		"zero OID":        func(value *Snapshot) { value.OID = OID{} },
		"self parent":     func(value *Snapshot) { value.Parent = &value.OID },
		"zero parent":     func(value *Snapshot) { value.Parent = &OID{} },
		"zero time":       func(value *Snapshot) { value.CreatedAt = time.Time{} },
		"overflow time":   func(value *Snapshot) { value.CreatedAt = time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"missing author":  func(value *Snapshot) { value.Author.Name = "" },
		"bad email":       func(value *Snapshot) { value.Author.Email = "a\nb" },
		"missing message": func(value *Snapshot) { value.Message = "" },
		"invalid message": func(value *Snapshot) { value.Message = string([]byte{0xff}) },
		"long message":    func(value *Snapshot) { value.Message = strings.Repeat("a", MaxMessageBytes+1) },
		"invalid path":    func(value *Snapshot) { value.Files[0].Path = "../bad" },
		"zero ref":        func(value *Snapshot) { value.Files[0].Ref = FileRef{} },
		"negative blob": func(value *Snapshot) {
			value.Files[1].Ref.size = -1
		},
		"zero Xet": func(value *Snapshot) {
			value.Files[0].Ref.xetHash = xethash.Zero
		},
		"blob with Xet hash": func(value *Snapshot) {
			value.Files[1].Ref.xetHash = xethash.Chunk([]byte("invalid"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := testSnapshot(t)
			mutate(&value)
			if _, err := CanonicalSnapshot(value); err == nil {
				t.Fatalf("invalid snapshot accepted: %#v", value)
			}
		})
	}
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	*snapshot.Files[0].Ref.sha256 = [32]byte{9}
	snapshot.Files[1].Path = "changed"
	refSHA, present := canonical.Files[1].Ref.SHA256()
	if canonical.Files[0].Path != "config.json" || canonical.Files[1].Path != "weights/model.safetensors" ||
		!present || refSHA == ([32]byte{9}) {
		t.Fatalf("canonical snapshot aliases caller data: %#v", canonical)
	}
	clone := CloneSnapshot(canonical)
	clone.Parent = &clone.OID
	*clone.Files[1].Ref.sha256 = [32]byte{8}
	sha, _ := canonical.Files[1].Ref.SHA256()
	if canonical.Parent != nil || sha == ([32]byte{8}) {
		t.Fatalf("snapshot clone aliases source: %#v", canonical)
	}
}

func TestCanonicalSnapshotRejectsFileDirectoryCollisions(t *testing.T) {
	for name, paths := range map[string][]FilePath{
		"direct": {"a", "a/b"},
		"nested": {"dir/file", "dir/file/child"},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := testSnapshot(t)
			ref := snapshot.Files[0].Ref
			snapshot.Files = []FileEntry{{Path: paths[0], Ref: ref}, {Path: paths[1], Ref: ref}}
			if _, err := CanonicalSnapshot(snapshot); err == nil {
				t.Fatalf("file/directory collision accepted: %v", paths)
			}
		})
	}
	snapshot := testSnapshot(t)
	ref := snapshot.Files[0].Ref
	snapshot.Files = []FileEntry{{Path: "a", Ref: ref}, {Path: "ab/file", Ref: ref}}
	if _, err := CanonicalSnapshot(snapshot); err != nil {
		t.Fatalf("unrelated shared prefix rejected: %v", err)
	}
}

func TestRepositoryAndRefValidation(t *testing.T) {
	repository := Repository{Key: testSnapshot(t).Repo, CreatedAt: time.Date(2026, 8, 11, 12, 0, 0, 0, time.FixedZone("offset", 3600))}
	canonical, err := CanonicalRepository(repository)
	if err != nil || canonical.CreatedAt.Location() != time.UTC {
		t.Fatalf("canonical repository = %#v, %v", canonical, err)
	}
	if _, err := CanonicalRepository(Repository{Key: repository.Key}); err == nil {
		t.Fatal("repository with zero creation time accepted")
	}
	if _, err := CanonicalRepository(Repository{Key: RepoKey{}, CreatedAt: time.Unix(1, 0)}); err == nil {
		t.Fatal("repository with invalid key accepted")
	}
	ref := Ref{Repo: repository.Key, Name: "main", OID: testOID(t, 4)}
	if err := ValidateRef(ref); err != nil {
		t.Fatalf("valid ref: %v", err)
	}
	ref.OID = OID{}
	if err := ValidateRef(ref); err == nil {
		t.Fatal("ref with zero OID accepted")
	}
	ref.OID = testOID(t, 5)
	ref.Name = "../bad"
	if err := ValidateRef(ref); err == nil {
		t.Fatal("ref with invalid name accepted")
	}
	ref.Name = "main"
	ref.Repo = RepoKey{}
	if err := ValidateRef(ref); err == nil {
		t.Fatal("ref with invalid repository accepted")
	}
}
