// Package memory implements an ephemeral catalog with the same transactional
// semantics required of durable backends.
package memory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
)

var _ catalog.Catalog = (*Store)(nil)

type Store struct {
	mu    sync.RWMutex
	repos map[model.RepoKey]*repositoryState
}

type repositoryState struct {
	repository   model.Repository
	snapshots    map[model.OID]model.Snapshot
	fingerprints map[model.OID]model.SnapshotFingerprint
	refs         map[model.RefName]model.OID
}

type cursor struct {
	Kind                    string `json:"kind"`
	Namespace               string `json:"namespace,omitempty"`
	RepoType                string `json:"repo_type,omitempty"`
	Repository              string `json:"repository,omitempty"`
	Prefix                  string `json:"prefix,omitempty"`
	Last                    string `json:"last,omitempty"`
	SnapshotUnixNanoseconds *int64 `json:"snapshot_unix_nanoseconds,omitempty"`
	SnapshotOID             string `json:"snapshot_oid,omitempty"`
}

type snapshotPosition struct {
	timestamp int64
	oid       model.OID
	set       bool
}

type filePosition struct {
	snapshot model.OID
	path     model.FilePath
	set      bool
}

func New() *Store {
	return &Store{repos: make(map[model.RepoKey]*repositoryState)}
}

func (store *Store) CreateRepository(ctx context.Context, repository model.Repository) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, err := model.CanonicalRepository(repository)
	if err != nil {
		return invalid(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.repos == nil {
		store.repos = make(map[model.RepoKey]*repositoryState)
	}
	if _, exists := store.repos[canonical.Key]; exists {
		return fmt.Errorf("catalog memory: repository %v: %w", canonical.Key, catalog.ErrAlreadyExists)
	}
	store.repos[canonical.Key] = &repositoryState{
		repository: canonical, snapshots: make(map[model.OID]model.Snapshot),
		fingerprints: make(map[model.OID]model.SnapshotFingerprint), refs: make(map[model.RefName]model.OID),
	}
	return nil
}

func (store *Store) GetRepository(ctx context.Context, key model.RepoKey) (model.Repository, error) {
	if err := validateContextAndRepo(ctx, key); err != nil {
		return model.Repository{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return model.Repository{}, err
	}
	state, exists := store.repos[key]
	if !exists {
		return model.Repository{}, notFound("repository")
	}
	return state.repository, nil
}

func (store *Store) ListRepositories(ctx context.Context, query catalog.RepositoryQuery) (catalog.RepositoryPage, error) {
	if err := ctx.Err(); err != nil {
		return catalog.RepositoryPage{}, err
	}
	limit, after, err := prepareRepositoryQuery(query)
	if err != nil {
		return catalog.RepositoryPage{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	items := make([]model.Repository, 0, min(len(store.repos), limit+1))
	all := make([]model.Repository, 0, len(store.repos))
	for _, state := range store.repos {
		key := state.repository.Key
		if (query.Namespace != "" && key.Namespace != query.Namespace) || (query.Type != "" && key.Type != query.Type) {
			continue
		}
		all = append(all, state.repository)
	}
	slices.SortFunc(all, func(left, right model.Repository) int {
		return strings.Compare(repositorySortKey(left.Key), repositorySortKey(right.Key))
	})
	for index, repository := range all {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return catalog.RepositoryPage{}, err
			}
		}
		if repositorySortKey(repository.Key) <= after {
			continue
		}
		items = append(items, repository)
		if len(items) == limit+1 {
			break
		}
	}
	page := catalog.RepositoryPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := repositorySortKey(page.Items[len(page.Items)-1].Key)
		page.NextCursor = encodeCursor(cursor{
			Kind: "repositories", Namespace: string(query.Namespace), RepoType: string(query.Type), Last: last,
		})
	}
	return page, nil
}

func (store *Store) ResolveRevision(
	ctx context.Context,
	key model.RepoKey,
	revision model.Revision,
) (model.Snapshot, error) {
	if err := validateContextAndRepo(ctx, key); err != nil {
		return model.Snapshot{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	state, exists := store.repos[key]
	if !exists {
		return model.Snapshot{}, notFound("repository or revision")
	}
	snapshot, err := resolveRevision(state, revision)
	if err != nil {
		return model.Snapshot{}, err
	}
	return model.CloneSnapshot(snapshot), nil
}

func (store *Store) GetSnapshot(
	ctx context.Context,
	key model.RepoKey,
	oid model.OID,
) (model.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	revision, err := model.RevisionFromOID(oid)
	if err != nil {
		return model.Snapshot{}, invalid(err)
	}
	return store.ResolveRevision(ctx, key, revision)
}

func (store *Store) ListSnapshots(
	ctx context.Context,
	key model.RepoKey,
	query catalog.SnapshotQuery,
) (catalog.SnapshotPage, error) {
	if err := validateContextAndRepo(ctx, key); err != nil {
		return catalog.SnapshotPage{}, err
	}
	limit, after, err := prepareSnapshotQuery(key, query)
	if err != nil {
		return catalog.SnapshotPage{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	state, exists := store.repos[key]
	if !exists {
		return catalog.SnapshotPage{}, notFound("repository")
	}
	all := make([]model.SnapshotInfo, 0, len(state.snapshots))
	for _, snapshot := range state.snapshots {
		all = append(all, snapshot.Info())
	}
	slices.SortFunc(all, compareSnapshotInfo)
	items := make([]model.SnapshotInfo, 0, min(len(all), limit+1))
	for index, info := range all {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return catalog.SnapshotPage{}, err
			}
		}
		if !snapshotAfter(info, after) {
			continue
		}
		items = append(items, info)
		if len(items) == limit+1 {
			break
		}
	}
	page := catalog.SnapshotPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		timestamp := last.CreatedAt.UnixNano()
		page.NextCursor = encodeCursor(cursor{
			Kind: "snapshots", Repository: repositorySortKey(key), SnapshotUnixNanoseconds: &timestamp,
			SnapshotOID: last.OID.String(),
		})
	}
	return page, nil
}

func (store *Store) GetRef(
	ctx context.Context,
	key model.RepoKey,
	name model.RefName,
) (model.Ref, error) {
	if err := validateContextAndRepo(ctx, key); err != nil {
		return model.Ref{}, err
	}
	if _, err := model.ParseRefName(string(name)); err != nil {
		return model.Ref{}, invalid(err)
	}
	if err := ctx.Err(); err != nil {
		return model.Ref{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return model.Ref{}, err
	}
	state, exists := store.repos[key]
	if !exists {
		return model.Ref{}, notFound("repository or ref")
	}
	oid, exists := state.refs[name]
	if !exists {
		return model.Ref{}, notFound("repository or ref")
	}
	return model.Ref{Repo: key, Name: name, OID: oid}, nil
}

func (store *Store) CompareAndSwapRef(
	ctx context.Context,
	key model.RepoKey,
	name model.RefName,
	expected *model.OID,
	newOID model.OID,
) error {
	if err := validateRefRequest(ctx, key, name, newOID); err != nil {
		return err
	}
	expectedOID, expectsExisting, err := copyExpectedOID(expected)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	state, exists := store.repos[key]
	if !exists {
		return notFound("repository")
	}
	if _, exists := state.snapshots[newOID]; !exists {
		return notFound("target snapshot")
	}
	current, exists := state.refs[name]
	if exists && current == newOID {
		return nil
	}
	if exists != expectsExisting || exists && current != expectedOID {
		return refConflict(key, name)
	}
	state.refs[name] = newOID
	return nil
}

func (store *Store) PublishSnapshot(
	ctx context.Context,
	snapshot model.Snapshot,
	expectation catalog.RefExpectation,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, err := model.CanonicalSnapshot(snapshot)
	if err != nil {
		return invalid(err)
	}
	if err := validateRefRequest(ctx, canonical.Repo, expectation.Name, canonical.OID); err != nil {
		return err
	}
	expectedOID, expectsExisting, err := copyExpectedOID(expectation.OID)
	if err != nil {
		return err
	}
	if expectsExisting && (canonical.Parent == nil || *canonical.Parent != expectedOID) {
		return invalid(errors.New("snapshot parent does not match expected ref"))
	}
	fingerprint, err := model.FingerprintSnapshot(canonical)
	if err != nil {
		return invalid(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	state, exists := store.repos[canonical.Repo]
	if !exists {
		return notFound("repository")
	}
	existing, snapshotExists := state.snapshots[canonical.OID]
	if snapshotExists && state.fingerprints[existing.OID] != fingerprint {
		return fmt.Errorf("catalog memory: snapshot %s: %w", canonical.OID, catalog.ErrConflict)
	}
	current, refExists := state.refs[expectation.Name]
	if snapshotExists && refExists && current == canonical.OID {
		return nil
	}
	if refExists != expectsExisting || refExists && current != expectedOID {
		return refConflict(canonical.Repo, expectation.Name)
	}
	if canonical.Parent != nil {
		if _, exists := state.snapshots[*canonical.Parent]; !exists {
			return notFound("parent snapshot")
		}
	} else if len(state.snapshots) != 0 {
		return invalid(errors.New("only the first snapshot may have no parent"))
	}
	if !snapshotExists {
		state.snapshots[canonical.OID] = canonical
		state.fingerprints[canonical.OID] = fingerprint
	}
	state.refs[expectation.Name] = canonical.OID
	if len(state.snapshots) == 1 {
		state.refs[model.RefName("main")] = canonical.OID
	}
	return nil
}

func (store *Store) GetFile(
	ctx context.Context,
	key model.RepoKey,
	revision model.Revision,
	path model.FilePath,
) (model.FileEntry, error) {
	if err := ctx.Err(); err != nil {
		return model.FileEntry{}, err
	}
	canonicalPath, err := model.ParseFilePath(string(path))
	if err != nil {
		return model.FileEntry{}, invalid(err)
	}
	snapshot, err := store.ResolveRevision(ctx, key, revision)
	if err != nil {
		return model.FileEntry{}, err
	}
	index, found := slices.BinarySearchFunc(snapshot.Files, canonicalPath, func(entry model.FileEntry, path model.FilePath) int {
		return strings.Compare(string(entry.Path), string(path))
	})
	if !found {
		return model.FileEntry{}, notFound("file")
	}
	return snapshot.Files[index], nil
}

func (store *Store) ListFiles(
	ctx context.Context,
	key model.RepoKey,
	revision model.Revision,
	query catalog.FileQuery,
) (catalog.FilePage, error) {
	if err := validateContextAndRepo(ctx, key); err != nil {
		return catalog.FilePage{}, err
	}
	limit, prefix, after, err := prepareFileQuery(key, query)
	if err != nil {
		return catalog.FilePage{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return catalog.FilePage{}, err
	}
	state, exists := store.repos[key]
	if !exists {
		return catalog.FilePage{}, notFound("repository or revision")
	}
	snapshot, err := resolveRevision(state, revision)
	if err != nil {
		return catalog.FilePage{}, err
	}
	if after.set && after.snapshot != snapshot.OID {
		return catalog.FilePage{}, fmt.Errorf("catalog memory: file continuation revision changed: %w", catalog.ErrConflict)
	}
	start := 0
	if after.set {
		start = sort.Search(len(snapshot.Files), func(index int) bool {
			return snapshot.Files[index].Path > after.path
		})
	} else if prefix != "" {
		start = sort.Search(len(snapshot.Files), func(index int) bool {
			return snapshot.Files[index].Path >= model.FilePath(prefix)
		})
	}
	items := make([]model.FileEntry, 0, min(limit+1, len(snapshot.Files)-start))
	for index := start; index < len(snapshot.Files); index++ {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return catalog.FilePage{}, err
			}
		}
		entry := snapshot.Files[index]
		if prefix != "" && !strings.HasPrefix(string(entry.Path), string(prefix)) {
			break
		}
		items = append(items, entry)
		if len(items) == limit+1 {
			break
		}
	}
	page := catalog.FilePage{Items: items, SnapshotOID: snapshot.OID}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = encodeCursor(cursor{
			Kind: "files", Repository: repositorySortKey(key), Prefix: string(prefix),
			Last: string(page.Items[len(page.Items)-1].Path), SnapshotOID: snapshot.OID.String(),
		})
	}
	return page, nil
}

func resolveRevision(state *repositoryState, revision model.Revision) (model.Snapshot, error) {
	oid, isOID := revision.OID()
	if !isOID {
		ref, isRef := revision.Ref()
		if !isRef {
			return model.Snapshot{}, invalid(errors.New("empty revision"))
		}
		var exists bool
		oid, exists = state.refs[ref]
		if !exists {
			return model.Snapshot{}, notFound("revision")
		}
	}
	snapshot, exists := state.snapshots[oid]
	if !exists {
		return model.Snapshot{}, notFound("revision")
	}
	return snapshot, nil
}

func prepareRepositoryQuery(query catalog.RepositoryQuery) (int, string, error) {
	limit, err := pageLimit(query.Limit)
	if err != nil {
		return 0, "", err
	}
	if query.Namespace != "" {
		if _, err := model.ParseNamespace(string(query.Namespace)); err != nil {
			return 0, "", invalid(err)
		}
	}
	if query.Type != "" && query.Type != model.RepoTypeModel {
		return 0, "", invalid(fmt.Errorf("unsupported repository type %q", query.Type))
	}
	if query.Cursor == "" {
		return limit, "", nil
	}
	decoded, err := decodeCursor(query.Cursor)
	lastKey, validLast := parseRepositorySortKey(decoded.Last)
	if err != nil || decoded.Kind != "repositories" || decoded.Namespace != string(query.Namespace) ||
		decoded.RepoType != string(query.Type) || decoded.Repository != "" || decoded.Prefix != "" ||
		decoded.SnapshotUnixNanoseconds != nil || decoded.SnapshotOID != "" || !validLast ||
		(query.Namespace != "" && lastKey.Namespace != query.Namespace) || (query.Type != "" && lastKey.Type != query.Type) {
		return 0, "", invalid(errors.New("malformed or mismatched repository cursor"))
	}
	return limit, decoded.Last, nil
}

func prepareSnapshotQuery(key model.RepoKey, query catalog.SnapshotQuery) (int, snapshotPosition, error) {
	limit, err := pageLimit(query.Limit)
	if err != nil {
		return 0, snapshotPosition{}, err
	}
	if query.Cursor == "" {
		return limit, snapshotPosition{}, nil
	}
	decoded, err := decodeCursor(query.Cursor)
	if err != nil || decoded.Kind != "snapshots" || decoded.Repository != repositorySortKey(key) ||
		decoded.Namespace != "" || decoded.RepoType != "" || decoded.Prefix != "" || decoded.Last != "" ||
		decoded.SnapshotUnixNanoseconds == nil {
		return 0, snapshotPosition{}, invalid(errors.New("malformed or mismatched snapshot cursor"))
	}
	oid, err := model.ParseOID(decoded.SnapshotOID)
	if err != nil {
		return 0, snapshotPosition{}, invalid(errors.New("malformed or mismatched snapshot cursor"))
	}
	return limit, snapshotPosition{timestamp: *decoded.SnapshotUnixNanoseconds, oid: oid, set: true}, nil
}

func prepareFileQuery(
	key model.RepoKey,
	query catalog.FileQuery,
) (int, model.FilePrefix, filePosition, error) {
	limit, err := pageLimit(query.Limit)
	if err != nil {
		return 0, "", filePosition{}, err
	}
	prefix, err := model.ParseFilePrefix(string(query.Prefix))
	if err != nil {
		return 0, "", filePosition{}, invalid(err)
	}
	if query.Cursor == "" {
		return limit, prefix, filePosition{}, nil
	}
	decoded, err := decodeCursor(query.Cursor)
	if err != nil || decoded.Kind != "files" || decoded.Repository != repositorySortKey(key) ||
		decoded.Namespace != "" || decoded.RepoType != "" || decoded.Prefix != string(prefix) ||
		decoded.SnapshotUnixNanoseconds != nil {
		return 0, "", filePosition{}, invalid(errors.New("malformed or mismatched file cursor"))
	}
	path, pathErr := model.ParseFilePath(decoded.Last)
	oid, oidErr := model.ParseOID(decoded.SnapshotOID)
	if pathErr != nil || oidErr != nil || (prefix != "" && !strings.HasPrefix(string(path), string(prefix))) {
		return 0, "", filePosition{}, invalid(errors.New("malformed or mismatched file cursor"))
	}
	return limit, prefix, filePosition{snapshot: oid, path: path, set: true}, nil
}

func pageLimit(value int) (int, error) {
	if value < 0 || value > catalog.MaxPageSize {
		return 0, invalid(fmt.Errorf("page limit must be inside [0,%d]", catalog.MaxPageSize))
	}
	if value == 0 {
		return catalog.DefaultPageSize, nil
	}
	return value, nil
}

func validateContextAndRepo(ctx context.Context, key model.RepoKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := model.ValidateRepoKey(key); err != nil {
		return invalid(err)
	}
	return nil
}

func validateRefRequest(ctx context.Context, key model.RepoKey, name model.RefName, oid model.OID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := model.ValidateRef(model.Ref{Repo: key, Name: name, OID: oid}); err != nil {
		return invalid(err)
	}
	return nil
}

func repositorySortKey(key model.RepoKey) string {
	return string(key.Type) + "\x00" + string(key.Namespace) + "\x00" + string(key.Name)
}

func compareSnapshotInfo(left, right model.SnapshotInfo) int {
	if left.CreatedAt.After(right.CreatedAt) {
		return -1
	}
	if left.CreatedAt.Before(right.CreatedAt) {
		return 1
	}
	return strings.Compare(right.OID.String(), left.OID.String())
}

func snapshotAfter(info model.SnapshotInfo, after snapshotPosition) bool {
	if !after.set {
		return true
	}
	timestamp := info.CreatedAt.UnixNano()
	if timestamp != after.timestamp {
		return timestamp < after.timestamp
	}
	return info.OID.String() < after.oid.String()
}

func validRepositorySortKey(value string) bool {
	_, valid := parseRepositorySortKey(value)
	return valid
}

func parseRepositorySortKey(value string) (model.RepoKey, bool) {
	parts := strings.Split(value, "\x00")
	if len(parts) != 3 {
		return model.RepoKey{}, false
	}
	key, err := model.NewRepoKey(parts[1], parts[2], model.RepoType(parts[0]))
	return key, err == nil && repositorySortKey(key) == value
}

func copyExpectedOID(value *model.OID) (model.OID, bool, error) {
	if value == nil {
		return model.OID{}, false, nil
	}
	copy := *value
	if copy.IsZero() {
		return model.OID{}, false, invalid(errors.New("zero expected ref OID"))
	}
	return copy, true, nil
}

func encodeCursor(value cursor) string {
	encoded, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeCursor(value string) (cursor, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursor{}, err
	}
	var decoded cursor
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return cursor{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing cursor data")
		}
		return cursor{}, err
	}
	return decoded, nil
}

func invalid(err error) error {
	return fmt.Errorf("%w: %v", catalog.ErrInvalid, err)
}

func notFound(subject string) error {
	return fmt.Errorf("catalog memory: %s: %w", subject, catalog.ErrNotFound)
}

func refConflict(key model.RepoKey, name model.RefName) error {
	return fmt.Errorf("catalog memory: ref %v/%s: %w", key, name, catalog.ErrConflict)
}
