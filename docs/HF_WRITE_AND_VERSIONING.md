# Hugging Face writes and host-owned versioning

`hfcompat` implements the model-repository write profile exercised by
`huggingface_hub==1.27.0` and `hf_xet==1.6.0`. The client pins are asserted by
the opt-in black-box tests and must be reviewed whenever either pin changes.
Git, LFS, and Hub HTTP semantics remain confined to `hfcompat`.

## Supported write profile

The adapter exposes credential validation, repository creation, preupload,
commit, Xet write-token exchange, and the basic Git LFS fallback. Native Xet
is the primary large-file path: preupload returns the official wire value
`"lfs"`, then an installed `hf_xet` client selects Xet and refreshes a scoped
write token. The commit still represents that file as `lfsFile` with its
conventional SHA-256 and size.

All returned repository, commit, token, and upload-action URLs are rooted at
`HubBaseURL` or `CASBaseURL` (or the corresponding `BaseURLFunc` result),
including any configured base path. When a static base path is present, mount
the corresponding handler with that prefix removed (for example,
`http.StripPrefix("/hub", service.HubHandler())`); the handlers keep route
parsing independent from deployment middleware.

For a public Hub prefix that varies per request, leave both static fields empty
and set `BaseURLFunc`. The mounting layer must strip the same variable prefix
that the function includes in its returned Hub base. A mismatch emits the Xet
read-token refresh link and LFS upload action under a path that does not route;
preventing that failure is the reason the function exists. For example, this
mounts one service at a tenant path selected by a trusted router while keeping
CAS at one fixed mount:

```go
type publicHubBaseKey struct{}

service, err := hfcompat.New(hfcompat.Options{
    Bucket: bucketService,
    Broker: accessBroker,
    BaseURLFunc: func(r *http.Request) (string, string, error) {
        hub, ok := r.Context().Value(publicHubBaseKey{}).(string)
        if !ok {
            return "", "", errors.New("missing routed Hub base")
        }
        return hub, "https://models.example/cas", nil
    },
})
if err != nil {
    return err
}

mux.Handle("/tenants/{tenant}/{rest...}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    tenant := r.PathValue("tenant")
    if tenant == "" || strings.Trim(tenant, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
        http.NotFound(w, r)
        return
    }
    prefix := "/tenants/" + tenant
    ctx := context.WithValue(r.Context(), publicHubBaseKey{}, "https://models.example"+prefix)
    http.StripPrefix(prefix, service.Handler()).ServeHTTP(w, r.WithContext(ctx))
}))
```

The same rule applies when the returned CAS base has a variable path: mount the
corresponding CAS handler at that external prefix and strip it before CAS route
parsing. `BaseURLFunc` runs on Hub requests and controls emitted URL values; it
does not configure or mount the CAS handler itself. In the composed service,
this means the returned CAS base and the external mount of
`bucket/hosted.Service.CASHandler` must agree.

`BaseURLFunc` is called at most once after the required authorization and before
an absolute URL or URL-producing side effect. Routes whose repository is in the
path resolve before dispatch; repository creation resolves after parsing and
authorizing the body-supplied target and before creating it. Both results are
validated before use. The library does not infer public identity from `Host`,
`X-Forwarded-Host`, `X-Forwarded-Proto`, or other request headers. An embedder
may use trusted proxy-derived state in its function, but owns that trust
decision.

Returned bases must also remain routable for the lifetime of URLs already sent
to clients, not merely for the request that selected them. In particular, a
client can follow the Xet read-token refresh link later during a long transfer
when it needs a fresh scoped token, and follows an LFS upload action later for
the body PUT. A request-scoped identifier, short-lived view, or rotating alias
that expires first will break those operations; the read-token refresh is the
less obvious failure.

The pinned preupload request contains only path, size, and the first 512 bytes;
it does **not** contain a full-file digest. Consequently preupload cannot
infer exact content merely because path, size, or the prefix match.
`shouldIgnore` remains false in the supported profile (the pinned client
reserves it for server-side gitignore policy). Existing destination paths
instead return the client's expected remote OID: Git blob SHA-1 for ordinary
files and whole-file SHA-256 for Xet/LFS files. The client uses that OID to
remove unchanged operations; transfer deduplication is performed later by
native Xet or the LFS batch request.

Basic LFS requires `hfcompat.Options.Ingester`. The upload action is a
short-lived HMAC capability bound to repository, principal, object SHA-256,
length, and expiry. The receiver streams to a private temporary file and checks
the complete hash and length before invoking `XetFileIngester`; it never places
the Hub bearer in the action URL. Active and completed capabilities are rejected
within an instance, and a retained completed object makes replay fail after a
restart. `bucket/hosted.Options.LFSIngester` forwards the same capability for
composed services. Multi-instance or restart-stable receivers must configure
the same 32-byte `LFSUploadCapabilityKey`; the default ephemeral key is
intentionally suitable only for one service instance.

The `LFSUploadCapabilityKey` defines a trust domain. Share it only among
instances that serve the same catalog, content store, and authorization policy;
use distinct keys for instances intended to be isolated. The upload capability
is the authorization for `lfs-upload`, which deliberately performs no separate
repository authorization, so another instance with the same key can accept a
capability for the same `RepoKey` without consulting its own repository
authorizer. `XetFileIngester.IngestXetFile` receives only the context, `RepoKey`,
and content reader—not the principal—so an embedder cannot re-authorize there.
The bounded impact is storage and a namespace-scoped Xet record in that other
catalog: ingest alone creates no catalog tree entry, and `commit` still requires
`RepositoryWrite`. The base URL is intentionally not signed because one logical
repository may legitimately be reached through several addresses. Any future
stronger isolation should bind a separately designed trust-domain identifier,
with an explicit capability invalidation policy, rather than bind the public
URL.

`hfcompat.Options.Audit` observes every recognized write operation after its
HTTP outcome is known. `WriteAuditEvent` contains only the authenticated
principal, repository, operation, status code, and request correlation ID; it
has no credential or capability field. `bucket/hosted.Options.WriteAudit`
forwards the same sink at the composition boundary.

Pull-request commits (`create_pr=1`) and non-model repository types are outside
this profile. `huggingface_hub` 1.27.0 also sends a root `README.md` to the
hard-coded public `https://huggingface.co/api/validate-yaml`, ignoring the
configured endpoint. Offline/private-endpoint conformance therefore excludes
a root `README.md`. Re-check this limitation on every client bump.

The always-on unit tests use source-backed DTO fixtures. A sanitized golden
write transcript from an authenticated reference Hub is still required before
changing private DTOs or claiming compatibility with another client version;
do not infer new fields from documentation alone. Never commit the Hub bearer,
CAS tokens, signed action URLs, or repository content from that capture.

## Host-owned revision resolution

`BucketService` is the supported revision-resolution extension point. Every
read route resolves through `ResolveRevision`, and file reads then re-pin
`OpenFile` to the returned immutable OID. A host can redefine mutable refs with
a decorator:

```go
type hostRevisions struct {
    underlying hfcompat.BucketService
    refs       HostRefStore
}

func (h *hostRevisions) ResolveRevision(ctx context.Context, repo model.RepoKey, rev model.Revision) (model.Snapshot, error) {
    oid, visible, err := h.refs.ResolveVisible(ctx, repo, rev)
    if err != nil || !visible {
        return model.Snapshot{}, err
    }
    pinned, _ := model.RevisionFromOID(oid)
    return h.underlying.ResolveRevision(ctx, repo, pinned)
}
```

The decorator must delegate `GetRepository` and `OpenFile`. It must also apply
the host's visibility policy to explicit-OID revisions; filtering only named
refs lets callers bypass that policy by supplying an OID directly.

Xet read tokens are intentionally repository-namespace scoped, not snapshot
scoped. This matches the CAS protocol and permits chunk reuse, but possession
of a file hash plus a repository read token can reach newer content in that
namespace. Hosts that require snapshot-level secrecy must enforce that policy
before token issuance or use separate CAS namespaces; revision decoration
alone is not a snapshot-scoped CAS capability.

## Host-owned publication

`Options.Publisher` delegates the publication step. `hfcompat` calls it once
after all referenced content is durable and after constructing and
canonicalizing the complete immutable snapshot. A host may veto the operation
or compose its own durable metadata work. To keep refs entirely host-owned,
publish the catalog snapshot with `catalog.NoRefUpdate()` and move the host ref
in the host transaction. Ref-less first publication creates no implicit
`main`. `Options.Snapshots` retrieves a durable prepared intent or an already
retained OID so an ambiguous retry can reuse the exact immutable snapshot,
including its original timestamp. It is inferred automatically when the writer
or bucket implements `SnapshotReader`; a publisher that persists intents before
catalog publication should supply a reader over those intents explicitly.

At the higher-level `bucket/hosted` composition boundary, use
`BucketDecorator`, `PublisherDecorator`, and `SnapshotReader`. The decorators
are invoked after the default `bucket.Service` exists, so a host can wrap the
actual composed reader and publisher without a mutable forwarding proxy.

No transaction can atomically enlist an arbitrary host database and the xet-go
catalog. Embedders must use this reconciliation protocol:

1. Allocate the opaque OID before publication.
2. Durably persist an intent containing repository, target ref, expected old
   OID, new OID, and the canonical snapshot (or inputs that reconstruct it
   byte-for-byte).
3. Publish using that exact OID and snapshot. Never allocate a replacement
   after an ambiguous response.
4. On startup or retry: if the target already equals the prepared OID and the
   retained snapshot matches, complete the intent; if the target still equals
   the expected old OID, replay the exact publication; otherwise record a
   terminal conflict for operator resolution.

Target-state idempotency requires the same OID, immutable snapshot, and ref
target. An identical replay succeeds; different content under that OID or a
competing ref move is a typed conflict, never an overwrite.

## Verification

Install the exact pins from `conformance/hf-client/requirements.txt`, then run:

```bash
XET_HF_CLIENT_PYTHON="$(pwd)/.cache/hf-client/bin/python" \
  go test -race -run '^TestOfficialPythonClient' -count=1 -v ./hfcompat
```

The write cases run create/re-create, `HfApi.upload_file`,
`HfApi.upload_folder`, `ModelHubMixin.push_to_hub`, `hf upload`, commit, and
byte-identical download. The `push_to_hub` case excludes root `README.md` with
`allow_patterns`, matching the supported profile above. One case leaves Xet
enabled and proves download then upload in one process without an environment
workaround; another sets `HF_HUB_DISABLE_XET=1` before import and proves the
basic LFS fallback.
