// Package s3store implements immutable Xet CAS blob storage and signed range
// reads on Amazon S3 and compatible object stores.
package s3store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

const (
	objectLayoutVersion = "blobs-v1"
	defaultPresignTTL   = 15 * time.Minute
	maximumPresignTTL   = 7 * 24 * time.Hour
	conditionalRetries  = 3
	conditionalDelay    = 10 * time.Millisecond
	cursorVersion       = 1
)

type s3Client interface {
	PutObject(context.Context, *awss3.PutObjectInput, ...func(*awss3.Options)) (*awss3.PutObjectOutput, error)
	HeadObject(context.Context, *awss3.HeadObjectInput, ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error)
	GetObject(context.Context, *awss3.GetObjectInput, ...func(*awss3.Options)) (*awss3.GetObjectOutput, error)
	ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error)
}

type presignClient interface {
	PresignGetObject(
		context.Context,
		*awss3.GetObjectInput,
		...func(*awss3.PresignOptions),
	) (*v4.PresignedHTTPRequest, error)
}

// Options configures an authoritative S3 CAS object prefix. Prefix is an
// optional slash-separated operator-controlled path below Bucket. TempDirectory
// selects where immutable request bodies are spooled and exactly length-checked
// before upload; empty uses the process temporary directory.
type Options struct {
	Bucket        string
	Prefix        string
	TempDirectory string
	PresignExpiry time.Duration
}

// Store implements server.BlobStore, server.BlobLister, and
// server.RangeURLSigner. The supplied client owns endpoint, credential,
// path-style, retry, and TLS configuration, allowing the same adapter to target
// AWS S3, MinIO, and other compatible stores.
type Store struct {
	client        s3Client
	presigner     presignClient
	bucket        string
	prefix        string
	tempDirectory string
	presignTTL    time.Duration
}

// New constructs an S3 CAS adapter from an already configured AWS SDK client.
func New(client *awss3.Client, options Options) (*Store, error) {
	if client == nil {
		return nil, fmt.Errorf("xet CAS S3: nil client")
	}
	return newStore(client, awss3.NewPresignClient(client), options)
}

func newStore(client s3Client, presigner presignClient, options Options) (*Store, error) {
	if client == nil || presigner == nil || strings.TrimSpace(options.Bucket) == "" ||
		strings.TrimSpace(options.Bucket) != options.Bucket || strings.IndexByte(options.Bucket, 0) >= 0 {
		return nil, fmt.Errorf("xet CAS S3: invalid client, presigner, or bucket")
	}
	prefix, err := normalizePrefix(options.Prefix)
	if err != nil {
		return nil, err
	}
	ttl := options.PresignExpiry
	if ttl == 0 {
		ttl = defaultPresignTTL
	}
	if ttl < time.Second || ttl > maximumPresignTTL || ttl%time.Second != 0 {
		return nil, fmt.Errorf("xet CAS S3: presign expiry %s must be whole seconds inside [1s,%s]",
			ttl, maximumPresignTTL)
	}
	if options.TempDirectory != "" {
		info, err := os.Stat(options.TempDirectory)
		if err != nil {
			return nil, fmt.Errorf("xet CAS S3: invalid upload temporary directory: %w", err)
		}
		if !info.IsDir() {
			return nil, errors.New("xet CAS S3: upload temporary path is not a directory")
		}
	}
	return &Store{
		client: client, presigner: presigner, bucket: options.Bucket,
		prefix: prefix, tempDirectory: options.TempDirectory, presignTTL: ttl,
	}, nil
}

// PutIfAbsent spools and exactly validates body before conditionally creating
// its immutable object. A pre-existing byte-identical object is idempotent;
// different bytes under the same key return server.ErrConflict.
func (s *Store) PutIfAbsent(
	ctx context.Context,
	key casserver.BlobKey,
	body io.Reader,
	size int64,
) (bool, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return false, err
	}
	if body == nil || size < 0 || size == math.MaxInt64 {
		return false, fmt.Errorf("%w: invalid S3 blob body or size", casserver.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(s.tempDirectory, ".xet-s3-blob-*")
	if err != nil {
		return false, fmt.Errorf("xet CAS S3: create upload spool: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	read := &contextReader{ctx: ctx, reader: body}
	written, err := io.Copy(temporary, io.LimitReader(read, size+1))
	if err != nil {
		return false, fmt.Errorf("xet CAS S3: spool upload: %w", err)
	}
	if written != size {
		return false, fmt.Errorf("%w: S3 blob body size %d, expected %d", casserver.ErrInvalid, written, size)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for attempt := 0; ; attempt++ {
		if _, err := temporary.Seek(0, io.SeekStart); err != nil {
			return false, fmt.Errorf("xet CAS S3: rewind upload spool: %w", err)
		}
		_, err = s.client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(s.bucket), Key: aws.String(objectKey), Body: temporary,
			ContentLength: aws.Int64(size), IfNoneMatch: aws.String("*"),
		})
		if err == nil {
			return true, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return false, contextErr
		}
		if isPreconditionFailed(err) {
			equal, compareErr := s.matchesExisting(ctx, key, temporary, size)
			if compareErr != nil {
				return false, compareErr
			}
			if !equal {
				return false, casserver.ErrConflict
			}
			return false, nil
		}
		if !isConditionalRequestConflict(err) || attempt == conditionalRetries {
			return false, fmt.Errorf("xet CAS S3: put %s: %w", objectKey, err)
		}
		if err := waitConditionalRetry(ctx, attempt); err != nil {
			return false, err
		}
	}
}

func (s *Store) matchesExisting(
	ctx context.Context,
	key casserver.BlobKey,
	temporary *os.File,
	size int64,
) (bool, error) {
	info, found, err := s.Head(ctx, key)
	if err != nil {
		return false, err
	}
	if !found {
		return false, errors.New("xet CAS S3: conditional write conflicted but object is absent")
	}
	if info.Size != size {
		return false, nil
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("xet CAS S3: rewind comparison spool: %w", err)
	}
	reader, err := s.Get(ctx, key, nil)
	if err != nil {
		return false, err
	}
	equal, compareErr := equalReaders(ctx, reader, temporary, size)
	closeErr := reader.Close()
	if err := errors.Join(compareErr, closeErr); err != nil {
		return false, fmt.Errorf("xet CAS S3: compare existing object: %w", err)
	}
	return equal, nil
}

// Head returns the exact stored object length without reading its payload.
func (s *Store) Head(ctx context.Context, key casserver.BlobKey) (casserver.BlobInfo, bool, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return casserver.BlobInfo{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return casserver.BlobInfo{}, false, err
	}
	output, err := s.client.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(objectKey),
	})
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return casserver.BlobInfo{}, false, contextErr
		}
		if isMissing(err) {
			return casserver.BlobInfo{}, false, nil
		}
		return casserver.BlobInfo{}, false, fmt.Errorf("xet CAS S3: head %s: %w", objectKey, err)
	}
	if output == nil || output.ContentLength == nil || *output.ContentLength < 0 {
		return casserver.BlobInfo{}, false, fmt.Errorf("%w: S3 head %s returned an invalid size",
			casserver.ErrCorrupt, objectKey)
	}
	return casserver.BlobInfo{Size: *output.ContentLength}, true, nil
}

// Get opens a full object or one validated inclusive byte range.
func (s *Store) Get(
	ctx context.Context,
	key casserver.BlobKey,
	wanted *xetcas.HTTPRange,
) (io.ReadCloser, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return nil, err
	}
	input := &awss3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(objectKey)}
	var expectedLength uint64
	var expectedContentRange string
	if wanted != nil {
		if err := wanted.Validate(); err != nil {
			return nil, xetcas.ErrRangeNotSatisfiable
		}
		info, found, err := s.Head(ctx, key)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, casserver.ErrNotFound
		}
		if wanted.End >= uint64(info.Size) {
			return nil, xetcas.ErrRangeNotSatisfiable
		}
		expectedLength = wanted.Len()
		expectedContentRange = fmt.Sprintf("bytes %d-%d/%d", wanted.Start, wanted.End, info.Size)
		input.Range = aws.String(httpRange(*wanted))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		if isMissing(err) {
			return nil, casserver.ErrNotFound
		}
		if wanted != nil && isRangeInvalid(err) {
			return nil, xetcas.ErrRangeNotSatisfiable
		}
		return nil, fmt.Errorf("xet CAS S3: get %s: %w", objectKey, err)
	}
	if output == nil || output.Body == nil || output.ContentLength == nil || *output.ContentLength < 0 {
		if output != nil && output.Body != nil {
			_ = output.Body.Close()
		}
		return nil, fmt.Errorf("%w: S3 get %s returned an invalid body or size", casserver.ErrCorrupt, objectKey)
	}
	if wanted != nil && (uint64(*output.ContentLength) != expectedLength ||
		output.ContentRange == nil || *output.ContentRange != expectedContentRange) {
		_ = output.Body.Close()
		return nil, fmt.Errorf("%w: S3 range %s returned inconsistent range metadata",
			casserver.ErrCorrupt, objectKey)
	}
	return &contextReadCloser{ctx: ctx, reader: output.Body}, nil
}

// ListBlobs returns one deterministic keyset-paginated physical inventory.
func (s *Store) ListBlobs(
	ctx context.Context,
	kind casserver.BlobKind,
	request casserver.PageRequest,
) (casserver.BlobPage, error) {
	root, code, err := s.kindRoot(kind)
	if err != nil {
		return casserver.BlobPage{}, err
	}
	limit, err := pageLimit(request)
	if err != nil {
		return casserver.BlobPage{}, err
	}
	var cursor xethash.Hash
	if request.Cursor != "" {
		cursor, err = decodeCursor(request.Cursor, code)
		if err != nil {
			return casserver.BlobPage{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return casserver.BlobPage{}, err
	}
	page := casserver.BlobPage{Items: make([]casserver.BlobEntry, 0, limit)}
	startAfter := ""
	if request.Cursor != "" {
		startAfter, err = s.objectKey(casserver.BlobKey{Kind: kind, Hash: cursor})
		if err != nil {
			return casserver.BlobPage{}, err
		}
	}
	var continuation string
	for len(page.Items) < limit {
		if err := ctx.Err(); err != nil {
			return casserver.BlobPage{}, err
		}
		remaining := int32(limit - len(page.Items))
		input := &awss3.ListObjectsV2Input{
			Bucket: aws.String(s.bucket), Prefix: aws.String(root), MaxKeys: aws.Int32(remaining),
		}
		if continuation != "" {
			input.ContinuationToken = aws.String(continuation)
		} else if startAfter != "" {
			input.StartAfter = aws.String(startAfter)
		}
		output, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return casserver.BlobPage{}, contextErr
			}
			return casserver.BlobPage{}, fmt.Errorf("xet CAS S3: list %s: %w", root, err)
		}
		if output == nil || len(output.Contents) > int(remaining) {
			return casserver.BlobPage{}, fmt.Errorf("%w: S3 list %s returned an oversized page",
				casserver.ErrCorrupt, root)
		}
		previous := startAfter
		if len(page.Items) != 0 {
			previous, _ = s.objectKey(page.Items[len(page.Items)-1].Key)
		}
		for _, object := range output.Contents {
			if err := ctx.Err(); err != nil {
				return casserver.BlobPage{}, err
			}
			if object.Key == nil || object.Size == nil || *object.Size < 0 ||
				(previous != "" && *object.Key <= previous) {
				return casserver.BlobPage{}, fmt.Errorf("%w: S3 list %s returned invalid or unordered metadata",
					casserver.ErrCorrupt, root)
			}
			parsed, err := s.parseObjectKey(kind, *object.Key)
			if err != nil {
				return casserver.BlobPage{}, err
			}
			page.Items = append(page.Items, casserver.BlobEntry{
				Key: parsed, Info: casserver.BlobInfo{Size: *object.Size},
			})
			previous = *object.Key
		}
		if output.IsTruncated == nil {
			return casserver.BlobPage{}, fmt.Errorf("%w: S3 list %s omitted truncation metadata",
				casserver.ErrCorrupt, root)
		}
		truncated := *output.IsTruncated
		if !truncated {
			if output.NextContinuationToken != nil && *output.NextContinuationToken != "" {
				return casserver.BlobPage{}, fmt.Errorf("%w: S3 list %s returned an unexpected continuation",
					casserver.ErrCorrupt, root)
			}
			break
		}
		if len(output.Contents) == 0 || output.NextContinuationToken == nil ||
			*output.NextContinuationToken == "" || *output.NextContinuationToken == continuation {
			return casserver.BlobPage{}, fmt.Errorf("%w: S3 list %s returned a stationary continuation",
				casserver.ErrCorrupt, root)
		}
		continuation = *output.NextContinuationToken
		if len(page.Items) == limit {
			page.NextCursor = encodeCursor(code, page.Items[len(page.Items)-1].Key.Hash)
			break
		}
	}
	return page, nil
}

// SignRange creates a SigV4 URL bound to one exact Range header. Callers must
// send the same Range header when fetching the URL.
func (s *Store) SignRange(
	ctx context.Context,
	key casserver.BlobKey,
	wanted xetcas.HTTPRange,
) (casserver.SignedRange, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return casserver.SignedRange{}, err
	}
	if err := wanted.Validate(); err != nil {
		return casserver.SignedRange{}, xetcas.ErrRangeNotSatisfiable
	}
	if err := ctx.Err(); err != nil {
		return casserver.SignedRange{}, err
	}
	rangeHeader := httpRange(wanted)
	request, err := s.presigner.PresignGetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(objectKey), Range: aws.String(rangeHeader),
	}, awss3.WithPresignExpires(s.presignTTL))
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return casserver.SignedRange{}, contextErr
		}
		return casserver.SignedRange{}, fmt.Errorf("xet CAS S3: presign %s: %w", objectKey, err)
	}
	if request == nil || request.Method != http.MethodGet ||
		!validSignedURL(request.URL) || !signedRangeMatches(request.SignedHeader, rangeHeader) {
		return casserver.SignedRange{}, errors.New("xet CAS S3: presigner did not bind the requested range")
	}
	expiresAt, err := signedURLExpiry(request.URL, s.presignTTL)
	if err != nil {
		return casserver.SignedRange{}, err
	}
	return casserver.SignedRange{URL: request.URL, ExpiresAt: expiresAt}, nil
}

func (s *Store) objectKey(key casserver.BlobKey) (string, error) {
	root, _, err := s.kindRoot(key.Kind)
	if err != nil {
		return "", err
	}
	if key.Hash.IsZero() {
		return "", fmt.Errorf("%w: zero S3 blob hash", casserver.ErrInvalid)
	}
	hash := key.Hash.String()
	return root + hash[:2] + "/" + hash[2:4] + "/" + hash, nil
}

func (s *Store) kindRoot(kind casserver.BlobKind) (string, byte, error) {
	var code byte
	switch kind {
	case casserver.BlobXorb:
		code = 1
	case casserver.BlobShard:
		code = 2
	default:
		return "", 0, fmt.Errorf("%w: unsupported S3 blob kind %q", casserver.ErrInvalid, kind)
	}
	root := objectLayoutVersion + "/" + string(kind) + "/"
	if s.prefix != "" {
		root = s.prefix + "/" + root
	}
	return root, code, nil
}

func (s *Store) parseObjectKey(kind casserver.BlobKind, value string) (casserver.BlobKey, error) {
	root, _, err := s.kindRoot(kind)
	if err != nil {
		return casserver.BlobKey{}, err
	}
	relative := strings.TrimPrefix(value, root)
	parts := strings.Split(relative, "/")
	if relative == value || len(parts) != 3 || len(parts[0]) != 2 || len(parts[1]) != 2 || len(parts[2]) != 64 ||
		parts[0] != parts[2][:2] || parts[1] != parts[2][2:4] {
		return casserver.BlobKey{}, fmt.Errorf("%w: malformed S3 object key %q", casserver.ErrCorrupt, value)
	}
	hash, err := xethash.Parse(parts[2])
	if err != nil || hash.IsZero() || hash.String() != parts[2] {
		return casserver.BlobKey{}, fmt.Errorf("%w: malformed S3 object hash in key %q", casserver.ErrCorrupt, value)
	}
	return casserver.BlobKey{Kind: kind, Hash: hash}, nil
}

func normalizePrefix(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 512 || strings.ContainsAny(value, "\\\x00") || path.Clean(value) != value ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return "", fmt.Errorf("xet CAS S3: invalid object prefix")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return "", fmt.Errorf("xet CAS S3: invalid object prefix")
		}
	}
	return value, nil
}

func pageLimit(request casserver.PageRequest) (int, error) {
	if request.Limit < 0 || request.Limit > casserver.MaxPageSize {
		return 0, fmt.Errorf("%w: page limit %d is outside [0,%d]",
			casserver.ErrInvalid, request.Limit, casserver.MaxPageSize)
	}
	if request.Limit == 0 {
		return casserver.DefaultPageSize, nil
	}
	return request.Limit, nil
}

func encodeCursor(kind byte, hash xethash.Hash) string {
	data := make([]byte, 2+len(xethash.Hash{}))
	data[0], data[1] = cursorVersion, kind
	copy(data[2:], hash[:])
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeCursor(cursor string, kind byte) (xethash.Hash, error) {
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(data) != 2+len(xethash.Hash{}) || data[0] != cursorVersion || data[1] != kind {
		return xethash.Hash{}, fmt.Errorf("%w: malformed S3 blob cursor", casserver.ErrInvalid)
	}
	var hash xethash.Hash
	copy(hash[:], data[2:])
	return hash, nil
}

func equalReaders(ctx context.Context, left io.Reader, right io.Reader, size int64) (bool, error) {
	leftBuffer := make([]byte, 64<<10)
	rightBuffer := make([]byte, len(leftBuffer))
	remaining := size
	for remaining != 0 {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		wanted := int64(len(leftBuffer))
		if remaining < wanted {
			wanted = remaining
		}
		leftN, leftErr := io.ReadFull(left, leftBuffer[:wanted])
		rightN, rightErr := io.ReadFull(right, rightBuffer[:wanted])
		if leftErr != nil || rightErr != nil {
			return false, errors.Join(leftErr, rightErr)
		}
		if leftN != rightN || !bytes.Equal(leftBuffer[:leftN], rightBuffer[:rightN]) {
			return false, nil
		}
		remaining -= int64(leftN)
	}
	var extra [1]byte
	count, err := left.Read(extra[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return count == 0, nil
}

func httpRange(value xetcas.HTTPRange) string {
	return fmt.Sprintf("bytes=%d-%d", value.Start, value.End)
}

func signedRangeMatches(headers http.Header, expected string) bool {
	values := headers.Values("Range")
	return len(values) == 1 && values[0] == expected
}

func validSignedURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func signedURLExpiry(value string, expectedTTL time.Duration) (time.Time, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return time.Time{}, errors.New("xet CAS S3: presigner returned an invalid expiration")
	}
	dateValues := parsed.Query()["X-Amz-Date"]
	expiryValues := parsed.Query()["X-Amz-Expires"]
	if len(dateValues) != 1 || len(expiryValues) != 1 {
		return time.Time{}, errors.New("xet CAS S3: presigner returned an invalid expiration")
	}
	signedAt, err := time.Parse("20060102T150405Z", dateValues[0])
	if err != nil {
		return time.Time{}, errors.New("xet CAS S3: presigner returned an invalid expiration")
	}
	expirySeconds, err := strconv.ParseInt(expiryValues[0], 10, 32)
	if err != nil || expirySeconds < 1 || expirySeconds > int64(maximumPresignTTL/time.Second) {
		return time.Time{}, errors.New("xet CAS S3: presigner returned an invalid expiration")
	}
	if strconv.FormatInt(expirySeconds, 10) != expiryValues[0] ||
		expirySeconds != int64(expectedTTL/time.Second) {
		return time.Time{}, errors.New("xet CAS S3: presigner returned an unexpected expiration")
	}
	return signedAt.Add(time.Duration(expirySeconds) * time.Second), nil
}

func waitConditionalRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(conditionalDelay << attempt)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isPreconditionFailed(err error) bool {
	return matchesS3Error(err, []string{"PreconditionFailed"}, 412)
}

func isConditionalRequestConflict(err error) bool {
	return matchesS3Error(err, []string{"ConditionalRequestConflict"}, 409)
}

func isMissing(err error) bool {
	return matchesS3Error(err, []string{"NoSuchKey", "NotFound"}, http.StatusNotFound)
}

func isRangeInvalid(err error) bool {
	return matchesS3Error(err, []string{"InvalidRange", "RequestedRangeNotSatisfiable"},
		http.StatusRequestedRangeNotSatisfiable)
}

func matchesS3Error(err error, codes []string, fallbackStatus int) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		for _, code := range codes {
			if apiError.ErrorCode() == code {
				return true
			}
		}
		return false
	}
	return hasHTTPStatus(err, fallbackStatus)
}

func hasHTTPStatus(err error, statuses ...int) bool {
	var responseError interface{ HTTPStatusCode() int }
	if !errors.As(err, &responseError) {
		return false
	}
	for _, status := range statuses {
		if responseError.HTTPStatusCode() == status {
			return true
		}
	}
	return false
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

type contextReadCloser struct {
	ctx    context.Context
	reader io.ReadCloser
	once   sync.Once
	err    error
}

func (r *contextReadCloser) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func (r *contextReadCloser) Close() error {
	r.once.Do(func() { r.err = r.reader.Close() })
	return r.err
}

var (
	_ casserver.BlobStore      = (*Store)(nil)
	_ casserver.BlobLister     = (*Store)(nil)
	_ casserver.RangeURLSigner = (*Store)(nil)
)
