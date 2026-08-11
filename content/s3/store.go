// Package s3 implements immutable ordinary-content storage in Amazon S3 and
// compatible object stores.
package s3

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/content/internal/verified"
)

const (
	layoutVersion      = "content-v1"
	conditionalRetries = 3
	conditionalDelay   = 10 * time.Millisecond
)

type client interface {
	PutObject(context.Context, *awss3.PutObjectInput, ...func(*awss3.Options)) (*awss3.PutObjectOutput, error)
	HeadObject(context.Context, *awss3.HeadObjectInput, ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error)
	GetObject(context.Context, *awss3.GetObjectInput, ...func(*awss3.Options)) (*awss3.GetObjectOutput, error)
	ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error)
}

// Options identifies the private bucket namespace and local upload spool.
type Options struct {
	Bucket        string
	Prefix        string
	TempDirectory string
}

// Store is an immutable content.Store backed by S3.
type Store struct {
	client client
	bucket string
	prefix string
	temp   string
}

var (
	_ content.Store      = (*Store)(nil)
	_ content.BlobLister = (*Store)(nil)
)

// New constructs a store using an already configured AWS SDK client.
func New(s3Client *awss3.Client, options Options) (*Store, error) {
	if s3Client == nil {
		return nil, fmt.Errorf("%w: nil S3 client", content.ErrInvalid)
	}
	return newStore(s3Client, options)
}

func newStore(s3Client client, options Options) (*Store, error) {
	if s3Client == nil || options.Bucket == "" || strings.TrimSpace(options.Bucket) != options.Bucket || strings.IndexByte(options.Bucket, 0) >= 0 {
		return nil, fmt.Errorf("%w: invalid S3 client or bucket", content.ErrInvalid)
	}
	prefix, err := validatePrefix(options.Prefix)
	if err != nil {
		return nil, err
	}
	if options.TempDirectory != "" {
		info, statErr := os.Stat(options.TempDirectory)
		if statErr != nil || !info.IsDir() {
			return nil, fmt.Errorf("%w: invalid temporary directory", content.ErrInvalid)
		}
	}
	return &Store{client: s3Client, bucket: options.Bucket, prefix: prefix, temp: options.TempDirectory}, nil
}

func validatePrefix(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 512 || strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || path.Clean(value) != value {
		return "", fmt.Errorf("%w: invalid S3 prefix", content.ErrInvalid)
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("%w: invalid S3 prefix", content.ErrInvalid)
		}
	}
	return value, nil
}

func (s *Store) objectKey(sum [32]byte) string {
	digest := hex.EncodeToString(sum[:])
	key := layoutVersion + "/blobs/" + digest[:2] + "/" + digest[2:4] + "/" + digest
	if s.prefix != "" {
		return s.prefix + "/" + key
	}
	return key
}

func (s *Store) blobPrefix() string {
	prefix := layoutVersion + "/blobs/"
	if s.prefix != "" {
		return s.prefix + "/" + prefix
	}
	return prefix
}

// ListBlobs returns a bounded physical inventory in digest order. The cursor
// identifies the last returned digest; it is not an authorization capability.
func (s *Store) ListBlobs(ctx context.Context, request content.PageRequest) (content.BlobPage, error) {
	if err := validate(ctx, nil); err != nil {
		return content.BlobPage{}, err
	}
	limit := request.Limit
	if limit == 0 {
		limit = content.DefaultPageSize
	}
	if limit < 1 || limit > content.MaxPageSize {
		return content.BlobPage{}, fmt.Errorf("%w: invalid page limit", content.ErrInvalid)
	}
	var cursor [32]byte
	if request.Cursor != "" {
		decoded, err := hex.DecodeString(request.Cursor)
		if err != nil || len(decoded) != len(cursor) || request.Cursor != strings.ToLower(request.Cursor) {
			return content.BlobPage{}, fmt.Errorf("%w: invalid blob cursor", content.ErrInvalid)
		}
		copy(cursor[:], decoded)
	}
	input := &awss3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket), Prefix: aws.String(s.blobPrefix()), MaxKeys: aws.Int32(int32(limit)),
	}
	if request.Cursor != "" {
		input.StartAfter = aws.String(s.objectKey(cursor))
	}
	output, err := s.client.ListObjectsV2(ctx, input)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return content.BlobPage{}, ctxErr
		}
		return content.BlobPage{}, unavailable(err)
	}
	if output == nil || output.IsTruncated == nil || len(output.CommonPrefixes) != 0 || len(output.Contents) > limit ||
		(output.KeyCount != nil && int(*output.KeyCount) != len(output.Contents)) {
		return content.BlobPage{}, fmt.Errorf("%w: invalid S3 inventory response", content.ErrCorrupt)
	}
	items := make([]content.Blob, 0, len(output.Contents))
	previous := aws.ToString(input.StartAfter)
	for _, object := range output.Contents {
		if err := ctx.Err(); err != nil {
			return content.BlobPage{}, err
		}
		if object.Key == nil || object.Size == nil || *object.Size < 0 || *object.Key <= previous {
			return content.BlobPage{}, fmt.Errorf("%w: invalid S3 blob inventory metadata", content.ErrCorrupt)
		}
		digest, parseErr := s.parseObjectKey(*object.Key)
		if parseErr != nil {
			return content.BlobPage{}, parseErr
		}
		items = append(items, content.Blob{SHA256: digest, Size: *object.Size})
		previous = *object.Key
	}
	page := content.BlobPage{Items: items}
	if aws.ToBool(output.IsTruncated) {
		if len(items) == 0 {
			return content.BlobPage{}, fmt.Errorf("%w: truncated S3 inventory made no progress", content.ErrCorrupt)
		}
		page.NextCursor = hex.EncodeToString(items[len(items)-1].SHA256[:])
	}
	return page, nil
}

func (s *Store) parseObjectKey(key string) ([32]byte, error) {
	var sum [32]byte
	relative, found := strings.CutPrefix(key, s.blobPrefix())
	parts := strings.Split(relative, "/")
	if !found || len(parts) != 3 || len(parts[0]) != 2 || len(parts[1]) != 2 || len(parts[2]) != 64 ||
		parts[0] != parts[2][:2] || parts[1] != parts[2][2:4] || parts[2] != strings.ToLower(parts[2]) {
		return sum, fmt.Errorf("%w: non-canonical ordinary blob key", content.ErrCorrupt)
	}
	decoded, err := hex.DecodeString(parts[2])
	if err != nil || len(decoded) != len(sum) {
		return sum, fmt.Errorf("%w: malformed ordinary blob key", content.ErrCorrupt)
	}
	copy(sum[:], decoded)
	return sum, nil
}

func validate(ctx context.Context, blob *content.Blob) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", content.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if blob != nil {
		return blob.Validate()
	}
	return nil
}

func (s *Store) Put(ctx context.Context, blob content.Blob, body io.Reader) (bool, error) {
	if err := validate(ctx, &blob); err != nil {
		return false, err
	}
	if body == nil {
		return false, fmt.Errorf("%w: nil blob body", content.ErrInvalid)
	}
	temporary, err := os.CreateTemp(s.temp, ".content-s3-*")
	if err != nil {
		return false, unavailable(err)
	}
	name := temporary.Name()
	defer func() { _ = temporary.Close(); _ = os.Remove(name) }()
	if err = verified.Write(ctx, localSpoolWriter{Writer: temporary}, body, blob); err != nil {
		return false, err
	}
	key := s.objectKey(blob.SHA256)
	for attempt := 0; ; attempt++ {
		if _, err = temporary.Seek(0, io.SeekStart); err != nil {
			return false, unavailable(err)
		}
		_, err = s.client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(s.bucket), Key: aws.String(key), Body: temporary,
			ContentLength: aws.Int64(blob.Size), IfNoneMatch: aws.String("*"),
		}, func(options *awss3.Options) {
			// The local spool already authenticates the request body. Requiring
			// checksums avoids optional aws-chunked checksum trailers that many
			// otherwise-compatible S3 implementations do not support.
			options.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		})
		if err == nil {
			return true, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if matches(err, []string{"PreconditionFailed"}, http.StatusPreconditionFailed) {
			if compareErr := s.matches(ctx, blob, temporary); compareErr != nil {
				return false, compareErr
			}
			return false, nil
		}
		if !matches(err, []string{"ConditionalRequestConflict"}, http.StatusConflict) || attempt == conditionalRetries {
			return false, unavailable(err)
		}
		timer := time.NewTimer(conditionalDelay << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Store) matches(ctx context.Context, blob content.Blob, temporary *os.File) error {
	info, found, err := s.Head(ctx, blob.SHA256)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: conditional write conflicted but the object is absent", content.ErrUnavailable)
	}
	if info.Size != blob.Size {
		return content.ErrConflict
	}
	if _, err = temporary.Seek(0, io.SeekStart); err != nil {
		return unavailable(err)
	}
	reader, err := s.Open(ctx, blob, nil)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return fmt.Errorf("%w: conditional write conflict disappeared: %w", content.ErrUnavailable, err)
		}
		return err
	}
	compareErr := compare(ctx, reader, localSpoolReader{Reader: temporary}, blob.Size)
	closeErr := reader.Close()
	return errors.Join(compareErr, closeErr)
}

// compare returns nil only for exact equality. A conclusive byte/length
// mismatch includes ErrConflict; read failures remain joined with that result.
func compare(ctx context.Context, left, right io.Reader, size int64) error {
	a, b := make([]byte, 64*1024), make([]byte, 64*1024)
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		wanted := int64(len(a))
		if wanted > remaining {
			wanted = remaining
		}
		leftCount, leftErr := readBlock(left, a[:wanted])
		rightCount, rightErr := readBlock(right, b[:wanted])
		leftErr = blockError(leftErr, leftCount, int(wanted), "retained S3 object")
		rightErr = blockError(rightErr, rightCount, int(wanted), "local comparison spool")
		mismatch := leftCount != int(wanted) || rightCount != int(wanted) ||
			!equal(a[:leftCount], b[:rightCount])
		terminal := errors.Join(leftErr, rightErr)
		if mismatch {
			return errors.Join(content.ErrConflict, terminal)
		}
		if terminal != nil {
			return terminal
		}
		remaining -= wanted
	}
	// Force verified full readers to settle (important for empty objects).
	var probe [1]byte
	count, err := left.Read(probe[:])
	if count != 0 {
		return errors.Join(content.ErrConflict, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func readBlock(reader io.Reader, buffer []byte) (int, error) {
	total, noProgress := 0, 0
	for total < len(buffer) {
		count, err := reader.Read(buffer[total:])
		if count < 0 || count > len(buffer)-total {
			return total, fmt.Errorf("%w: comparison reader returned an invalid byte count", content.ErrCorrupt)
		}
		total += count
		if count == 0 && err == nil {
			noProgress++
			if noProgress == 100 {
				return total, io.ErrNoProgress
			}
		} else {
			noProgress = 0
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func blockError(err error, count, wanted int, description string) error {
	if count == wanted && errors.Is(err, io.EOF) {
		return nil
	}
	if count != wanted && (err == nil || errors.Is(err, io.EOF)) {
		return fmt.Errorf("%w: %s ended with %d bytes missing", content.ErrCorrupt, description, wanted-count)
	}
	return err
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for i := range a {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}

func (s *Store) Head(ctx context.Context, sum [32]byte) (content.Info, bool, error) {
	if err := validate(ctx, nil); err != nil {
		return content.Info{}, false, err
	}
	key := s.objectKey(sum)
	output, err := s.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return content.Info{}, false, ctxErr
		}
		if matches(err, []string{"NoSuchKey", "NotFound"}, http.StatusNotFound) {
			return content.Info{}, false, nil
		}
		return content.Info{}, false, unavailable(err)
	}
	if output == nil || output.ContentLength == nil || *output.ContentLength < 0 {
		return content.Info{}, false, fmt.Errorf("%w: invalid S3 head metadata", content.ErrCorrupt)
	}
	return content.Info{Size: *output.ContentLength}, true, nil
}

func (s *Store) Open(ctx context.Context, blob content.Blob, wanted *content.Range) (io.ReadCloser, error) {
	if err := validate(ctx, &blob); err != nil {
		return nil, err
	}
	info, found, err := s.Head(ctx, blob.SHA256)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, content.ErrNotFound
	}
	if info.Size != blob.Size {
		return nil, fmt.Errorf("%w: retained length %d, expected %d", content.ErrCorrupt, info.Size, blob.Size)
	}
	start, end, full := int64(0), blob.Size, wanted == nil
	input := &awss3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(s.objectKey(blob.SHA256))}
	if wanted != nil {
		if err = wanted.Validate(blob.Size); err != nil {
			return nil, err
		}
		start, end = wanted.Start, wanted.End
		input.Range = aws.String(fmt.Sprintf("bytes=%d-%d", start, end-1))
	}
	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if matches(err, []string{"NoSuchKey", "NotFound"}, http.StatusNotFound) {
			return nil, content.ErrNotFound
		}
		if wanted != nil && matches(err, []string{"InvalidRange", "RequestedRangeNotSatisfiable"}, http.StatusRequestedRangeNotSatisfiable) {
			return nil, content.ErrRangeNotSatisfiable
		}
		return nil, unavailable(err)
	}
	expected := end - start
	if output == nil || output.Body == nil || output.ContentLength == nil || *output.ContentLength < 0 || *output.ContentLength != expected {
		metadataErr := fmt.Errorf("%w: invalid S3 get metadata", content.ErrCorrupt)
		return nil, errors.Join(metadataErr, closeOutput(ctx, output))
	}
	if wanted != nil {
		expectedRange := fmt.Sprintf("bytes %d-%d/%d", start, end-1, blob.Size)
		if output.ContentRange == nil || *output.ContentRange != expectedRange {
			metadataErr := fmt.Errorf("%w: inconsistent S3 range metadata", content.ErrCorrupt)
			return nil, errors.Join(metadataErr, closeOutput(ctx, output))
		}
	}
	return verified.New(ctx, &backendBody{ctx: ctx, body: output.Body}, blob, expected, full), nil
}

func closeOutput(ctx context.Context, output *awss3.GetObjectOutput) error {
	if output != nil && output.Body != nil {
		return classifyIO(ctx, output.Body.Close())
	}
	return nil
}

type localSpoolWriter struct{ io.Writer }

func (writer localSpoolWriter) Write(buffer []byte) (int, error) {
	count, err := writer.Writer.Write(buffer)
	if err != nil {
		return count, unavailable(err)
	}
	if count != len(buffer) {
		return count, unavailable(io.ErrShortWrite)
	}
	return count, nil
}

type localSpoolReader struct{ io.Reader }

func (reader localSpoolReader) Read(buffer []byte) (int, error) {
	count, err := reader.Reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		err = unavailable(err)
	}
	return count, err
}

type backendBody struct {
	ctx  context.Context
	body io.ReadCloser
}

func (b *backendBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	return n, classifyIO(b.ctx, err)
}
func (b *backendBody) Close() error { return classifyIO(b.ctx, b.body.Close()) }
func classifyIO(ctx context.Context, err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return unavailable(err)
}

func unavailable(err error) error {
	return fmt.Errorf("%w: S3 operation: %w", content.ErrUnavailable, err)
}

func matches(err error, codes []string, status int) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		for _, code := range codes {
			if api.ErrorCode() == code {
				return true
			}
		}
		return false
	}
	var response interface{ HTTPStatusCode() int }
	return errors.As(err, &response) && response.HTTPStatusCode() == status
}
