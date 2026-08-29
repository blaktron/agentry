package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3API is the slice of the S3 client S3Store uses. Narrowing it to three
// calls is what lets the tests run against an in-process fake instead of a
// network: see blobstore_s3_test.go.
type S3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// S3Options configures the S3-backed BlobStore.
type S3Options struct {
	Bucket string
	Region string
	// Prefix is prepended to every key, letting one bucket host several
	// environments. A trailing slash is optional.
	Prefix string
	// Endpoint overrides the AWS endpoint (MinIO, or an S3-compatible store).
	Endpoint string
	// UsePathStyle addresses buckets as {endpoint}/{bucket}/{key}. MinIO
	// needs it; AWS does not.
	UsePathStyle bool
}

// S3Store is the SaaS BlobStore (D-21). Keys are content-addressed by the
// caller (ArchiveKey), so an object's name already commits to its bytes.
type S3Store struct {
	api    S3API
	bucket string
	prefix string
}

// maxArchiveBufferBytes bounds what Put will hold in memory. Put buffers
// because the S3 request signer needs to seek the body, and because §1.6.4
// makes agents small by construction — the §19 archive quota is 10 MB, so a
// 64 MB ceiling is generous headroom, not a design assumption. A body past
// the ceiling is refused rather than silently truncated.
const maxArchiveBufferBytes = 64 << 20

// NewS3 builds an S3Store using the ambient AWS credential chain (task role
// on ECS, instance profile, environment, or shared config).
func NewS3(ctx context.Context, opt S3Options) (*S3Store, error) {
	if opt.Bucket == "" {
		return nil, errors.New("blobstore: s3 bucket is required")
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if opt.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(opt.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("blobstore: aws config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opt.Endpoint != "" {
			o.BaseEndpoint = aws.String(opt.Endpoint)
		}
		o.UsePathStyle = opt.UsePathStyle
	})
	return NewS3WithAPI(client, opt.Bucket, opt.Prefix), nil
}

// NewS3WithAPI builds an S3Store over an existing client (tests, and callers
// that already hold a configured s3.Client).
func NewS3WithAPI(api S3API, bucket, prefix string) *S3Store {
	return &S3Store{api: api, bucket: bucket, prefix: strings.Trim(prefix, "/")}
}

// objectKey applies the configured prefix.
func (s *S3Store) objectKey(key string) string {
	key = strings.TrimPrefix(key, "/")
	if s.prefix == "" {
		return key
	}
	return s.prefix + "/" + key
}

// Put implements BlobStore with write-once semantics.
//
// If-None-Match: * makes S3 itself refuse to overwrite an existing object, so
// two workers racing on the same digest cannot interleave a partial rewrite of
// a blob a third reader is already streaming. The 412 that a loser gets back
// is success from this layer's point of view: the key is content-addressed, so
// whoever won stored the same bytes.
func (s *S3Store) Put(ctx context.Context, key string, r io.Reader) error {
	body, err := io.ReadAll(io.LimitReader(r, maxArchiveBufferBytes+1))
	if err != nil {
		return fmt.Errorf("blobstore: read archive: %w", err)
	}
	if len(body) > maxArchiveBufferBytes {
		return fmt.Errorf("blobstore: archive exceeds %d bytes", maxArchiveBufferBytes)
	}
	_, err = s.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.objectKey(key)),
		Body:        bytes.NewReader(body),
		IfNoneMatch: aws.String("*"),
	})
	if err == nil {
		return nil
	}
	if isPreconditionFailed(err) {
		return nil // already stored, by the same digest
	}
	// Not every S3-compatible backend implements conditional writes. Falling
	// back to an existence check keeps MinIO and older gateways working
	// without weakening the AWS path, where the conditional write is what
	// actually holds.
	if isNotImplemented(err) {
		exists, existsErr := s.Exists(ctx, key)
		if existsErr == nil && exists {
			return nil
		}
		_, err = s.api.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(s.objectKey(key)),
			Body:   bytes.NewReader(body),
		})
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("blobstore: put %s: %w", key, err)
}

// Get implements BlobStore. The caller closes the returned body.
func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err != nil {
		return nil, fmt.Errorf("blobstore: get %s: %w", key, err)
	}
	return out.Body, nil
}

// Exists implements BlobStore.
func (s *S3Store) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	})
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("blobstore: head %s: %w", key, err)
}

func isNotFound(err error) bool {
	var nf *s3types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	return httpStatus(err) == http.StatusNotFound
}

func isPreconditionFailed(err error) bool {
	if httpStatus(err) == http.StatusPreconditionFailed {
		return true
	}
	return apiErrorCode(err) == "PreconditionFailed"
}

func isNotImplemented(err error) bool {
	if httpStatus(err) == http.StatusNotImplemented {
		return true
	}
	return apiErrorCode(err) == "NotImplemented"
}

func apiErrorCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// httpStatus digs the HTTP status out of a smithy response error, which is
// how S3 reports 412 and 501 when no modeled error type matches.
func httpStatus(err error) int {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}
