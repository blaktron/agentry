package registry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// fakeS3 is an in-process stand-in for S3. These tests exercise the store's
// logic — key layout, conditional-write handling, not-found mapping — never a
// network. Behaviour against live AWS is untested here (DEV-029).
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	// conditionalWrites off makes PutObject reject If-None-Match the way an
	// older S3-compatible gateway does.
	conditionalWrites bool
	puts              int
	lastIfNoneMatch   *string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}, conditionalWrites: true}
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	f.lastIfNoneMatch = in.IfNoneMatch
	if in.IfNoneMatch != nil {
		if !f.conditionalWrites {
			return nil, statusErr("NotImplemented", http.StatusNotImplemented)
		}
		if _, exists := f.objects[*in.Key]; exists && *in.IfNoneMatch == "*" {
			return nil, statusErr("PreconditionFailed", http.StatusPreconditionFailed)
		}
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[*in.Key] = body
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[*in.Key]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[*in.Key]; !ok {
		return nil, &s3types.NotFound{}
	}
	return &s3.HeadObjectOutput{}, nil
}

// statusErr builds the smithy response error shape the SDK returns when no
// modeled type matches — which is exactly how 412 and 501 arrive.
func statusErr(code string, status int) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "PutObject",
		Err: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      &smithy.GenericAPIError{Code: code},
		},
	}
}

// S3Store must satisfy the same interface LocalFS does.
var _ BlobStore = (*S3Store)(nil)

func TestS3StoreRoundTrip(t *testing.T) {
	f := newFakeS3()
	st := NewS3WithAPI(f, "bucket", "")
	key := ArchiveKey("sha256:abcdef0123456789")

	if err := st.Put(t.Context(), key, strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	exists, err := st.Exists(t.Context(), key)
	if err != nil || !exists {
		t.Fatalf("Exists = %v, %v; want true, nil", exists, err)
	}
	rc, err := st.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "payload" {
		t.Errorf("Get returned %q, want %q", got, "payload")
	}
}

func TestS3StoreAppliesPrefix(t *testing.T) {
	f := newFakeS3()
	st := NewS3WithAPI(f, "bucket", "staging/")
	if err := st.Put(t.Context(), "releases/ab/abcd.tar.zst", strings.NewReader("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := f.objects["staging/releases/ab/abcd.tar.zst"]; !ok {
		t.Errorf("object stored under the wrong key; have %v", keysOf(f))
	}
	// The prefix must be transparent on the way back out.
	if exists, err := st.Exists(t.Context(), "releases/ab/abcd.tar.zst"); err != nil || !exists {
		t.Errorf("Exists through the prefix = %v, %v; want true, nil", exists, err)
	}
}

// Content-addressed keys make a second Put a no-op, not an overwrite: the
// 412 from the conditional write is the success path.
func TestS3StorePutIsWriteOnce(t *testing.T) {
	f := newFakeS3()
	st := NewS3WithAPI(f, "bucket", "")
	key := ArchiveKey("sha256:deadbeef")

	if err := st.Put(t.Context(), key, strings.NewReader("first")); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := st.Put(t.Context(), key, strings.NewReader("second")); err != nil {
		t.Fatalf("second Put must succeed as a no-op, got: %v", err)
	}
	if got := string(f.objects[key]); got != "first" {
		t.Errorf("stored bytes = %q; the second Put overwrote a content-addressed object", got)
	}
	if f.lastIfNoneMatch == nil || *f.lastIfNoneMatch != "*" {
		t.Errorf("If-None-Match = %v, want \"*\" (the write-once guard)", f.lastIfNoneMatch)
	}
}

// An S3-compatible backend without conditional writes must still work.
func TestS3StoreFallsBackWhenConditionalWritesAreUnsupported(t *testing.T) {
	f := newFakeS3()
	f.conditionalWrites = false
	st := NewS3WithAPI(f, "bucket", "")
	key := ArchiveKey("sha256:cafe")

	if err := st.Put(t.Context(), key, strings.NewReader("body")); err != nil {
		t.Fatalf("Put on a backend without conditional writes: %v", err)
	}
	if got := string(f.objects[key]); got != "body" {
		t.Errorf("stored %q, want %q", got, "body")
	}
	// Second Put short-circuits on the existence check rather than rewriting.
	before := f.puts
	if err := st.Put(t.Context(), key, strings.NewReader("other")); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if got := string(f.objects[key]); got != "body" {
		t.Errorf("fallback path overwrote the object: %q", got)
	}
	if f.puts != before+1 {
		t.Errorf("puts = %d, want one refused attempt then no rewrite", f.puts-before)
	}
}

func TestS3StoreExistsIsFalseNotError(t *testing.T) {
	st := NewS3WithAPI(newFakeS3(), "bucket", "")
	exists, err := st.Exists(t.Context(), ArchiveKey("sha256:missing"))
	if err != nil {
		t.Fatalf("Exists on a missing key returned an error: %v", err)
	}
	if exists {
		t.Error("Exists = true for a key that was never written")
	}
}

func TestS3StoreGetMissingKeyErrors(t *testing.T) {
	st := NewS3WithAPI(newFakeS3(), "bucket", "")
	if _, err := st.Get(t.Context(), ArchiveKey("sha256:missing")); err == nil {
		t.Error("Get on a missing key returned no error")
	}
}

func TestS3StoreRefusesOversizedBody(t *testing.T) {
	st := NewS3WithAPI(newFakeS3(), "bucket", "")
	err := st.Put(t.Context(), "releases/aa/a.tar.zst", &endlessReader{})
	if err == nil {
		t.Fatal("Put accepted an unbounded body")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want a size refusal", err)
	}
}

func TestNewS3RequiresBucket(t *testing.T) {
	if _, err := NewS3(t.Context(), S3Options{}); err == nil {
		t.Error("NewS3 accepted an empty bucket")
	}
}

func TestS3ErrorClassification(t *testing.T) {
	if !isPreconditionFailed(statusErr("PreconditionFailed", http.StatusPreconditionFailed)) {
		t.Error("412 not classified as precondition-failed")
	}
	if !isNotImplemented(statusErr("NotImplemented", http.StatusNotImplemented)) {
		t.Error("501 not classified as not-implemented")
	}
	if !isNotFound(&s3types.NotFound{}) || !isNotFound(&s3types.NoSuchKey{}) {
		t.Error("modeled not-found types not classified as not-found")
	}
	if isNotFound(errors.New("some other failure")) {
		t.Error("an unrelated error was classified as not-found")
	}
	if isPreconditionFailed(errors.New("some other failure")) {
		t.Error("an unrelated error was classified as precondition-failed")
	}
}

func TestS3ObjectKeyIgnoresLeadingSlash(t *testing.T) {
	st := NewS3WithAPI(newFakeS3(), "bucket", "p")
	if got := st.objectKey("/releases/x"); got != "p/releases/x" {
		t.Errorf("objectKey = %q, want %q", got, "p/releases/x")
	}
	bare := NewS3WithAPI(newFakeS3(), "bucket", "")
	if got := bare.objectKey("releases/x"); got != "releases/x" {
		t.Errorf("objectKey without a prefix = %q", got)
	}
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func keysOf(f *fakeS3) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	return out
}

var _ S3API = (*fakeS3)(nil)
var _ = aws.String
