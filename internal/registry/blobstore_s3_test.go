package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
// network. Behaviour against live AWS is untested here.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	// conditionalWrites off makes PutObject reject If-None-Match the way an
	// older S3-compatible gateway does.
	conditionalWrites bool
	puts              int
	lastIfNoneMatch   *string
	// buckets and keys record the bucket and the key the latest request of
	// each kind ("put", "get", "head", "delete") named.
	buckets map[string]string
	keys    map[string]string
	// conditions records the If-None-Match of every PutObject, in order.
	conditions []*string
	// putErrs are returned, one per PutObject and before anything is
	// stored; headErr, getErr and deleteErr fail every call of that kind.
	putErrs                    []error
	headErr, getErr, deleteErr error
}

func newFakeS3() *fakeS3 {
	return &fakeS3{
		objects: map[string][]byte{}, conditionalWrites: true,
		buckets: map[string]string{}, keys: map[string]string{},
	}
}

func (f *fakeS3) note(op string, bucket, key *string) {
	f.buckets[op], f.keys[op] = aws.ToString(bucket), aws.ToString(key)
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	f.lastIfNoneMatch = in.IfNoneMatch
	f.conditions = append(f.conditions, in.IfNoneMatch)
	f.note("put", in.Bucket, in.Key)
	if len(f.putErrs) > 0 {
		err := f.putErrs[0]
		f.putErrs = f.putErrs[1:]
		return nil, err
	}
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
	f.note("get", in.Bucket, in.Key)
	if f.getErr != nil {
		return nil, f.getErr
	}
	b, ok := f.objects[*in.Key]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("head", in.Bucket, in.Key)
	if f.headErr != nil {
		return nil, f.headErr
	}
	if _, ok := f.objects[*in.Key]; !ok {
		return nil, &s3types.NotFound{}
	}
	return &s3.HeadObjectOutput{}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("delete", in.Bucket, in.Key)
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	delete(f.objects, *in.Key)
	return &s3.DeleteObjectOutput{}, nil
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

	// Every operation asks the bucket it was built with for the prefixed key,
	// however the prefix and the key spell their slashes.
	for _, tc := range []struct{ prefix, key, want string }{
		{"staging/", "releases/ab/abcd.tar.zst", "staging/releases/ab/abcd.tar.zst"},
		{"/staging/", "releases/ab/abcd.tar.zst", "staging/releases/ab/abcd.tar.zst"},
		{"/stage/env/", "/releases/ab/abcd.tar.zst", "stage/env/releases/ab/abcd.tar.zst"},
		{"stage/env", "releases/ab/abcd.tar.zst", "stage/env/releases/ab/abcd.tar.zst"},
		{"", "releases/ab/abcd.tar.zst", "releases/ab/abcd.tar.zst"},
	} {
		f := newFakeS3()
		st := NewS3WithAPI(f, "the-bucket", tc.prefix)
		if err := st.Put(t.Context(), tc.key, strings.NewReader("x")); err != nil {
			t.Fatalf("prefix %q: Put: %v", tc.prefix, err)
		}
		if _, ok := f.objects[tc.want]; !ok {
			t.Errorf("prefix %q: object stored under %v, want %q", tc.prefix, keysOf(f), tc.want)
		}
		rc, err := st.Get(t.Context(), tc.key)
		if err != nil {
			t.Fatalf("prefix %q: Get through the prefix: %v", tc.prefix, err)
		}
		_ = rc.Close()
		if ok, err := st.Exists(t.Context(), tc.key); err != nil || !ok {
			t.Errorf("prefix %q: Exists = %v, %v", tc.prefix, ok, err)
		}
		if err := st.Delete(t.Context(), tc.key); err != nil {
			t.Fatalf("prefix %q: Delete: %v", tc.prefix, err)
		}
		if len(f.objects) != 0 {
			t.Errorf("prefix %q: Delete through the prefix left %v", tc.prefix, keysOf(f))
		}
		for _, op := range []string{"put", "get", "head", "delete"} {
			if f.buckets[op] != "the-bucket" || f.keys[op] != tc.want {
				t.Errorf("prefix %q: %s asked bucket %q key %q, want the-bucket %q", tc.prefix, op, f.buckets[op], f.keys[op], tc.want)
			}
		}
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
	if f.buckets["put"] != "bucket" || f.keys["put"] != key {
		t.Errorf("Put asked bucket %q key %q, want bucket %q", f.buckets["put"], f.keys["put"], key)
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

	t.Run("the unconditional write keeps the bucket and the prefix", func(t *testing.T) {
		f := newFakeS3()
		f.conditionalWrites = false
		st := NewS3WithAPI(f, "the-bucket", "p/")
		if err := st.Put(t.Context(), "releases/ab/x.tar.zst", strings.NewReader("body")); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.objects["p/releases/ab/x.tar.zst"]; !ok {
			t.Fatalf("object stored under %v", keysOf(f))
		}
		if f.buckets["put"] != "the-bucket" || f.keys["put"] != "p/releases/ab/x.tar.zst" {
			t.Errorf("the second write asked bucket %q key %q", f.buckets["put"], f.keys["put"])
		}
		if len(f.conditions) != 2 || f.conditions[0] == nil || *f.conditions[0] != "*" || f.conditions[1] != nil {
			t.Errorf("preconditions %v, want the guarded write then an unconditional one", f.conditions)
		}
	})
	t.Run("a failed existence check does not stop the write", func(t *testing.T) {
		f := newFakeS3()
		f.conditionalWrites = false
		f.headErr = errors.New("head failed")
		st := NewS3WithAPI(f, "bucket", "")
		if err := st.Put(t.Context(), "releases/ab/x.tar.zst", strings.NewReader("body")); err != nil {
			t.Fatal(err)
		}
		if got := string(f.objects["releases/ab/x.tar.zst"]); got != "body" {
			t.Errorf("stored %q", got)
		}
	})
	t.Run("a failure that is neither a conflict nor missing support is not retried", func(t *testing.T) {
		boom := errors.New("backend unavailable")
		f := newFakeS3()
		f.putErrs = []error{statusErr("InternalError", http.StatusInternalServerError)}
		st := NewS3WithAPI(f, "bucket", "")
		err := st.Put(t.Context(), "releases/ab/x.tar.zst", strings.NewReader("body"))
		var re interface{ HTTPStatusCode() int }
		if err == nil || !errors.As(err, &re) || re.HTTPStatusCode() != http.StatusInternalServerError ||
			!strings.HasPrefix(err.Error(), "blobstore: put releases/ab/x.tar.zst: ") {
			t.Fatalf("Put = %v, want the wrapped 500", err)
		}
		if f.puts != 1 || len(f.objects) != 0 {
			t.Errorf("%d puts and %v stored, want one attempt and nothing", f.puts, keysOf(f))
		}
		f = newFakeS3()
		f.conditionalWrites = false
		f.putErrs = []error{statusErr("NotImplemented", http.StatusNotImplemented), boom}
		st = NewS3WithAPI(f, "bucket", "")
		err = st.Put(t.Context(), "releases/ab/x.tar.zst", strings.NewReader("body"))
		if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "blobstore: put releases/ab/x.tar.zst: ") {
			t.Fatalf("Put whose fallback fails = %v, want the wrapped failure", err)
		}
		if len(f.objects) != 0 {
			t.Errorf("stored %v after a failed write", keysOf(f))
		}
	})
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

	// A plain 404 is also absent; any other failure is an error and not an
	// answer, wrapped with the key.
	f := newFakeS3()
	f.headErr = statusErr("Anything", http.StatusNotFound)
	if exists, err := NewS3WithAPI(f, "bucket", "").Exists(t.Context(), "k"); err != nil || exists {
		t.Errorf("Exists on a 404 = %v, %v; want false, nil", exists, err)
	}
	boom := errors.New("backend unavailable")
	f.headErr = boom
	exists, err = NewS3WithAPI(f, "bucket", "").Exists(t.Context(), "k")
	if exists || !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "blobstore: head k: ") {
		t.Errorf("Exists on a failure = %v, %v; want false and the wrapped failure", exists, err)
	}
}

func TestS3StoreGetMissingKeyErrors(t *testing.T) {
	st := NewS3WithAPI(newFakeS3(), "bucket", "")
	_, err := st.Get(t.Context(), ArchiveKey("sha256:missing"))
	if err == nil {
		t.Fatal("Get on a missing key returned no error")
	}
	var nsk *s3types.NoSuchKey
	if !errors.As(err, &nsk) || !strings.HasPrefix(err.Error(), "blobstore: get ") {
		t.Errorf("Get on a missing key = %v, want the wrapped no-such-key", err)
	}
}

func TestS3StoreRefusesOversizedBody(t *testing.T) {
	st := NewS3WithAPI(newFakeS3(), "bucket", "")
	err := st.Put(t.Context(), "releases/aa/a.tar.zst", &endlessReader{})
	if err == nil {
		t.Fatal("Put accepted an unbounded body")
	}
	if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), "67108864") {
		t.Errorf("error = %v, want a size refusal naming the 64 MiB limit", err)
	}

	// A body of exactly 64 MiB is stored whole; one byte more is refused
	// before anything is sent.
	const limit = 64 << 20
	exact := &sizingS3{fakeS3: newFakeS3()}
	if err := NewS3WithAPI(exact, "bucket", "").Put(t.Context(), "k", io.LimitReader(endlessReader{}, limit)); err != nil {
		t.Fatalf("a body of exactly the limit was refused: %v", err)
	}
	if exact.n != limit {
		t.Errorf("%d bytes sent, want all %d", exact.n, limit)
	}
	over := &sizingS3{fakeS3: newFakeS3()}
	if err := NewS3WithAPI(over, "bucket", "").Put(t.Context(), "k", io.LimitReader(endlessReader{}, limit+1)); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Errorf("a body one byte over the limit: %v", err)
	}
	if over.puts != 0 {
		t.Error("an oversized body was sent")
	}

	// A body that cannot be read is refused, not stored empty.
	broken := newFakeS3()
	boom := errors.New("reader failed")
	if err := NewS3WithAPI(broken, "bucket", "").Put(t.Context(), "k", &errReader{boom}); !errors.Is(err, boom) ||
		!strings.HasPrefix(err.Error(), "blobstore: read archive: ") {
		t.Errorf("Put with a failing reader = %v", err)
	}
	if broken.puts != 0 {
		t.Error("a body that failed to read was sent")
	}
}

// sizingS3 counts the bytes of the body a PutObject is given instead of
// keeping them.
type sizingS3 struct {
	*fakeS3
	n int64
}

func (s *sizingS3) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.mu.Lock()
	s.puts++
	s.mu.Unlock()
	n, err := io.Copy(io.Discard, in.Body)
	s.n = n
	return &s3.PutObjectOutput{}, err
}

func TestNewS3RequiresBucket(t *testing.T) {
	if _, err := NewS3(t.Context(), S3Options{}); err == nil {
		t.Error("NewS3 accepted an empty bucket")
	} else if !strings.Contains(err.Error(), "bucket is required") {
		t.Errorf("NewS3 without a bucket: %v", err)
	}

	// The options reach the store and its client; nothing is sent.
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	st, err := NewS3(t.Context(), S3Options{
		Bucket: "b", Region: "eu-test-1", Prefix: "/env/", Endpoint: "http://127.0.0.1:9", UsePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := st.api.(*s3.Client).Options()
	if st.bucket != "b" || st.prefix != "env" || opts.Region != "eu-test-1" || !opts.UsePathStyle ||
		aws.ToString(opts.BaseEndpoint) != "http://127.0.0.1:9" {
		t.Errorf("store %q prefix %q, client region %q path-style %v endpoint %q",
			st.bucket, st.prefix, opts.Region, opts.UsePathStyle, aws.ToString(opts.BaseEndpoint))
	}
	plain, err := NewS3(t.Context(), S3Options{Bucket: "b", Region: "eu-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if o := plain.api.(*s3.Client).Options(); o.UsePathStyle || o.BaseEndpoint != nil {
		t.Errorf("default client: path-style %v endpoint %v; want the AWS defaults", o.UsePathStyle, o.BaseEndpoint)
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

	// Each class is recognised by its status alone, by its code alone, and
	// through a wrapping; no other status or code is taken for it.
	code := func(c string) error { return &smithy.GenericAPIError{Code: c} }
	for _, tc := range []struct {
		name                   string
		err                    error
		notFound, precond, not bool
	}{
		{"status 404", statusErr("Whatever", http.StatusNotFound), true, false, false},
		{"status 412", statusErr("Whatever", http.StatusPreconditionFailed), false, true, false},
		{"status 501", statusErr("Whatever", http.StatusNotImplemented), false, false, true},
		{"code PreconditionFailed", code("PreconditionFailed"), false, true, false},
		{"code NotImplemented", code("NotImplemented"), false, false, true},
		{"code only, another", code("AccessDenied"), false, false, false},
		{"status 403", statusErr("AccessDenied", http.StatusForbidden), false, false, false},
		{"status 409", statusErr("Whatever", http.StatusConflict), false, false, false},
		{"status 405", statusErr("Whatever", http.StatusMethodNotAllowed), false, false, false},
		{"status 500", statusErr("InternalError", http.StatusInternalServerError), false, false, false},
		{"wrapped no-such-key", fmt.Errorf("wrapped: %w", &s3types.NoSuchKey{}), true, false, false},
		{"wrapped 412", fmt.Errorf("wrapped: %w", statusErr("Whatever", http.StatusPreconditionFailed)), false, true, false},
	} {
		if got := isNotFound(tc.err); got != tc.notFound {
			t.Errorf("%s: isNotFound = %v, want %v", tc.name, got, tc.notFound)
		}
		if got := isPreconditionFailed(tc.err); got != tc.precond {
			t.Errorf("%s: isPreconditionFailed = %v, want %v", tc.name, got, tc.precond)
		}
		if got := isNotImplemented(tc.err); got != tc.not {
			t.Errorf("%s: isNotImplemented = %v, want %v", tc.name, got, tc.not)
		}
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
	if got := bare.objectKey("/releases/x"); got != "releases/x" {
		t.Errorf("objectKey without a prefix and with a leading slash = %q", got)
	}
	for _, prefix := range []string{"p/q", "p/q/", "/p/q", "/p/q/"} {
		if got := NewS3WithAPI(newFakeS3(), "bucket", prefix).objectKey("releases/x"); got != "p/q/releases/x" {
			t.Errorf("objectKey with prefix %q = %q, want p/q/releases/x", prefix, got)
		}
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

// Delete removes the object and a second delete is not an error (a sweep
// that runs twice is a sweep that ran).
func TestS3StoreDeleteIsIdempotent(t *testing.T) {
	f := newFakeS3()
	st := NewS3WithAPI(f, "bucket", "x/")
	if err := st.Put(t.Context(), "runs/a/b", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(t.Context(), "runs/a/b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := st.Exists(t.Context(), "runs/a/b"); ok {
		t.Fatal("the object survived its delete")
	}
	if err := st.Delete(t.Context(), "runs/a/b"); err != nil {
		t.Fatalf("a second Delete is an error: %v", err)
	}
	if f.buckets["delete"] != "bucket" || f.keys["delete"] != "x/runs/a/b" {
		t.Errorf("Delete asked bucket %q key %q, want bucket x/runs/a/b", f.buckets["delete"], f.keys["delete"])
	}

	// A backend that answers not-found is the same as success; any other
	// failure is an error, wrapped with the key.
	f.deleteErr = &s3types.NoSuchKey{}
	if err := st.Delete(t.Context(), "runs/a/b"); err != nil {
		t.Errorf("a not-found answer is an error: %v", err)
	}
	boom := errors.New("backend unavailable")
	f.deleteErr = boom
	if err := st.Delete(t.Context(), "runs/a/b"); !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "blobstore: delete runs/a/b: ") {
		t.Errorf("Delete on a failure = %v, want the wrapped failure", err)
	}
}
