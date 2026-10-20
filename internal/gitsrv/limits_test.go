package gitsrv

// White-box: the shipped limits, the refusals the git handler answers before
// it runs git, and the environment it hands the pre-receive hook. None of it
// needs a database, so it runs wherever the package builds.

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/registry"
)

// limitsStore is a RepoStore over a scratch data directory, with the hooks
// directory a push makes its hook in.
func limitsStore(t *testing.T) *RepoStore {
	t.Helper()
	s, err := NewRepoStore(config.Config{Git: config.Git{DataDir: t.TempDir(), HooksDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestShippedLimitDefaults: a limit left unset takes its shipped value, a
// positive one is used as given, and zero or a negative number never
// becomes a budget of nothing.
func TestShippedLimitDefaults(t *testing.T) {
	for _, set := range []struct{ in, want int }{{0, 20}, {-3, 20}, {1, 1}, {7, 7}} {
		cfg := config.Config{}
		cfg.Limits.GitConcurrentPerIP = set.in
		if got := gitConcurrentPerIP(cfg); got != set.want {
			t.Errorf("concurrent git operations per address, set %d: %d, want %d", set.in, got, set.want)
		}
	}
	for _, set := range []struct{ in, want int }{{0, 60}, {-3, 60}, {1, 1}, {7, 7}} {
		h := &Handler{}
		h.cfg.Limits.GitPushesPerHour = set.in
		if got := h.pushesPerHour(); got != set.want {
			t.Errorf("pushes per hour, set %d: %d, want %d", set.in, got, set.want)
		}
		h.cfg.Limits.SSHKeyOffersPerMin = set.in
		if got := h.sshKeyOffersPerMin(); got != set.want {
			t.Errorf("ssh key offers per minute, set %d: %d, want %d", set.in, got, set.want)
		}
	}
}

// TestNewHandlerBoundsGitWork: the handler is built with the instance-wide
// cap, the per-repository cap, the per-address budget and the two
// timeouts the rest of the package relies on.
func TestNewHandlerBoundsGitWork(t *testing.T) {
	h := NewHandler(config.Config{}, nil, limitsStore(t), nil, nil, nil)
	t.Cleanup(func() { _ = h.Close() })
	if got := cap(h.sem); got != 32 {
		t.Errorf("instance-wide git cap = %d, want 32", got)
	}
	if got := h.perRepo.capacity; got != 4 {
		t.Errorf("per-repository git cap = %d, want 4", got)
	}
	if got := h.perClient.capacity; got != 20 {
		t.Errorf("per-address git budget = %d, want 20", got)
	}
	if h.opTimeout != 5*time.Minute || h.postReceiveTimeout != 2*time.Minute {
		t.Errorf("timeouts = %v / %v, want 5m / 2m", h.opTimeout, h.postReceiveTimeout)
	}

	cfg := config.Config{}
	cfg.Limits.GitConcurrentPerIP = 3
	h2 := NewHandler(cfg, nil, limitsStore(t), nil, nil, nil)
	t.Cleanup(func() { _ = h2.Close() })
	if got := h2.perClient.capacity; got != 3 {
		t.Errorf("configured per-address git budget = %d, want 3", got)
	}
}

// TestPushBudgetDefaultIsSixtyAnHour: with nothing configured a repository
// may take sixty pushes at once and the sixty-first waits; another
// repository has a budget of its own.
func TestPushBudgetDefaultIsSixtyAnHour(t *testing.T) {
	h := NewHandler(config.Config{}, nil, limitsStore(t), nil, nil, nil)
	t.Cleanup(func() { _ = h.Close() })
	busy := registry.Agent{ID: uuid.New(), RepoID: uuid.New()}
	for i := 1; i <= 60; i++ {
		if retry, ok := h.admitPush(context.Background(), busy); !ok {
			t.Fatalf("push %d of 60 was refused (retry in %v)", i, retry)
		}
	}
	retry, ok := h.admitPush(context.Background(), busy)
	if ok {
		t.Fatal("the 61st push inside the hour was admitted")
	}
	if retry <= 0 || retry > time.Hour {
		t.Fatalf("retry after a refused push = %v, want a wait inside the hour", retry)
	}
	if _, ok := h.admitPush(context.Background(), registry.Agent{ID: uuid.New(), RepoID: uuid.New()}); !ok {
		t.Fatal("a second repository inherited the first one's exhausted budget")
	}
}

// TestPushBudgetRefusalWords: the wait a pusher is told rounds to whole
// seconds and is never zero, and the sentence names the limit and the wait.
func TestPushBudgetRefusalWords(t *testing.T) {
	for _, tc := range []struct {
		wait time.Duration
		want int
	}{
		{0, 1}, {100 * time.Millisecond, 1}, {499 * time.Millisecond, 1}, {500 * time.Millisecond, 1},
		{1400 * time.Millisecond, 1}, {1500 * time.Millisecond, 2}, {2400 * time.Millisecond, 2},
		{90 * time.Second, 90}, {time.Hour, 3600},
	} {
		if got := retrySeconds(tc.wait); got != tc.want {
			t.Errorf("retrySeconds(%v) = %d, want %d", tc.wait, got, tc.want)
		}
	}
	const want = "This repository is over its hourly push limit. Retry in 90 seconds."
	if got := pushBudgetRefusal(90 * time.Second); got != want {
		t.Errorf("refusal = %q, want %q", got, want)
	}
}

// TestClientHostIsTheAddressPart: the key the per-address budget and the
// key-offer budget use is the host, whatever the connection's string form.
func TestClientHostIsTheAddressPart(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7:55000":  "203.0.113.7",
		"[2001:db8::1]:2222": "2001:db8::1",
		"203.0.113.7":        "203.0.113.7",
		"2001:db8::1":        "2001:db8::1",
		"":                   "",
	} {
		if got := clientHost(in); got != want {
			t.Errorf("clientHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// rpcRequest is a git-upload-pack POST for the handler's rpc, from the
// given peer, with an empty command section (a flush packet).
func rpcRequest(ctx context.Context, peer string, body io.Reader) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/ns/repo.git/git-upload-pack", body)
	r.RemoteAddr = peer
	return r
}

// TestRPCAnswersWhatItCannotServe drives the stateless service through the
// handler with no database: the refusals it makes before git runs (a body
// that is not gzip, an address at its budget, a repository at its cap) and
// the headers of an answer it does give.
func TestRPCAnswersWhatItCannotServe(t *testing.T) {
	repos := limitsStore(t)
	agent := registry.Agent{ID: uuid.New(), RepoID: uuid.New()}
	if err := repos.InitBare(context.Background(), agent.RepoID, "main"); err != nil {
		t.Fatal(err)
	}
	newHandler := func(perRepo, perClient int) *Handler {
		return &Handler{
			cfg: config.Config{}, repos: repos, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			sem: make(chan struct{}, 8), perRepo: newRepoSemaphores(perRepo), perClient: newClientSemaphores(perClient),
			opTimeout: time.Minute, postReceiveTimeout: time.Minute,
		}
	}
	serve := func(h *Handler, r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.rpc(w, r, agent, &auth.Principal{Anonymous: true}, auth.AgentRoleNone, refView{}, "upload-pack", nil)
		return w
	}
	flush := func() io.Reader { return strings.NewReader("0000") }

	t.Run("a body that is not gzip", func(t *testing.T) {
		r := rpcRequest(context.Background(), "203.0.113.7:4000", strings.NewReader("this is not gzip"))
		r.Header.Set("Content-Encoding", "gzip")
		w := serve(newHandler(4, 4), r)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bad gzip body") {
			t.Fatalf("bad gzip body: %d %q, want 400 naming the body", w.Code, w.Body.String())
		}
	})

	t.Run("a gzip body is decoded", func(t *testing.T) {
		var zipped bytes.Buffer
		zw := gzip.NewWriter(&zipped)
		_, _ = zw.Write([]byte("0000"))
		_ = zw.Close()
		r := rpcRequest(context.Background(), "203.0.113.7:4000", &zipped)
		r.Header.Set("Content-Encoding", "gzip")
		w := serve(newHandler(4, 4), r)
		if w.Code != http.StatusOK {
			t.Fatalf("gzip request: %d %q, want 200", w.Code, w.Body.String())
		}
	})

	t.Run("an answer carries the service's result type and is not cached", func(t *testing.T) {
		w := serve(newHandler(4, 4), rpcRequest(context.Background(), "203.0.113.7:4000", flush()))
		if w.Code != http.StatusOK {
			t.Fatalf("upload-pack: %d %q", w.Code, w.Body.String())
		}
		if got := w.Header().Get("Content-Type"); got != "application/x-git-upload-pack-result" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("Cache-Control = %q", got)
		}
	})

	t.Run("an address at its budget is told to come back", func(t *testing.T) {
		h := newHandler(4, 1)
		hold, ok := h.perClient.tryAcquire("203.0.113.7")
		if !ok {
			t.Fatal("could not hold the address's only slot")
		}
		defer hold()
		w := serve(h, rpcRequest(context.Background(), "203.0.113.7:4000", flush()))
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("address at its budget: %d, want 429", w.Code)
		}
		if got := w.Header().Get("Retry-After"); got != "1" {
			t.Errorf("Retry-After = %q, want 1", got)
		}
		if !strings.Contains(w.Body.String(), "too many concurrent git operations from this address; try again shortly") {
			t.Errorf("body = %q, want the budget sentence", w.Body.String())
		}
		// Another address is served beside it.
		if w := serve(h, rpcRequest(context.Background(), "198.51.100.9:4000", flush())); w.Code != http.StatusOK {
			t.Fatalf("another address beside one at its budget: %d", w.Code)
		}
	})

	t.Run("a repository at its cap is busy", func(t *testing.T) {
		h := newHandler(1, 4)
		hold, err := h.perRepo.acquire(context.Background(), agent.RepoID)
		if err != nil {
			t.Fatal(err)
		}
		defer hold()
		gone, cancel := context.WithCancel(context.Background())
		cancel()
		w := serve(h, rpcRequest(gone, "203.0.113.7:4000", flush()))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "git busy") {
			t.Fatalf("repository at its cap: %d %q, want 503 git busy", w.Code, w.Body.String())
		}
	})

	t.Run("a push with no runnable hook is not started", func(t *testing.T) {
		h := newHandler(4, 4)
		h.repos = &RepoStore{dataDir: repos.dataDir, gitBin: repos.gitBin, hookBin: repos.hookBin, hooksBase: t.TempDir() + "/missing/deeper"}
		r := rpcRequest(context.Background(), "203.0.113.7:4000", flush())
		w := httptest.NewRecorder()
		h.rpc(w, r, agent, &auth.Principal{Anonymous: true}, auth.AgentRoleNone, refView{}, "receive-pack", &bytes.Buffer{})
		if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "git error") {
			t.Fatalf("push with no hook: %d %q, want 500 git error", w.Code, w.Body.String())
		}
	})
}

// TestGitEnvCarriesThePushPolicy: the hook learns the pusher's rights and
// the repository's limits from the environment the handler builds, and
// nowhere else.
func TestGitEnvCarriesThePushPolicy(t *testing.T) {
	cfg := config.Config{}
	cfg.Limits.RepoMaxBlobBytes = 111
	cfg.Limits.RepoQuotaBytes = 222
	cfg.Limits.RepoWarnBytes = 333
	repos := &RepoStore{hookBin: "/opt/agentryd"}
	h := &Handler{cfg: cfg, repos: repos, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agent := registry.Agent{DefaultBranch: "trunk", AllowForcePush: true, Visibility: "private", NamespaceKind: "user"}

	value := func(env []string, key string) string {
		t.Helper()
		got := ""
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, key+"="); ok {
				got = v
			}
		}
		return got
	}
	publisher := &auth.Principal{Via: "pat", Scopes: []string{"repo:write", "agent:publish"}}
	env := h.gitEnvFor(context.Background(), "version=2", agent, publisher, auth.AgentRolePublish)
	for key, want := range map[string]string{
		"GIT_PROTOCOL":                "version=2",
		"AGENTRY_HOOK_BIN":            "/opt/agentryd",
		"AGENTRY_HOOK_DEFAULT_BRANCH": "trunk",
		"AGENTRY_HOOK_CAN_PUBLISH":    "true",
		"AGENTRY_HOOK_MAX_BLOB_BYTES": "111",
		"AGENTRY_HOOK_QUOTA_BYTES":    "222",
		"AGENTRY_HOOK_WARN_BYTES":     "333",
		"AGENTRY_HOOK_ALLOW_FORCE":    "true",
	} {
		if got := value(env, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	// A token without the publish scope cannot create a version tag even
	// for an owner; a role below publish cannot either.
	writeOnly := &auth.Principal{Via: "pat", Scopes: []string{"repo:write"}}
	if got := value(h.gitEnvFor(context.Background(), "", agent, writeOnly, auth.AgentRolePublish), "AGENTRY_HOOK_CAN_PUBLISH"); got != "false" {
		t.Errorf("CAN_PUBLISH for a token without agent:publish = %q, want false", got)
	}
	if got := value(h.gitEnvFor(context.Background(), "", agent, publisher, auth.AgentRoleWrite), "AGENTRY_HOOK_CAN_PUBLISH"); got != "false" {
		t.Errorf("CAN_PUBLISH for a writer = %q, want false", got)
	}
	agent.AllowForcePush = false
	if got := value(h.gitEnvFor(context.Background(), "", agent, publisher, auth.AgentRolePublish), "AGENTRY_HOOK_ALLOW_FORCE"); got != "false" {
		t.Errorf("ALLOW_FORCE with the setting off = %q, want false", got)
	}
	// The Git-Protocol header of an HTTP request is what reaches git.
	r := httptest.NewRequest(http.MethodPost, "/ns/repo.git/git-upload-pack", nil)
	r.Header.Set("Git-Protocol", "version=2")
	if got := value(h.gitEnv(r, agent, publisher, auth.AgentRolePublish), "GIT_PROTOCOL"); got != "version=2" {
		t.Errorf("GIT_PROTOCOL from the request header = %q", got)
	}
}

// TestMountServesOnlyTheThreeSmartHTTPRoutes: the git handler answers a GET
// of info/refs and a POST of each of the two services, no other method on
// them and no other service; and a request for an advertisement that names
// no smart service is refused before anything is looked up.
func TestMountServesOnlyTheThreeSmartHTTPRoutes(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handler{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h.Mount(mux)
	for _, tc := range []struct {
		method, path string
		pattern      string
	}{
		{"GET", "/ns/repo.git/info/refs", "GET /{ns}/{repo}/info/refs"},
		{"POST", "/ns/repo.git/git-upload-pack", "POST /{ns}/{repo}/git-upload-pack"},
		{"POST", "/ns/repo.git/git-receive-pack", "POST /{ns}/{repo}/git-receive-pack"},
	} {
		if _, got := mux.Handler(httptest.NewRequest(tc.method, tc.path, nil)); got != tc.pattern {
			t.Errorf("%s %s routes to %q, want %q", tc.method, tc.path, got, tc.pattern)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"POST", "/ns/repo.git/info/refs"}, {"PUT", "/ns/repo.git/info/refs"}, {"DELETE", "/ns/repo.git/info/refs"},
		{"GET", "/ns/repo.git/git-upload-pack"}, {"PUT", "/ns/repo.git/git-upload-pack"},
		{"GET", "/ns/repo.git/git-receive-pack"}, {"PATCH", "/ns/repo.git/git-receive-pack"},
		{"POST", "/ns/repo.git/git-upload-archive"}, {"GET", "/ns/repo.git/HEAD"}, {"GET", "/ns/repo.git/objects/info/packs"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
			t.Errorf("%s %s answered %d, want 405 or 404 from the mux", tc.method, tc.path, w.Code)
		}
	}
	// A path that does not name a repository ending in .git is not found,
	// before any lookup.
	for _, tc := range []struct{ method, path string }{
		{"GET", "/ns/repo/info/refs?service=git-upload-pack"},
		{"GET", "/ns/repo.gitx/info/refs?service=git-receive-pack"},
		{"POST", "/ns/repo/git-upload-pack"},
		{"POST", "/ns/repo.git.bak/git-receive-pack"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s answered %d, want 404", tc.method, tc.path, w.Code)
		}
	}
	for _, query := range []string{"", "?service=", "?service=git-upload-archive", "?service=upload-pack", "?service=git-upload-pack%20", "?service=GIT-UPLOAD-PACK"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ns/repo.git/info/refs"+query, nil))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "smart protocol only") {
			t.Errorf("info/refs%s: %d %q, want 403 'smart protocol only'", query, w.Code, w.Body.String())
		}
	}
}

// TestGitClientIsTheResolvedAddress: the address a git operation is budgeted
// to is the one the middleware resolved, and the peer when there is none.
func TestGitClientIsTheResolvedAddress(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:5000"
	if got := gitClient(r); got != "203.0.113.7" {
		t.Errorf("without a resolved address: %q, want the peer 203.0.113.7", got)
	}
	r = r.WithContext(auth.WithClientIP(r.Context(), "198.51.100.9"))
	if got := gitClient(r); got != "198.51.100.9" {
		t.Errorf("with a resolved address: %q, want 198.51.100.9", got)
	}
}

// slowStart is a reader that hands out nothing at first.
type slowStart struct{ chunks []string }

func (s *slowStart) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		return 0, io.EOF
	}
	c := s.chunks[0]
	s.chunks = s.chunks[1:]
	return copy(p, c), nil
}

// TestFirstByteTimerRecordsTheFirstByteOnce: the clone first-byte SLI is the
// time to the first byte of pack data, once per operation.
func TestFirstByteTimerRecordsTheFirstByteOnce(t *testing.T) {
	var recorded []time.Duration
	f := &firstByteTimer{r: &slowStart{chunks: []string{"", "abc", "def"}}, start: time.Now().Add(-time.Minute), record: func(d time.Duration) { recorded = append(recorded, d) }}
	buf := make([]byte, 16)
	if n, err := f.Read(buf); n != 0 || err != nil || len(recorded) != 0 {
		t.Fatalf("an empty read: %d, %v, recorded %v; nothing arrived yet", n, err, recorded)
	}
	for range 2 {
		if n, err := f.Read(buf); n != 3 || err != nil {
			t.Fatalf("read = %d, %v", n, err)
		}
	}
	if len(recorded) != 1 || recorded[0] < time.Minute {
		t.Fatalf("recorded %v, want one duration measured from the start of the request", recorded)
	}
}

// TestAcceptedRefsAreWhatTheRepositoryNowHolds: receive-pack exits 0 on a
// push its hook refused, so the commands a client sent are checked against
// the repository: a create or update counts when the ref is at the new
// object, a delete when the ref is gone, and on any doubt nothing counts.
func TestAcceptedRefsAreWhatTheRepositoryNowHolds(t *testing.T) {
	r := newReleaseRepo(t, nil)
	h := &Handler{repos: r.s, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agent := registry.Agent{RepoID: r.id}
	c1 := r.commit
	c2 := plumbIn(t, r.dir, "second\n", "commit-tree", r.tree, "-p", c1)
	plumbIn(t, r.dir, "", "update-ref", "refs/heads/created", c1)
	plumbIn(t, r.dir, "", "update-ref", "refs/heads/updated", c2)
	plumbIn(t, r.dir, "", "update-ref", "refs/heads/unmoved", c1)
	plumbIn(t, r.dir, "", "update-ref", "refs/heads/still-there", c1)
	want := []RefUpdate{
		{Old: zeroOID, New: c1, Ref: "refs/heads/created"},
		{Old: zeroOID, New: c1, Ref: "refs/heads/never-created"},
		{Old: c1, New: c2, Ref: "refs/heads/updated"},
		{Old: c1, New: c2, Ref: "refs/heads/unmoved"},
		{Old: c1, New: zeroOID, Ref: "refs/heads/deleted"},
		{Old: c1, New: zeroOID, Ref: "refs/heads/still-there"},
	}
	got := h.acceptedRefs(context.Background(), agent, want)
	var names []string
	for _, ru := range got {
		names = append(names, ru.Ref)
	}
	if !slices.Equal(names, []string{"refs/heads/created", "refs/heads/updated", "refs/heads/deleted"}) {
		t.Fatalf("accepted %v, want the create that exists, the update that landed and the delete that happened", names)
	}
	if got[0] != want[0] || got[1] != want[2] || got[2] != want[4] {
		t.Fatalf("accepted updates are not the requested ones: %+v", got)
	}
	if got := h.acceptedRefs(context.Background(), agent, nil); len(got) != 0 {
		t.Fatalf("no commands accepted %v", got)
	}
	// A repository that cannot be read leaves nothing to believe.
	if got := h.acceptedRefs(context.Background(), registry.Agent{RepoID: uuid.New()}, want); len(got) != 0 {
		t.Fatalf("with the refs unreadable, accepted %v", got)
	}
}

// fakeChannel is the server's end of an SSH session channel.
type fakeChannel struct {
	in  io.Reader
	out bytes.Buffer
	err bytes.Buffer
}

func (c *fakeChannel) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *fakeChannel) Write(p []byte) (int, error) { return c.out.Write(p) }
func (*fakeChannel) Close() error                  { return nil }
func (*fakeChannel) CloseWrite() error             { return nil }
func (*fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return true, nil
}
func (c *fakeChannel) Stderr() io.ReadWriter { return &c.err }

// TestExecGitAnswersWhatItCannotServe: the SSH transport runs the service
// under the same budgets as HTTP and tells the client why it did not, with
// git's own exit status when git itself failed.
func TestExecGitAnswersWhatItCannotServe(t *testing.T) {
	repos := limitsStore(t)
	agent := registry.Agent{ID: uuid.New(), RepoID: uuid.New()}
	if err := repos.InitBare(context.Background(), agent.RepoID, "main"); err != nil {
		t.Fatal(err)
	}
	newServer := func(perRepo, perClient int) *SSHServer {
		return &SSHServer{h: &Handler{
			repos: repos, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			sem: make(chan struct{}, 8), perRepo: newRepoSemaphores(perRepo), perClient: newClientSemaphores(perClient),
			opTimeout: time.Minute, postReceiveTimeout: time.Minute,
		}}
	}
	run := func(s *SSHServer, ctx context.Context, client, service, stdin string, agent registry.Agent) (int, *fakeChannel) {
		ch := &fakeChannel{in: strings.NewReader(stdin)}
		code := s.execGit(ctx, ch, client, service, "", agent, &auth.Principal{Anonymous: true}, auth.AgentRoleNone, refView{})
		return code, ch
	}

	t.Run("an address at its budget", func(t *testing.T) {
		s := newServer(4, 1)
		hold, ok := s.h.perClient.tryAcquire("203.0.113.7")
		if !ok {
			t.Fatal("could not hold the address's only slot")
		}
		defer hold()
		code, ch := run(s, context.Background(), "203.0.113.7", "upload-pack", "", agent)
		if code != 1 || ch.err.String() != "agentry: too many concurrent git operations from this address; try again shortly\n" {
			t.Fatalf("address at its budget: exit %d, stderr %q", code, ch.err.String())
		}
	})

	t.Run("a repository at its cap", func(t *testing.T) {
		s := newServer(1, 4)
		hold, err := s.h.perRepo.acquire(context.Background(), agent.RepoID)
		if err != nil {
			t.Fatal(err)
		}
		defer hold()
		gone, cancel := context.WithCancel(context.Background())
		cancel()
		code, ch := run(s, gone, "203.0.113.7", "upload-pack", "", agent)
		if code != 1 || ch.err.String() != "agentry: repository busy, try again\n" {
			t.Fatalf("repository at its cap: exit %d, stderr %q", code, ch.err.String())
		}
	})

	t.Run("git's own failure keeps its exit status", func(t *testing.T) {
		s := newServer(4, 4)
		code, ch := run(s, context.Background(), "203.0.113.7", "upload-pack", "", registry.Agent{ID: uuid.New(), RepoID: uuid.New()})
		if code != 128 || !strings.Contains(ch.err.String(), "does not appear to be a git repository") {
			t.Fatalf("upload-pack of a repository that is not there: exit %d, stderr %q, want git's 128", code, ch.err.String())
		}
		if s.h.perClient.tracked() != 0 || s.h.perRepo.tracked() != 0 || len(s.h.sem) != 0 {
			t.Fatalf("slots left held after git failed")
		}
	})

	t.Run("a push with no runnable hook is not started", func(t *testing.T) {
		s := newServer(4, 4)
		s.h.repos = &RepoStore{dataDir: repos.dataDir, gitBin: repos.gitBin, hookBin: repos.hookBin, hooksBase: t.TempDir() + "/missing/deeper"}
		code, ch := run(s, context.Background(), "203.0.113.7", "receive-pack", "", agent)
		if code != 1 || ch.err.String() != "agentry: the server cannot check pushes right now, try again later\n" {
			t.Fatalf("push with no hook: exit %d, stderr %q", code, ch.err.String())
		}
	})

	t.Run("a clone is served", func(t *testing.T) {
		s := newServer(4, 4)
		// The client's flush packet says it wants nothing: git ends cleanly.
		code, ch := run(s, context.Background(), "203.0.113.7", "upload-pack", "0000", agent)
		if code != 0 || ch.out.Len() == 0 {
			t.Fatalf("upload-pack of an empty repository: exit %d, %d bytes of advertisement, stderr %q", code, ch.out.Len(), ch.err.String())
		}
	})
}

// TestSafeRefName: a client-supplied ref name is a plain, fully qualified
// ref of at most 512 bytes with none of the characters git reads as a
// pattern, a range or a revision.
func TestSafeRefName(t *testing.T) {
	long := func(n int) string {
		name := "refs/heads/"
		for len(name) < n {
			name += strings.Repeat("a", min(100, n-len(name)))
			if len(name) < n {
				name += "/"
			}
		}
		return name
	}
	for _, ref := range []string{"refs/heads/main", "refs/tags/v1.0.0", "refs/heads/a/b-c_d.e", "refs/x", long(512)} {
		if !safeRefName(ref) {
			t.Errorf("safeRefName(%q) = false", ref)
		}
	}
	if len(long(512)) != 512 || len(long(513)) != 513 {
		t.Fatalf("test names are %d and %d bytes", len(long(512)), len(long(513)))
	}
	for _, ref := range []string{
		"", "main", "heads/main", "-d", "--all", "/refs/heads/main", long(513),
		"refs/heads/a*", "refs/heads/a?", "refs/heads/a[b", "refs/heads/a]b", `refs/heads/a\b`, "refs/heads/a^b",
		"refs/heads/a:b", "refs/heads/a~1", "refs/heads/a b", "refs/heads/a\tb", "refs/heads/a\nb",
	} {
		if safeRefName(ref) {
			t.Errorf("safeRefName(%q) = true", ref)
		}
	}
}

// TestGitFailuresAreNotAbsences: when git cannot run at all, the answer is an
// error, not "the commit or file is not there".
func TestGitFailuresAreNotAbsences(t *testing.T) {
	r := newReleaseRepo(t, nil)
	broken := *r.s
	broken.gitBin = filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(broken.gitBin, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, err := broken.HasCommit(ctx, r.id, r.commit); ok || err == nil || !strings.Contains(err.Error(), "cat-file") {
		t.Errorf("HasCommit with no git: %v, %v, want an error naming cat-file", ok, err)
	}
	if _, err := broken.ReadFileAt(ctx, r.id, r.commit, "README.md"); err == nil || errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "cat-file") {
		t.Errorf("ReadFileAt with no git: %v, want an error naming cat-file that is not fs.ErrNotExist", err)
	}
	// With git, a commit or path that is not there is an absence.
	if ok, err := r.s.HasCommit(ctx, r.id, strings.Repeat("e", 40)); ok || err != nil {
		t.Errorf("HasCommit of a commit that is not there: %v, %v", ok, err)
	}
	if _, err := r.s.ReadFileAt(ctx, r.id, r.commit, "nope.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFileAt of a path that is not there: %v, want fs.ErrNotExist", err)
	}
	// A failing git command says what git said.
	if _, err := r.s.git(ctx, r.dir, nil, nil, "rev-parse", "--verify", "no-such-revision"); err == nil || !strings.Contains(err.Error(), "gitsrv: git rev-parse:") || !strings.Contains(err.Error(), "fatal:") {
		t.Errorf("git failure: %v, want 'gitsrv: git rev-parse:' with git's own words", err)
	}
}

// TestHermeticEnvIsolatesGit: git run for the store sees none of the
// caller's GIT_ variables and no system or global configuration, never asks
// for a credential, and takes the caller's additions last.
func TestHermeticEnvIsolatesGit(t *testing.T) {
	t.Setenv("GIT_DIR", "/elsewhere")
	t.Setenv("GIT_WORK_TREE", "/elsewhere")
	t.Setenv("GIT_CONFIG_GLOBAL", "/somewhere/gitconfig")
	t.Setenv("KEEP_ME", "yes")
	env := hermeticEnv([]string{"GIT_INDEX_FILE=/idx"})
	has := func(kv string) bool { return slices.Contains(env, kv) }
	for _, kv := range []string{"KEEP_ME=yes", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_INDEX_FILE=/idx"} {
		if !has(kv) {
			t.Errorf("environment lacks %s", kv)
		}
	}
	for _, kv := range env {
		if kv == "GIT_DIR=/elsewhere" || kv == "GIT_WORK_TREE=/elsewhere" || kv == "GIT_CONFIG_GLOBAL=/somewhere/gitconfig" {
			t.Errorf("environment kept %s", kv)
		}
	}
	if env[len(env)-1] != "GIT_INDEX_FILE=/idx" {
		t.Errorf("the caller's additions are not last: %q", env[len(env)-1])
	}
}
