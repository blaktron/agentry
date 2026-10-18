package extension

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/voice"
	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// A minimal extension compiles against the interface using only the
// aliases this package exports: what a module outside the core can do.
type noop struct{}

func (noop) Name() string { return "noop" }
func (noop) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}
func (noop) Migrations() fs.FS      { return nil }
func (noop) Entitlements() Resolver { return nil }
func (noop) Hooks() Hooks           { return Hooks{Event: func(context.Context, Event) {}} }
func (noop) Jobs() []Job            { return nil }

var _ Extension = noop{}

// billingLike is the shape a billing extension takes: the optional
// seams, satisfied with the aliases alone. It must compile; the
// behaviour is the API's tests.
type billingLike struct{ noop }

func (billingLike) Admitter() Admitter {
	return admitAll{}
}
func (billingLike) UnthrottledRoutes() []string { return []string{"POST /webhooks/pay"} }

type admitAll struct{}

func (admitAll) Admit(context.Context, Admission) (Ticket, *Refusal, error) {
	return Ticket{ID: "t"}, nil, nil
}
func (admitAll) Void(context.Context, Ticket) error { return nil }

func (b *bound) Bind(d Deps) { b.deps = d }

type bound struct {
	billingLike
	deps Deps
}

func (bound) Name() string { return "bound" }

// tiered is the shape an extension's resolver takes: the core's, with
// Features answered by the extension. It must compile against the
// aliases alone.
type tiered struct {
	Resolver
}

func (tiered) Features(context.Context, Subject) (Features, error) {
	return Features{PrivateAgents: Cap{Enabled: true, Max: 10}}, nil
}

var _ Resolver = tiered{}

var (
	_ Extension   = billingLike{}
	_ Admits      = billingLike{}
	_ Unthrottles = billingLike{}
	_ Binds       = (*bound)(nil)
)

// TestRegisterAuditActionKeepsTheExtensionPrefix: an extension may add its
// own actions to the audit catalog, only under its own name, and never one
// the catalog already holds.
func TestRegisterAuditActionKeepsTheExtensionPrefix(t *testing.T) {
	registerAuditAction("billing", "billing.tier_set")
	for _, bad := range []AuditAction{"tier_set", "agent.update", "billing.", "billingx.tier_set", "billing.tier_set"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("action %q was accepted", bad)
				}
			}()
			registerAuditAction("billing", bad)
		}()
	}
	// An extension named for a core prefix cannot take a core action over.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("agent.update was registered by an extension named agent")
			}
		}()
		registerAuditAction("agent", "agent.update")
	}()
}

// binder keeps the deps it is bound with and registers nothing else.
type binder struct {
	noop
	deps Deps
}

func (b *binder) Bind(d Deps) { b.deps = d }

// TestBindHandsTheBaseURL: a bound extension gets the address the
// core's own links use, whether the deployment names it in the config
// file (as a chart does) or in AGENTRY_BASE_URL (as a compose file
// does), the variable winning over the file, and nothing when neither
// names one.
func TestBindHandsTheBaseURL(t *testing.T) {
	cases := []struct {
		name, file, env, want string
	}{
		{"the config file", "https://file.example/", "", "https://file.example"},
		{"the environment", "", "https://env.example", "https://env.example"},
		{"the environment over the file", "https://file.example", "https://env.example/", "https://env.example"},
		{"neither", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agentry.yaml")
			body := "devMode: true\n"
			if c.file != "" {
				body += "baseURL: " + c.file + "\n"
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			// Set but empty would clear the file's address, so an unset
			// case is unset (t.Setenv first, to restore it afterwards).
			t.Setenv("AGENTRY_BASE_URL", c.env)
			if c.env == "" {
				if err := os.Unsetenv("AGENTRY_BASE_URL"); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			ext := &binder{}
			applyExtensions(api.New(cfg, nil, slog.New(slog.DiscardHandler)), []Extension{ext})
			if ext.deps.BaseURL != c.want || ext.deps.BaseURL != strings.TrimRight(cfg.BaseURL, "/") {
				t.Fatalf("Deps.BaseURL = %q, want %q (config %q)", ext.deps.BaseURL, c.want, cfg.BaseURL)
			}
		})
	}
}

func (bound) AuditActions() []AuditAction { return []AuditAction{"bound.tier_set"} }

// TestApplyExtensionsBindsAndRegistersActions: applyExtensions hands a
// Binds extension its deps (a nil pool without a database, a logger, an
// audit writer) and puts its audit actions in the catalog under its name,
// before anything else of it is wired.
func TestApplyExtensionsBindsAndRegistersActions(t *testing.T) {
	ext := &bound{}
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, nil, slog.New(slog.DiscardHandler))
	applyExtensions(srv, []Extension{ext})
	if ext.deps.Log == nil || ext.deps.Audit == nil || ext.deps.Entitlements == nil {
		t.Fatalf("Bind did not deliver the deps: %+v", ext.deps)
	}
	if f, err := ext.deps.Entitlements.Features(context.Background(), Subject{Kind: NamespaceUser}); err != nil || f.PrivateAgents.Max != 0 {
		t.Fatalf("the core resolver must be the configured, uncapped one: %+v %v", f, err)
	}
	if ext.deps.DB != nil {
		t.Fatal("a server without a database handed out a pool")
	}
	if ext.deps.Blobs != nil {
		t.Fatal("a server without a database handed out an object store")
	}
	if ext.deps.Notifier != nil {
		t.Fatal("a server without a database handed out a notifier: the rule about who may be written to reads the user's row")
	}
	if ext.deps.Webhooks != nil {
		t.Fatal("a server without a database handed out a webhook transport: an endpoint is a row and a delivery is another")
	}
	if ext.deps.Knowledge != nil {
		t.Fatal("a server without a database handed out the knowledge store")
	}
	if ext.deps.Meter == nil {
		t.Fatal("a server without a database handed out a nil meter: it must be a no-op one")
	}
	if _, err := ext.deps.Meter.Int64Counter("BoundThings"); err != nil {
		t.Fatalf("the no-op meter refused an instrument: %v", err)
	}
	if !audit.Registered("bound.tier_set") {
		t.Fatal("the extension's audit action is not in the catalog")
	}
	if err := ext.deps.Audit.Write(context.Background(), AuditEvent{Action: "bound.tier_set", ActorKind: ActorSystem}); err == nil {
		t.Fatal("an audit write with no database must fail, not vanish")
	}
}

// TestPeriodicTickerEnqueuesNowAndOnThePeriod pins the shape of Job.Every:
// one enqueue at start-up, then one per period, until the context ends.
func TestPeriodicTickerEnqueuesNowAndOnThePeriod(t *testing.T) {
	q := &countingQueue{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		periodicTicker(ctx, q, "probe.cycle", "", 20*time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for q.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if n := q.count(); n < 3 {
		t.Fatalf("enqueued %d times in 2s at a 20ms period", n)
	}
	if k, qn := q.last(); k != "probe.cycle" || qn != "core" {
		t.Fatalf("enqueued %s on %s; want probe.cycle on core", k, qn)
	}
}

type countingQueue struct {
	mu    sync.Mutex
	n     int
	kind  string
	queue string
}

func (c *countingQueue) Enqueue(_ context.Context, kind, queueName string, _ any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.kind, c.queue = kind, queueName
	return uuid.New(), nil
}
func (c *countingQueue) Register(string, queue.Handler)                      {}
func (c *countingQueue) Work(context.Context, ...string) error               { return nil }
func (c *countingQueue) CountWaiting(context.Context, string) (int64, error) { return 0, nil }
func (c *countingQueue) count() int                                          { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
func (c *countingQueue) last() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kind, c.queue
}

func TestNoopSatisfiesTheInterface(t *testing.T) {
	var e Extension = noop{}
	if e.Name() != "noop" || e.Migrations() != nil || e.Entitlements() != nil || e.Hooks().Event == nil {
		t.Fatal("unexpected zero behaviour")
	}
}

// TestParseQueues pins the worker's --queues contract: a subset of the
// queues that exist, in the order given, duplicates folded; an unknown
// name ("judge" included, which has no queue) is refused rather than
// drained as nothing; empty means both.
func TestParseQueues(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		err  string
	}{
		{"", nil, ""},
		{"core", []string{"core"}, ""},
		{"sandbox", []string{"sandbox"}, ""},
		{"sandbox, core, sandbox", []string{"sandbox", "core"}, ""},
		{"judge", nil, `"judge" is not a queue`},
		{"core,scan", nil, `"scan" is not a queue`},
		{" , ", nil, "names no queue"},
	}
	for _, c := range cases {
		got, err := parseQueues(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("%q: err %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("%q: got %v want %v", c.in, got, c.want)
		}
	}
}

// ScopeAllows is how an extension route requires a hosted-run scope
// through the seam alone: nobody anonymous; a session, which has the
// account's full authority; a PAT only with the scope.
func TestScopeAllows(t *testing.T) {
	if ScopeAllows(nil, ScopeRunWrite) || ScopeAllows(&Principal{Anonymous: true}, ScopeRunWrite) {
		t.Fatal("an anonymous caller passed")
	}
	if !ScopeAllows(&Principal{Via: "session"}, ScopeRunWrite) {
		t.Fatal("a session was refused; it carries the account's full authority")
	}
	pat := &Principal{Via: "pat", Scopes: []string{"run:read", "agent:read"}}
	if !ScopeAllows(pat, ScopeRunRead) {
		t.Fatal("a PAT carrying run:read was refused")
	}
	if ScopeAllows(pat, ScopeRunWrite) {
		t.Fatal("a PAT without run:write passed; the list is flat")
	}
	if ScopeAllows(pat, ScopeKnowledgeWrite) || !ScopeAllows(&Principal{Via: "pat", Scopes: []string{"knowledge:write"}}, ScopeKnowledgeWrite) {
		t.Fatal("knowledge:write is not read as the core reads it")
	}
	if ScopeAllows(pat, ScopeSecretWrite) || !ScopeAllows(&Principal{Via: "pat", Scopes: []string{"secret:write"}}, ScopeSecretWrite) {
		t.Fatal("secret:write is not read as the core reads it")
	}
	if ScopeAllows(&Principal{Via: "user"}, ScopeRunRead) {
		t.Fatal("a principal from Principals.ForUser passed; it is no caller")
	}
	// A schedule's credential is read as a token minted with
	// auth.ScheduleScopes: it starts and reads a run and attaches
	// knowledge, and writes nothing else, never as a session.
	sched := &Principal{Via: "schedule", ScheduleID: uuid.New(), Scopes: auth.ScheduleScopes()}
	for _, s := range []Scope{ScopeRunRead, ScopeRunWrite, ScopeKnowledgeRead} {
		if !ScopeAllows(sched, s) {
			t.Errorf("a schedule's credential was refused %s", s)
		}
	}
	for _, s := range []Scope{ScopeKnowledgeWrite, ScopeSecretWrite, auth.ScopeVoiceWrite, auth.ScopeOrgAdmin} {
		if ScopeAllows(sched, s) {
			t.Errorf("a schedule's credential passed %s; it carries only its own scopes", s)
		}
	}
	if ScopeAllows(&Principal{Via: "schedule"}, ScopeRunWrite) {
		t.Fatal("a schedule principal with no scopes passed, as if it were a session")
	}
}

// wrapperLike is the shape a knowledge wrapper takes: the WrapsKeys
// seam, satisfied with the aliases alone.
type wrapperLike struct{ noop }

func (wrapperLike) KeyWrapper() KeyWrapper { return certWrapper{} }

type certWrapper struct{}

func (certWrapper) Wrap(_ context.Context, o KeyOwner, _ []byte) (WrappedKey, error) {
	return WrappedKey{Kind: "certificate", Recipient: string(o.Kind)}, nil
}
func (certWrapper) Unwrap(context.Context, KeyOwner, WrappedKey) ([]byte, error) {
	return nil, ErrKeyNotOwner
}
func (certWrapper) Destroy(context.Context, KeyOwner) error { return nil }

var _ WrapsKeys = wrapperLike{}

// TestApplyExtensionsSetsTheKeyWrapper: a WrapsKeys extension's wrapper is
// the knowledge store's, in place of the deployment key's.
func TestApplyExtensionsSetsTheKeyWrapper(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	if _, ok := srv.Knowledge().Wrapper().(*knowledge.DeploymentWrapper); !ok {
		t.Fatalf("with no extension the wrapper is %T, want the deployment key's", srv.Knowledge().Wrapper())
	}
	applyExtensions(srv, []Extension{wrapperLike{}})
	if _, ok := srv.Knowledge().Wrapper().(certWrapper); !ok {
		t.Fatalf("after applyExtensions the wrapper is %T, want the extension's", srv.Knowledge().Wrapper())
	}
}

// jobAdmitter is the shape a runs extension takes for the model-input
// routes: the AdmitsModelInput seam, with the aliases alone.
type jobAdmitter struct{ noop }

func (jobAdmitter) ModelInputCallers() ModelInputCallers { return jobCallers{} }

type jobCallers struct{}

func (jobCallers) AdmitModelInput(_ context.Context, cred string, call ModelInputCall) (string, *Refusal, error) {
	if call.Op == ModelInputOpSearch && call.Count > 10 {
		return "", &Refusal{Status: http.StatusTooManyRequests, Slug: "draft-searches-used"}, nil
	}
	return strings.TrimPrefix(cred, "agyj_"), nil, nil
}
func (jobCallers) RecordModelInput(context.Context, string, ModelInputUse) {}

var _ AdmitsModelInput = jobAdmitter{}

// TestApplyExtensionsSetsTheModelInputCallers: an AdmitsModelInput
// extension is what admits hosted jobs to the model-input routes; with none,
// nothing does.
func TestApplyExtensionsSetsTheModelInputCallers(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, nil, slog.New(slog.DiscardHandler))
	if srv.ModelInputCallers() != nil {
		t.Fatal("a core server admits no job credentials")
	}
	applyExtensions(srv, []Extension{jobAdmitter{}})
	if _, ok := srv.ModelInputCallers().(jobCallers); !ok {
		t.Fatalf("after applyExtensions the callers are %T, want the extension's", srv.ModelInputCallers())
	}
}

// poolingResolver is the shape a resolver that pools knowledge takes:
// the PoolsKnowledge seam, with the aliases alone.
type poolingResolver struct{ tiered }

func (poolingResolver) KnowledgePool(_ context.Context, o KeyOwner) (KnowledgePool, error) {
	return KnowledgePool{Key: "org/pool", Owners: []KeyOwner{o}, Cap: Cap{Enabled: true, Max: 10 << 30}}, nil
}

var _ PoolsKnowledge = poolingResolver{}

// builder is the shape a hosted build takes over the knowledge store:
// it reads Deps.Knowledge and speaks only the seam's aliases.
type builder struct {
	noop
	store Knowledge
}

func (b *builder) Bind(d Deps) { b.store = d.Knowledge }

// TestBindHandsTheKnowledgeStore: a bound extension gets the core's
// knowledge store and can make a pack, put a tree in it — which is then
// scanning, with the registry's counts — and is refused its tree while it
// is scanned, all in the seam's own words.
func TestBindHandsTheKnowledgeStore(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	b := &builder{}
	applyExtensions(srv, []Extension{b})
	if b.store == nil {
		t.Fatal("a server with a database handed out no knowledge store")
	}
	ctx := context.Background()
	owner := KeyOwner{Kind: KeyOwnerUser, ID: uuid.New()}
	p, err := b.store.Create(ctx, owner, "seam-"+owner.ID.String()[:8])
	if err != nil || p.State != KnowledgeEmpty {
		t.Fatalf("create: %+v %v", p, err)
	}
	files := []KnowledgeFile{
		{Path: "sources/a.md", Content: []byte("# A\n")},
		{Path: "wiki/index.md", Content: []byte("# Index\n")},
		{Path: "wiki/topics/a.md", Content: []byte("---\ntitle: A\n---\nA. [src: doc:a.md]\n")},
	}
	got, changed, err := b.store.Replace(ctx, owner, p.ID, "", files)
	if err != nil || !changed || got.State != KnowledgeScanning || got.Pages != 1 || got.Files != 3 {
		t.Fatalf("replace: %+v %v %v", got, changed, err)
	}
	if again, changed, err := b.store.Replace(ctx, owner, p.ID, "", files); err != nil || changed || again.Digest != got.Digest {
		t.Fatalf("the same tree again is unchanged, whatever its from: %+v %v %v", again, changed, err)
	}
	other := append([]KnowledgeFile{{Path: "sources/b.md", Content: []byte("# B\n")}}, files...)
	if _, _, err := b.store.Replace(ctx, owner, p.ID, "", other); !errors.Is(err, ErrKnowledgeChanged) {
		t.Fatalf("a stale replace: %v", err)
	}
	if _, _, err := b.store.Tree(ctx, owner, p.ID); !errors.Is(err, ErrKnowledgeScanning) {
		t.Fatalf("the tree of a scanning pack: %v", err)
	}
	if _, err := b.store.Pack(ctx, KeyOwner{Kind: KeyOwnerUser, ID: uuid.New()}, p.ID); !errors.Is(err, ErrKnowledgeNotFound) {
		t.Fatalf("another owner's read: %v", err)
	}
	u, err := b.store.Usage(ctx, owner)
	if err != nil || u.Used != got.Bytes {
		t.Fatalf("usage: %+v %v", u, err)
	}
}

// vaultLike is the shape a vault extension takes: it deletes an
// account's rows in the core's erasure transaction, through the aliases
// alone.
type vaultLike struct{ noop }

func (vaultLike) Name() string { return "vault" }
func (vaultLike) EraseAccount(_ context.Context, _ ErasureTx, _ uuid.UUID, kind AccountErasureKind) (int64, error) {
	if kind != AccountErased && kind != AccountDataCleared {
		return 0, errors.New("unknown clear")
	}
	return 0, nil
}

var _ ErasesAccounts = vaultLike{}

// TestApplyExtensionsRegistersTheAccountEraser: an ErasesAccounts extension
// is called from the erasure and the data clear; with none, nothing is.
func TestApplyExtensionsRegistersTheAccountEraser(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, nil, slog.New(slog.DiscardHandler))
	applyExtensions(srv, []Extension{noop{}})
	if got := srv.AccountErasers(); len(got) != 0 {
		t.Fatalf("erasers with no ErasesAccounts extension: %v", got)
	}
	applyExtensions(srv, []Extension{vaultLike{}})
	if got := srv.AccountErasers(); len(got) != 1 || got[0] != "vault" {
		t.Fatalf("erasers = %v, want [vault]", got)
	}
}

// voiceWriter is the shape a hosted Voice Writer takes: it is handed
// the core's voice store, and admits the reviews the routes ask for.
type voiceWriter struct {
	noop
	store Voice
}

func (v *voiceWriter) Bind(d Deps)                  { v.store = d.Voice }
func (v *voiceWriter) VoiceAdmitter() VoiceAdmitter { return nil }

// stubVoiceJudge passes every voice.
type stubVoiceJudge struct{}

func (stubVoiceJudge) Scan(context.Context, string) judge.VoiceResult {
	sc := map[string]int{}
	for _, q := range judge.VoiceQuestions() {
		sc[q.ID] = 0
	}
	return judge.VoiceResult{Verdict: judge.VerdictPass, Model: judge.DefaultModel, QuestionSet: "sha256:stub", Scores: sc}
}
func (stubVoiceJudge) QuestionSet() string { return "sha256:stub" }

// TestBindHandsTheVoiceStore: a bound extension gets the core's voice
// store, proposes a Voice Writer run's output only as a build or an AI
// Edit, and reads a live voice only once it passed its review.
func TestBindHandsTheVoiceStore(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	srv.SetVoiceJudge(stubVoiceJudge{})
	v := &voiceWriter{}
	applyExtensions(srv, []Extension{v})
	if v.store == nil {
		t.Fatal("a server with a database handed out no voice store")
	}
	ctx := context.Background()
	user := uuid.New()
	if err := st.Queries().CreateHandle(ctx, storegen.CreateHandleParams{ID: user, Handle: "vw-" + user.String()[:8], Kind: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Queries().CreateUser(ctx, storegen.CreateUserParams{ID: user, Email: user.String() + "@example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.store.Live(ctx, user); !errors.Is(err, ErrVoiceNotFound) {
		t.Fatalf("no voice yet: %v", err)
	}
	if _, err := v.store.Propose(ctx, user, []byte("# Voice\n"), voice.SourceEdit); err == nil {
		t.Fatal("a Voice Writer run proposed an edit")
	}
	var invalid *VoiceInvalidError
	if _, err := v.store.Propose(ctx, user, []byte(" "), VoiceSourceBuild); !errors.As(err, &invalid) {
		t.Fatalf("an empty voice: %v", err)
	}
	s, err := v.store.Propose(ctx, user, []byte("# Voice\n\nShort sentences.\n"), VoiceSourceBuild)
	if err != nil || s.Pending == nil || s.Pending.Source != VoiceSourceBuild || s.Live != nil {
		t.Fatalf("propose: %+v %v", s, err)
	}
	// Pending is never what a run attaches.
	if _, err := v.store.Live(ctx, user); !errors.Is(err, ErrVoiceNotFound) {
		t.Fatalf("a pending voice read as live: %v", err)
	}
	w := queue.NewRiverClient(st, nil)
	w.SetTestOnly(true)
	srv.Voice().RegisterHandlers(w)
	w.Drain(ctx, "sandbox")
	live, err := v.store.Live(ctx, user)
	if err != nil || string(live.Text) != "# Voice\n\nShort sentences.\n" || live.ReviewState != "passed" {
		t.Fatalf("live: %+v %v", live, err)
	}
	if _, err := v.store.State(ctx, uuid.New()); !errors.Is(err, ErrVoiceNotFound) {
		t.Fatalf("another person's voice: %v", err)
	}
}

// metered records one counter on the meter it is bound with.
type metered struct {
	noop
	err error
}

func (*metered) Name() string { return "metered" }
func (m *metered) Bind(d Deps) {
	c, err := d.Meter.Int64Counter("MeteredThings", metric.WithDescription("things the stub counted"))
	if err != nil {
		m.err = err
		return
	}
	c.Add(context.Background(), 3, metric.WithAttributes(attribute.String("kind", "run")))
}

// TestBindHandsTheServersMeter: an extension bound to a server with a
// database and metrics records a counter on its meter, and the server's
// own /metrics serves it with the core's resource labels.
func TestBindHandsTheServersMeter(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	mx, err := metrics.New(t.Context(), metrics.Config{ServiceName: "agentryd", Role: "api", Env: "dev"})
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	t.Cleanup(func() { _ = mx.Shutdown(context.Background()) })
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	srv.SetMetrics(mx)
	ext := &metered{}
	applyExtensions(srv, []Extension{ext})
	if ext.err != nil {
		t.Fatalf("the bound meter refused a counter: %v", ext.err)
	}

	rec := httptest.NewRecorder()
	api.NewHandler(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics answered %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# TYPE MeteredThings counter") {
		t.Fatalf("the extension's counter is not on /metrics:\n%s", body)
	}
	if !strings.Contains(body, `MeteredThings{agentry_role="api",deployment_environment="dev",kind="run",service_name="agentryd"} 3`) {
		t.Fatalf("the extension's series is not the one it recorded, with the resource labels:\n%s", body)
	}
}

// designReader is the shape a hosted run takes for the report design:
// it is handed the core's report settings.
type designReader struct {
	noop
	settings ReportSettings
}

func (r *designReader) Bind(d Deps) { r.settings = d.ReportSettings }

// TestBindHandsTheReportSettings: a bound extension reads a person's
// report design as its canonical document, nil while they never chose
// one and again once they clear it, and another person's design is
// never theirs (no row is not Plain). Theme, the transitional read,
// answers the design's basedOn.
func TestBindHandsTheReportSettings(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	r := &designReader{}
	applyExtensions(srv, []Extension{r})
	if r.settings == nil {
		t.Fatal("a server with a database handed out no report settings")
	}
	ctx := context.Background()
	mk := func(prefix string) uuid.UUID {
		id := uuid.New()
		if err := st.Queries().CreateHandle(ctx, storegen.CreateHandleParams{ID: id, Handle: prefix + id.String()[:8], Kind: "user"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Queries().CreateUser(ctx, storegen.CreateUserParams{ID: id, Email: id.String() + "@example.test"}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	user, other := mk("rt-"), mk("ro-")
	if got, err := r.settings.Design(ctx, user); err != nil || got != nil {
		t.Fatalf("never chosen: %q, %v", got, err)
	}
	if got, err := r.settings.Theme(ctx, user); err != nil || got != "" {
		t.Fatalf("never chosen: %q, %v", got, err)
	}
	classic, _ := reportdesign.Builtin("classic")
	technical, _ := reportdesign.Builtin("technical")
	technical.Name, technical.Accent = "Acme", "#0b5c55"
	if _, err := st.Queries().UpsertUserReportSettings(ctx, storegen.UpsertUserReportSettingsParams{UserID: other, Design: classic.Canonical()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Queries().UpsertUserReportSettings(ctx, storegen.UpsertUserReportSettingsParams{UserID: user, Design: technical.Canonical()}); err != nil {
		t.Fatal(err)
	}
	if got, err := r.settings.Design(ctx, user); err != nil || !bytes.Equal(got, technical.Canonical()) {
		t.Fatalf("chosen: %s, %v", got, err)
	}
	if got, err := r.settings.Theme(ctx, user); err != nil || got != "technical" {
		t.Fatalf("chosen: %q, %v", got, err)
	}
	if got, err := r.settings.DesignWithLogo(ctx, user); err != nil || !bytes.Equal(got, technical.Canonical()) {
		t.Fatalf("chosen, no logo: %s, %v", got, err)
	}
	// A logo comes only with DesignWithLogo: Design stays what a reader
	// without logos can parse.
	var pb bytes.Buffer
	if err := png.Encode(&pb, image.NewNRGBA(image.Rect(0, 0, 8, 4))); err != nil {
		t.Fatal(err)
	}
	logo, err := reportdesign.NormalizeLogo(pb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := logo.Decode()
	if _, err := st.Queries().SetUserReportLogo(ctx, storegen.SetUserReportLogoParams{UserID: user, Logo: raw}); err != nil {
		t.Fatal(err)
	}
	if got, err := r.settings.Design(ctx, user); err != nil || !bytes.Equal(got, technical.Canonical()) {
		t.Fatalf("Design with a logo stored: %s, %v", got, err)
	}
	withLogo := technical
	withLogo.Logo = logo
	if got, err := r.settings.DesignWithLogo(ctx, user); err != nil || !bytes.Equal(got, withLogo.Canonical()) {
		t.Fatalf("DesignWithLogo: %.200s, %v", got, err)
	}
	if _, err := st.Queries().DeleteUserReportSettings(ctx, user); err != nil {
		t.Fatal(err)
	}
	if got, err := r.settings.Design(ctx, user); err != nil || got != nil {
		t.Fatalf("cleared: %q, %v", got, err)
	}
	if got, _ := r.settings.Design(ctx, other); !bytes.Equal(got, classic.Canonical()) {
		t.Fatalf("the other person's design moved: %s", got)
	}
}

// membersReader keeps the membership door it was bound with.
type membersReader struct {
	noop
	members Members
}

func (m *membersReader) Name() string   { return "members-reader" }
func (m *membersReader) Bind(deps Deps) { m.members = deps.Members }

// TestBindHandsTheMembersDoor: a server with a database hands an extension
// the core's membership door, and its refusals are the ones this package
// names. What provisioning and deprovisioning do is the API's tests'.
func TestBindHandsTheMembersDoor(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	m := &membersReader{}
	applyExtensions(srv, []Extension{m})
	if m.members == nil {
		t.Fatal("a server with a database handed out no membership door")
	}
	ctx := context.Background()
	if _, err := m.members.Provision(ctx, uuid.New(), ProvisionedMember{Email: "someone@example.test"}); !errors.Is(err, ErrOrgNotProvisionable) {
		t.Fatalf("provisioning into an unknown organization: %v, want ErrOrgNotProvisionable", err)
	}
	if kept, err := m.members.Deprovision(ctx, uuid.New(), uuid.New()); err != nil || kept {
		t.Fatalf("deprovisioning nobody: kept %v, %v; want a quiet no-op", kept, err)
	}
}
