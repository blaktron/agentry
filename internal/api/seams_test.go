package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/registry"
)

// The core seams of plan subscription-tiers §5 (agentry#319): the
// admission hook before a submission is stored, user.registered for
// directory accounts, Features and the private-agent cap, the pipeline-
// error flag on scan.completed, the rate-class opt-out. Each test builds
// the core with a probe extension standing in for the billing one, and
// the first pins that with no extension nothing changes.

// recordingAdmitter refuses when refuse is set, fails when broken, and
// otherwise hands out tickets; it remembers what it was asked and voided.
type recordingAdmitter struct {
	mu      sync.Mutex
	refuse  *registry.Refusal
	broken  bool
	asked   []registry.Admission
	tickets int
	voided  []string
}

func (a *recordingAdmitter) Admit(_ context.Context, req registry.Admission) (registry.Ticket, *registry.Refusal, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, req)
	if a.broken {
		return registry.Ticket{}, nil, errors.New("ledger unreachable")
	}
	if a.refuse != nil {
		return registry.Ticket{}, a.refuse, nil
	}
	a.tickets++
	return registry.Ticket{ID: "t-" + uuid.NewString()}, nil, nil
}

func (a *recordingAdmitter) Void(_ context.Context, t registry.Ticket) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.voided = append(a.voided, t.ID)
	return nil
}

func submitFixture(env *testEnv, author, name string) (string, map[string]string) {
	env.t.Helper()
	authorSess := env.login(author)
	_, _ = env.st.Pool().Exec(context.Background(),
		`UPDATE users SET created_at = now() - interval '30 days' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, author)
	env.doJSON(authorSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": name, "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(authorSess, "pub", "agent:publish", "agent:read", "repo:read")
	return pat, map[string]string{
		"agent.yaml": skillYAML(author, name, "1.0.0"),
		"README.md":  "# " + name + "\n",
		"SKILL.md":   "Summarise the incident politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
}

func countVersions(env *testEnv, author, name string) int {
	env.t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agent_versions v JOIN agents a ON a.id = v.agent_id
		 JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`, author, name).Scan(&n); err != nil {
		env.t.Fatal(err)
	}
	return n
}

// TestAdmissionRunsBeforeTheRow: a refusing admitter leaves no version row
// and no scan, and the API answers with the refusal's own status, slug and
// fields; an admitter that cannot answer is a 503 and nothing is stored; an
// admitting one sees its ticket on version.submitted; and the same
// submission with no admitter at all is unchanged — the gate never hears
// of any of this.
func TestAdmissionRunsBeforeTheRow(t *testing.T) {
	adm := &recordingAdmitter{}
	var mu sync.Mutex
	var submitted []map[string]any
	env := newTestEnvWith(t, func(s *api.Server) {
		s.Reg().SetAdmitter(adm)
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "version.submitted" {
				mu.Lock()
				submitted = append(submitted, ev.Payload)
				mu.Unlock()
			}
		})
	})
	author := env.register("adm-auth")
	env.verifyEmail(author)
	pat, files := submitFixture(env, author, "gated")

	// Refused: the refusal's status and slug, its fields at top level.
	adm.refuse = &registry.Refusal{
		Status: http.StatusPaymentRequired, Slug: "credits-exhausted", Title: "Not enough credits for this submission",
		Detail: "a submission costs 10 credits; the balance is 4 and resets on 2026-10-01",
		Fields: map[string]any{"balance": 4, "resetsAt": "2026-10-01T00:00:00Z"},
	}
	status, body := env.uploadVersionCLI(author, "gated", pat, files)
	if status != http.StatusPaymentRequired {
		t.Fatalf("refused submission: got %d %s", status, body)
	}
	var prob map[string]any
	if err := json.Unmarshal([]byte(body), &prob); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(prob["type"].(string), "/credits-exhausted") || prob["balance"] != float64(4) || prob["resetsAt"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("refusal body lacks the slug or the fields: %s", body)
	}
	if n := countVersions(env, author, "gated"); n != 0 {
		t.Fatalf("a refused submission stored %d version row(s)", n)
	}
	if len(adm.asked) != 1 || adm.asked[0].Kind != registry.AdmissionKindVersionSubmit || adm.asked[0].Source != "cli-upload" {
		t.Fatalf("admission asked: %+v", adm.asked)
	}

	// Unknown: fail closed, nothing stored.
	adm.refuse, adm.broken = nil, true
	status, body = env.uploadVersionCLI(author, "gated", pat, files)
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "admission-unavailable") {
		t.Fatalf("broken admitter: got %d %s", status, body)
	}
	if n := countVersions(env, author, "gated"); n != 0 {
		t.Fatalf("an unanswerable admission stored %d version row(s)", n)
	}

	// Admitted: the ticket rides on version.submitted, and nothing was voided.
	adm.broken = false
	status, body = env.uploadVersionCLI(author, "gated", pat, files)
	if status != http.StatusAccepted {
		t.Fatalf("admitted submission: got %d %s", status, body)
	}
	env.waitStatus(author, "gated", "1.0.0", "published")
	mu.Lock()
	defer mu.Unlock()
	if len(submitted) != 1 || submitted[0]["admissionTicket"] == nil || submitted[0]["versionId"] == nil {
		t.Fatalf("version.submitted must carry the admission ticket and the version id: %+v", submitted)
	}
	if len(adm.voided) != 0 {
		t.Fatalf("nothing failed after admission, yet tickets were voided: %v", adm.voided)
	}

	// A validation failure before admission never asks: the manifest is
	// checked first, so a broken package costs nothing.
	adm.refuse = &registry.Refusal{Status: http.StatusPaymentRequired, Slug: "credits-exhausted"}
	asked := len(adm.asked)
	bad := map[string]string{"agent.yaml": "schemaVersion: \"2\"\nname: gated\n", "SKILL.md": "x\n"}
	if status, _ := env.uploadVersionCLI(author, "gated", pat, bad); status != http.StatusUnprocessableEntity {
		t.Fatalf("broken manifest: got %d", status)
	}
	if len(adm.asked) != asked {
		t.Fatal("a submission that failed validation was put to the admitter")
	}
}

// TestAdmissionVoidedWhenTheRowNeverLands: a failure between admission and
// the row hands the ticket back, so a charge never outlives a submission
// that did not happen. The failure here is the server-built digest not
// matching the claimed one, which the core checks after admission.
func TestAdmissionVoidedWhenTheRowNeverLands(t *testing.T) {
	adm := &recordingAdmitter{}
	env := newTestEnvWith(t, func(s *api.Server) { s.Reg().SetAdmitter(adm) })
	author := env.register("void-auth")
	env.verifyEmail(author)
	pat, files := submitFixture(env, author, "voided")

	status, body := env.uploadVersionCLIWithDigest(author, "voided", pat, files, "sha256:"+strings.Repeat("0", 64))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched digest: got %d %s", status, body)
	}
	adm.mu.Lock()
	defer adm.mu.Unlock()
	if adm.tickets != 1 || len(adm.voided) != 1 {
		t.Fatalf("ticket issued %d, voided %v; want one of each", adm.tickets, adm.voided)
	}
}

// TestCoreWithoutAdmitterIsUnchanged pins the other half of the seam: with
// nothing registered a submission is exactly what it was.
func TestCoreWithoutAdmitterIsUnchanged(t *testing.T) {
	env := newTestEnv(t)
	author := env.register("plain-auth")
	env.verifyEmail(author)
	pat, files := submitFixture(env, author, "plain")
	if status, body := env.uploadVersionCLI(author, "plain", pat, files); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	env.waitStatus(author, "plain", "1.0.0", "published")
}

// TestUserRegisteredFiresForDirectoryAccounts: the JIT-created account of
// a first OIDC sign-in fires the same event the native register handler
// does, with how it arrived; a second sign-in of the same person does not.
func TestUserRegisteredFiresForDirectoryAccounts(t *testing.T) {
	idp := newFakeOIDC(t)
	var mu sync.Mutex
	var seen []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Google = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.srv.Client())
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				mu.Lock()
				seen = append(seen, ev)
				mu.Unlock()
			}
		})
	})
	userID := loginThroughFakeOIDC(t, env, idp)
	mu.Lock()
	n := len(seen)
	var ev api.Event
	if n > 0 {
		ev = seen[0]
	}
	mu.Unlock()
	if n != 1 || ev.UserID.String() != userID || ev.Payload["via"] != "social" || ev.Payload["provider"] != "google" || ev.Payload["handle"] == "" {
		t.Fatalf("user.registered for a JIT account: %d event(s) %+v", n, ev)
	}
	loginThroughFakeOIDC(t, env, idp)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("a repeat sign-in fired user.registered again: %d", len(seen))
	}
}

// cappedResolver is the core resolver with one private agent per personal
// namespace, as a tier's resolver would answer.
type cappedResolver struct {
	entitlements.Resolver
	max int64
}

func (c cappedResolver) Features(_ context.Context, s entitlements.Subject) (entitlements.Features, error) {
	if s.Kind == entitlements.NamespaceOrg {
		return entitlements.Features{PrivateAgents: entitlements.Allowance{Enabled: true}}, nil
	}
	return entitlements.Features{PrivateAgents: entitlements.Allowance{Enabled: true, Max: c.max}}, nil
}

// TestPrivateAgentCapNeverDeletes: at the cap, one more private agent is a
// 422 private-agent-cap on create and on a public→private flip; a public
// agent is still fine; and nothing already private is touched — with no
// extension the core caps nothing.
func TestPrivateAgentCapNeverDeletes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetEntitlements(cappedResolver{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: 1})
	})
	user := env.register("cap-user")
	env.verifyEmail(user)
	sess := env.login(user)
	create := func(name, visibility string, want int) string {
		t.Helper()
		res := env.do(sess, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": user, "name": name, "modes": []string{"autonomous"}, "visibility": visibility})
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("create %s %s: got %d want %d: %s", name, visibility, res.StatusCode, want, body)
		}
		return string(body)
	}
	create("one", "private", http.StatusCreated)
	body := create("two", "private", http.StatusUnprocessableEntity)
	if !strings.Contains(body, "private-agent-cap") {
		t.Fatalf("the cap must answer with its own slug: %s", body)
	}
	create("pub", "public", http.StatusCreated)
	res := env.do(sess, http.MethodPatch, "/api/v1/agents/"+user+"/pub", map[string]any{"visibility": "private"})
	body2, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body2), "private-agent-cap") {
		t.Fatalf("flip to private at the cap: got %d %s", res.StatusCode, body2)
	}
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.visibility = 'private'`, user).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the cap changed what is private: %d", n)
	}

	plain := newTestEnv(t)
	u2 := plain.register("uncapped")
	plain.verifyEmail(u2)
	s2 := plain.login(u2)
	for _, name := range []string{"a", "b", "c"} {
		plain.doJSON(s2, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": u2, "name": name, "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	}
}

// TestExtensionRouteRateClassOptOut: an extension's unthrottled route is
// never refused by the anonymous class while its sibling still is; the
// route still passes the principal middleware.
func TestExtensionRouteRateClassOptOut(t *testing.T) {
	var srv *api.Server
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Limits.AnonymousPerMin = 3
	}, func(s *api.Server) {
		srv = s
		s.RegisterExtension("hook", func(mux *http.ServeMux) {
			ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
			mux.HandleFunc("POST /webhooks/pay", ok)
			mux.HandleFunc("POST /other", ok)
		})
		s.SetExtensionUnthrottled("hook", []string{"POST /webhooks/pay"})
	})
	// The declaration is part of what the route tables enumerate.
	if list := srv.ExtensionUnthrottled(); len(list) != 1 || !list["POST /api/v1/x/hook/webhooks/pay"] {
		t.Fatalf("unthrottled routes enumerated as %v", list)
	}
	hit := func(path string) int {
		res := env.do(anonymous, http.MethodPost, "/api/v1/x/hook"+path, nil)
		_ = res.Body.Close()
		return res.StatusCode
	}
	for i := 0; i < 20; i++ {
		if got := hit("/webhooks/pay"); got != http.StatusNoContent {
			t.Fatalf("unthrottled route refused on call %d: %d", i+1, got)
		}
	}
	var throttled bool
	for i := 0; i < 20; i++ {
		if hit("/other") == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("the sibling route was never throttled; the opt-out is not narrow")
	}
	if got := hit("/webhooks/pay"); got != http.StatusNoContent {
		t.Fatalf("unthrottled route refused after the sibling was throttled: %d", got)
	}
}

// TestScanCompletedNamesTheVersionAndOutcome: scan.completed carries the
// version id and the gate's outcome so an extension can tie it to the
// admission ticket's version. The pipeline-error flag lives on the
// transition event (TestPipelineErrorFlagsTheTransition in internal/scan).
func TestScanCompletedNamesTheVersionAndOutcome(t *testing.T) {
	var mu sync.Mutex
	var completed []map[string]any
	env := newTestEnvWith(t, func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "scan.completed" {
				mu.Lock()
				completed = append(completed, ev.Payload)
				mu.Unlock()
			}
		})
	})
	author := env.register("s0-auth")
	env.verifyEmail(author)
	pat, files := submitFixture(env, author, "clean")
	if status, body := env.uploadVersionCLI(author, "clean", pat, files); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	env.waitStatus(author, "clean", "1.0.0", "published")
	mu.Lock()
	defer mu.Unlock()
	if len(completed) != 1 || completed[0]["outcome"] != "published" || completed[0]["versionId"] == nil {
		t.Fatalf("scan.completed must name the outcome and the version: %+v", completed)
	}
}

// TestBoundExtensionWritesItsOwnAuditAction: the deps an extension is
// handed (agentry#324) let it write an audit event under an action of its
// own name, and the person's activity feed shows it like any other; an
// action outside the extension's name is refused.
func TestBoundExtensionWritesItsOwnAuditAction(t *testing.T) {
	audit.Register("probe.tier_set")
	var write func(context.Context, audit.Event) error
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(*http.ServeMux) {})
		_, _, write, _ = s.ExtensionDeps()
	})
	u := env.register("bound-user")
	env.verifyEmail(u)
	sess := env.login(u)
	var me struct {
		Id uuid.UUID `json:"id"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)

	if err := write(context.Background(), audit.Event{
		Actor: me.Id, ActorKind: audit.ActorUser, Action: "probe.tier_set",
		TargetKind: "user", TargetID: me.Id, Detail: map[string]any{"tier": "pro"},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := write(context.Background(), audit.Event{
		Actor: me.Id, ActorKind: audit.ActorUser, Action: "probe.unregistered", TargetKind: "user", TargetID: me.Id,
	}); err == nil {
		t.Fatal("an unregistered action was written")
	}

	var page struct {
		Events []struct {
			Action string         `json:"action"`
			Detail map[string]any `json:"detail"`
		} `json:"events"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/activity", nil, &page, http.StatusOK)
	var seen bool
	for _, e := range page.Events {
		if e.Action == "probe.tier_set" && e.Detail["tier"] == "pro" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("the extension's event is not on the activity feed: %+v", page.Events)
	}
}
