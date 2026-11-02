package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/registry"
)

// The core seams: the admission hook before a submission is stored, user.registered for
// directory accounts, Features and the private-agent cap, the pipeline-
// error flag on scan.completed, the rate-class opt-out. Each test builds
// the core with a probe extension standing in for the billing one, and
// the first pins that with no extension nothing changes.

// recordingAdmitter refuses when refuse is set, fails when broken, and
// otherwise hands out tickets; it remembers what it was asked and voided.
type recordingAdmitter struct {
	mu     sync.Mutex
	refuse *registry.Refusal
	broken bool
	// blank hands out tickets with no id.
	blank   bool
	asked   []registry.Admission
	tickets int
	issued  []string
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
	if a.blank {
		return registry.Ticket{}, nil, nil
	}
	id := "t-" + uuid.NewString()
	a.issued = append(a.issued, id)
	return registry.Ticket{ID: id}, nil, nil
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
	if prob["title"] != "Not enough credits for this submission" || prob["status"] != float64(http.StatusPaymentRequired) ||
		prob["detail"] != "A submission costs 10 credits; the balance is 4 and resets on 2026-10-01." {
		t.Fatalf("refusal body lacks the refusal's own title, status or detail: %s", body)
	}
	if n := countVersions(env, author, "gated"); n != 0 {
		t.Fatalf("a refused submission stored %d version row(s)", n)
	}
	if len(adm.asked) != 1 || adm.asked[0].Kind != registry.AdmissionKindVersionSubmit || adm.asked[0].Source != "cli-upload" {
		t.Fatalf("admission asked: %+v", adm.asked)
	}
	// It is asked about who submits what to whom: the person, the agent and
	// the namespace it sits in, and the agent's visibility.
	var authorID, agentID uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.id, a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'gated'`, author).Scan(&authorID, &agentID); err != nil {
		t.Fatal(err)
	}
	if got := adm.asked[0]; got.Submitter != authorID || got.AgentID != agentID || got.Subject != entitlements.ForUser(authorID) || got.Visibility != "public" {
		t.Fatalf("admission asked about %+v, want submitter %s, agent %s, subject %v, public", got, authorID, agentID, entitlements.ForUser(authorID))
	}

	// A refusal that says nothing of its own is a 403 admission-refused.
	adm.refuse = &registry.Refusal{}
	status, body = env.uploadVersionCLI(author, "gated", pat, files)
	if status != http.StatusForbidden || problemTypeOf([]byte(body)) != "admission-refused" || !strings.Contains(body, `"title":"Submission refused"`) {
		t.Fatalf("a refusal with no words of its own: got %d %s, want 403 admission-refused titled Submission refused", status, body)
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
	var versionID string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.id::text FROM agent_versions v JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		  WHERE h.handle = $1 AND a.name = 'gated' AND v.version = '1.0.0'`, author).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	if len(adm.issued) != 1 || submitted[0]["admissionTicket"] != adm.issued[0] || submitted[0]["versionId"] != versionID {
		t.Fatalf("version.submitted carries ticket %v and version %v, want the issued ticket %v and the stored version %s",
			submitted[0]["admissionTicket"], submitted[0]["versionId"], adm.issued, versionID)
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
	if !strings.Contains(body, "packed this archive differently from the registry") ||
		!strings.Contains(body, "update the client to a release that matches this registry") {
		t.Fatalf("the refusal does not say the client packed differently and must update: %s", body)
	}
	adm.mu.Lock()
	if adm.tickets != 1 || len(adm.voided) != 1 || adm.voided[0] != adm.issued[0] {
		t.Fatalf("ticket issued %d (%v), voided %v; want the issued ticket voided", adm.tickets, adm.issued, adm.voided)
	}
	// An admitter that issued no ticket id has nothing to void.
	adm.blank = true
	adm.mu.Unlock()
	status, body = env.uploadVersionCLIWithDigest(author, "voided", pat, files, "sha256:"+strings.Repeat("1", 64))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched digest with no ticket id: got %d %s", status, body)
	}
	adm.mu.Lock()
	defer adm.mu.Unlock()
	if adm.tickets != 2 || len(adm.voided) != 1 {
		t.Fatalf("after a submission admitted with no ticket id: issued %d, voided %v; want nothing more voided", adm.tickets, adm.voided)
	}
}

// TestCoreWithoutAdmitterIsUnchanged pins the other half of the seam: with
// nothing registered a submission is exactly what it was.
func TestCoreWithoutAdmitterIsUnchanged(t *testing.T) {
	var mu sync.Mutex
	var submitted []map[string]any
	env := newTestEnvWith(t, func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "version.submitted" {
				mu.Lock()
				submitted = append(submitted, ev.Payload)
				mu.Unlock()
			}
		})
	})
	author := env.register("plain-auth")
	env.verifyEmail(author)
	pat, files := submitFixture(env, author, "plain")
	if status, body := env.uploadVersionCLI(author, "plain", pat, files); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	env.waitStatus(author, "plain", "1.0.0", "published")
	// Nothing of the seam shows on the event.
	mu.Lock()
	defer mu.Unlock()
	if len(submitted) != 1 {
		t.Fatalf("version.submitted events: %d, want 1", len(submitted))
	}
	for _, k := range []string{"admissionTicket", "versionId"} {
		if _, ok := submitted[0][k]; ok {
			t.Errorf("version.submitted carries %q with no admitter: %+v", k, submitted[0])
		}
	}
}

// TestUserRegisteredFiresForDirectoryAccounts: the JIT-created account of
// a first OIDC sign-in fires the same event the native register handler
// does, with how it arrived; a second sign-in of the same person does not.
func TestUserRegisteredFiresForDirectoryAccounts(t *testing.T) {
	idp := newFakeOIDC(t)
	var mu sync.Mutex
	var seen []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Auth.OIDC = config.OIDCProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.srv.URL}
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
	if n != 1 || ev.UserID.String() != userID || ev.Payload["via"] != "social" || ev.Payload["provider"] != "oidc" || ev.Payload["handle"] == "" {
		t.Fatalf("user.registered for a JIT account: %d event(s) %+v", n, ev)
	}
	var handle string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT handle FROM handles WHERE id = $1::uuid`, userID).Scan(&handle); err != nil {
		t.Fatal(err)
	}
	if ev.Payload["handle"] != handle || ev.Payload["email"] != idp.email || ev.Payload["emailVerified"] != true || ev.OrgID != uuid.Nil {
		t.Fatalf("user.registered payload %+v (org %s), want the account's handle %s, the provider's verified address %s and no organization", ev.Payload, ev.OrgID, handle, idp.email)
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
		return entitlements.Features{PrivateAgents: entitlements.Cap{Enabled: true}}, nil
	}
	return entitlements.Features{PrivateAgents: entitlements.Cap{Enabled: true, Max: c.max}}, nil
}

// noPrivateAgents is the core resolver for a person whose plan has no
// private agents.
type noPrivateAgents struct{ entitlements.Resolver }

func (r noPrivateAgents) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	f, err := r.Resolver.Features(ctx, s)
	f.PrivateAgents = entitlements.Cap{}
	return f, err
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
	// An agent already private is not one more: asking again for what it
	// already is passes at the cap.
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+user+"/one", map[string]any{"visibility": "private"}, nil, http.StatusOK)

	// A plan with no private agents at all refuses the first, and still lets
	// public ones be made.
	env.setEntitlements(noPrivateAgents{entitlements.NewConfigResolver(config.Default().Limits)})
	body = create("zero", "private", http.StatusUnprocessableEntity)
	if !strings.Contains(body, "private-agent-cap") {
		t.Fatalf("a plan without private agents must answer with the cap's slug: %s", body)
	}
	create("open", "public", http.StatusCreated)

	plain := newTestEnv(t)
	u2 := plain.register("uncapped")
	plain.verifyEmail(u2)
	s2 := plain.login(u2)
	for _, name := range []string{"a", "b", "c"} {
		plain.doJSON(s2, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": u2, "name": name, "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	}
}

// TestPrivateAgentCapHoldsUnderConcurrentCreates: the cap is counted
// inside the creating transaction under the namespace's row lock, so N
// concurrent creates at the cap admit exactly one — and N concurrent flips
// to private likewise. A
// count taken on the pool before the transaction would let every request
// see the same number.
func TestPrivateAgentCapHoldsUnderConcurrentCreates(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetEntitlements(cappedResolver{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: 1})
	})
	user := env.register("cap-race")
	env.verifyEmail(user)
	sess := env.login(user)
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := env.do(sess, http.MethodPost, "/api/v1/agents",
				map[string]any{"namespace": user, "name": fmt.Sprintf("race-%d", i), "modes": []string{"autonomous"}, "visibility": "private"})
			_ = res.Body.Close()
			codes[i] = res.StatusCode
		}(i)
	}
	wg.Wait()
	created, refused := 0, 0
	survivor := ""
	for i, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
			survivor = fmt.Sprintf("race-%d", i)
		case http.StatusUnprocessableEntity:
			refused++
		default:
			t.Fatalf("unexpected status %d in %v", c, codes)
		}
	}
	if created != 1 || refused != n-1 {
		t.Fatalf("concurrent private creates at a cap of 1: created %d refused %d (%v)", created, refused, codes)
	}
	var have int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.visibility = 'private'`, user).Scan(&have); err != nil || have != 1 {
		t.Fatalf("private agents after the race = %d (%v), want 1", have, err)
	}

	// The flip: several public agents, all turned private at once.
	for i := 0; i < 4; i++ {
		env.doJSON(sess, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": user, "name": fmt.Sprintf("pub-%d", i), "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	}
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+user+"/"+survivor, map[string]any{"visibility": "public"}, nil, http.StatusOK) // free the one slot
	flips := make([]int, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := env.do(sess, http.MethodPatch, "/api/v1/agents/"+user+fmt.Sprintf("/pub-%d", i), map[string]any{"visibility": "private"})
			_ = res.Body.Close()
			flips[i] = res.StatusCode
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range flips {
		if c == http.StatusOK {
			ok++
		}
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.visibility = 'private'`, user).Scan(&have); err != nil || have != 1 || ok != 1 {
		t.Fatalf("concurrent flips at a cap of 1: %d succeeded, %d private after (%v, %v)", ok, have, flips, err)
	}
}

// TestExtensionRouteRateClassOptOut: an extension's unthrottled route is
// never refused by the anonymous class while its sibling still is; the
// route still passes the principal middleware.
func TestExtensionRouteRateClassOptOut(t *testing.T) {
	var srv *api.Server
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Limits.AnonymousPerMin = 3
		// Three requests to spend and next to no refill, for the signed-in class.
		cfg.Limits.AuthedBurstPerMin = 3
		cfg.Limits.AuthedPerHour = 1
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
	// The opt-out is from the anonymous class alone: a signed-in caller's
	// own budget still applies on the route.
	u := env.register("optout")
	sess := env.login(u)
	var served int
	for i := 0; i < 20; i++ {
		res := env.do(sess, http.MethodPost, "/api/v1/x/hook/webhooks/pay", nil)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			break
		}
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("signed-in call %d: %d", i+1, res.StatusCode)
		}
		served++
	}
	if served != 3 {
		t.Fatalf("a signed-in caller was served %d calls on the unthrottled route before its own budget refused it, want its 3", served)
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
	var versionID string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.id::text FROM agent_versions v JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		  WHERE h.handle = $1 AND a.name = 'clean' AND v.version = '1.0.0'`, author).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	if completed[0]["versionId"] != versionID || completed[0]["version"] != "1.0.0" {
		t.Fatalf("scan.completed names version %v (%v), want 1.0.0 (%s)", completed[0]["version"], completed[0]["versionId"], versionID)
	}
	if run, _ := completed[0]["runId"].(string); uuid.Validate(run) != nil {
		t.Fatalf("scan.completed names run %v, want the scan run's id", completed[0]["runId"])
	}
	if reason, _ := completed[0]["reason"].(string); reason == "" {
		t.Fatalf("scan.completed gives no reason for its outcome: %+v", completed[0])
	}
}

// TestBoundExtensionWritesItsOwnAuditAction: the deps an extension is
// handed let it write an audit event under an action of its
// own name, and the person's activity feed shows it like any other; an
// action outside the extension's name is refused.
func TestBoundExtensionWritesItsOwnAuditAction(t *testing.T) {
	audit.Register("probe.tier_set")
	var write func(context.Context, audit.Event) error
	var writeIn func(context.Context, pgx.Tx, audit.Event) error
	var pool *pgxpool.Pool
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(*http.ServeMux) {})
		pool, _, write, writeIn = s.ExtensionDeps()
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

	// Written inside the extension's own transaction, the event commits with
	// it and goes with a rollback.
	ctx := context.Background()
	event := func(tier string) audit.Event {
		return audit.Event{Actor: me.Id, ActorKind: audit.ActorUser, Action: "probe.tier_set", TargetKind: "user", TargetID: me.Id, Detail: map[string]any{"tier": tier}}
	}
	for tier, commit := range map[string]bool{"committed": true, "rolled back": false} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeIn(ctx, tx, event(tier)); err != nil {
			t.Fatalf("write in a transaction: %v", err)
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for tier, want := range map[string]int{"committed": 1, "rolled back": 0} {
		var n int
		if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'probe.tier_set' AND target_id = $1 AND detail->>'tier' = $2`, me.Id, tier).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("audit rows with tier %q: %d, want %d", tier, n, want)
		}
	}
	if err := writeIn(ctx, nil, audit.Event{Actor: me.Id, ActorKind: audit.ActorUser, Action: "probe.unregistered", TargetKind: "user", TargetID: me.Id}); err == nil {
		t.Error("an unregistered action was written in a transaction")
	}
}

// TestRunScopesReachAnExtensionRoute: a PAT minted with the
// hosted-run scopes carries them on the resolved principal, so an
// extension route can require one — a token without it is refused, one
// with it passes, a session passes — while no core route is unlocked by
// them: a token carrying only the two is refused where the matrix refuses
// a token without the right scope.
func TestRunScopesReachAnExtensionRoute(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("POST /runs", func(w http.ResponseWriter, r *http.Request) {
				p := api.PrincipalFrom(r.Context())
				if p == nil || p.Anonymous || (p.Via == "pat" && !auth.HasScope(p.Scopes, auth.ScopeRunWrite)) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
		})
	})
	u := env.register("runner")
	env.verifyEmail(u)
	sess := env.login(u)
	_, runTok := env.mintPAT(sess, "run-only", "run:read", "run:write")
	_, otherTok := env.mintPAT(sess, "no-run", "repo:read", "agent:read")
	hit := func(c caller) int {
		res := env.do(c, http.MethodPost, "/api/v1/x/probe/runs", nil)
		_ = res.Body.Close()
		return res.StatusCode
	}
	if got := hit(caller{name: "run-pat", pat: runTok}); got != http.StatusNoContent {
		t.Fatalf("a PAT with run:write was refused by the extension route: %d", got)
	}
	if got := hit(caller{name: "other-pat", pat: otherTok}); got != http.StatusForbidden {
		t.Fatalf("a PAT without run:write passed the extension route: %d", got)
	}
	if got := hit(sess); got != http.StatusNoContent {
		t.Fatalf("a session was refused by the extension route: %d", got)
	}
	if got := hit(anonymous); got != http.StatusForbidden {
		t.Fatalf("an anonymous caller passed the extension route: %d", got)
	}
	// The token lists its scopes as minted.
	var tokens []struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/tokens", nil, &tokens, http.StatusOK)
	seen := false
	for _, tk := range tokens {
		if tk.Name == "run-only" {
			seen = strings.Join(tk.Scopes, " ") == "run:read run:write"
		}
	}
	if !seen {
		t.Fatalf("the minted token does not list run:read run:write: %+v", tokens)
	}
	// Inert in the core: the run-only token is refused where a token
	// without the right scope is refused.
	for _, path := range []string{"/api/v1/user", "/api/v1/user/tokens"} {
		res := env.do(caller{name: "run-pat", pat: runTok}, http.MethodGet, path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("a token carrying only the run scopes reached %s: %d", path, res.StatusCode)
		}
	}
}

// TestCreditsSessionScopeReachesItsExtensionRouteAlone: a PAT minted with
// credits:session alone reaches a handler only on the routes an extension
// declared as its credits-session routes, where the handler still requires
// the scope. Everywhere else the core refuses it before any handler runs:
// the same extension's other routes, even one that takes any caller,
// another extension's, the core's own routes and the anonymous reads. The
// scope is a token of its own: it is minted with no other.
func TestCreditsSessionScopeReachesItsExtensionRouteAlone(t *testing.T) {
	requires := func(sc auth.Scope) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p := api.PrincipalFrom(r.Context())
			if p == nil || p.Anonymous || (p.ScopeBound() && !auth.HasScope(p.Scopes, sc)) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	anyone := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("POST /sessions", requires(auth.ScopeCreditsSession))
			mux.HandleFunc("POST /sessions/{id}/renew", requires(auth.ScopeCreditsSession))
			mux.HandleFunc("GET /sessions/{id}", anyone)
			mux.HandleFunc("POST /runs", requires(auth.ScopeRunWrite))
			mux.HandleFunc("GET /status", anyone)
		})
		s.SetExtensionCreditsSessions("probe", []string{"POST /sessions", "POST /sessions/{id}/renew"})
		s.RegisterExtension("other", func(mux *http.ServeMux) {
			mux.HandleFunc("POST /sessions", requires(auth.ScopeCreditsSession))
		})
	})
	u := env.register("payer")
	env.verifyEmail(u)
	sess := env.login(u)
	_, creditsTok := env.mintPAT(sess, "credits-only", "credits:session")
	_, runTok := env.mintPAT(sess, "run-only", "run:read", "run:write")
	credits := caller{name: "credits-pat", pat: creditsTok}
	hit := func(c caller, method, path string) int {
		res := env.do(c, method, path, nil)
		_ = res.Body.Close()
		return res.StatusCode
	}
	for _, path := range []string{"/api/v1/x/probe/sessions", "/api/v1/x/probe/sessions/" + uuid.NewString() + "/renew"} {
		if got := hit(credits, http.MethodPost, path); got != http.StatusNoContent {
			t.Errorf("a PAT with credits:session was refused by the credits-session route %s: %d", path, got)
		}
	}
	if got := hit(caller{name: "run-pat", pat: runTok}, http.MethodPost, "/api/v1/x/probe/sessions"); got != http.StatusForbidden {
		t.Fatalf("a PAT without credits:session passed the credits-session route: %d", got)
	}
	if got := hit(sess, http.MethodPost, "/api/v1/x/probe/sessions"); got != http.StatusNoContent {
		t.Fatalf("a session was refused by the credits-session route: %d", got)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/x/probe/runs"},
		{http.MethodGet, "/api/v1/x/probe/status"},
		{http.MethodGet, "/api/v1/x/probe/sessions/" + uuid.NewString()},
		{http.MethodPost, "/api/v1/x/probe/sessions/" + uuid.NewString() + "/renew/more"},
		{http.MethodPost, "/api/v1/x/other/sessions"},
		{http.MethodGet, "/api/v1/user"},
		{http.MethodGet, "/api/v1/user/tokens"},
		{http.MethodPost, "/api/v1/user/tokens"},
		{http.MethodGet, "/api/v1/knowledge/packs"},
		{http.MethodGet, "/api/v1/voice"},
		{http.MethodGet, "/api/v1/meta"},
		{http.MethodGet, "/api/v1/agents/" + u + "/nothing"},
	} {
		if got := hit(credits, c.method, c.path); got != http.StatusForbidden {
			t.Errorf("a token carrying only credits:session reached %s %s: %d", c.method, c.path, got)
		}
	}
	if got := hit(anonymous, http.MethodGet, "/api/v1/x/probe/status"); got != http.StatusNoContent {
		t.Fatalf("the probe's open route refused an anonymous caller: %d; the refusal above proves nothing", got)
	}
	// The token lists its scope as minted.
	var tokens []struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/tokens", nil, &tokens, http.StatusOK)
	seen := false
	for _, tk := range tokens {
		if tk.Name == "credits-only" {
			seen = strings.Join(tk.Scopes, " ") == "credits:session"
		}
	}
	if !seen {
		t.Fatalf("the minted token does not list credits:session: %+v", tokens)
	}
	// A token of its own: never minted beside another scope.
	res := env.do(sess, http.MethodPost, "/api/v1/user/tokens", map[string]any{"name": "wider", "scopes": []string{"credits:session", "agent:read"}})
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "token of its own") {
		t.Fatalf("credits:session minted beside another scope: %d %s", res.StatusCode, body)
	}
}

// TestDepsBlobsIsTheDeploymentStore: the store the core runs
// on reaches an extension through Deps, and an object put under the
// extension's own prefix reads back, exists, and goes away on delete.
func TestDepsBlobsIsTheDeploymentStore(t *testing.T) {
	var srv *api.Server
	dir := t.TempDir()
	_ = newTestEnvCfg(t, func(cfg *config.Config) { cfg.Storage.LocalDir = dir }, func(s *api.Server) { srv = s })
	blobs := srv.Blobs()
	if blobs == nil {
		t.Fatal("a server with a database and local storage handed out no object store")
	}
	ctx := context.Background()
	key := "x/probe/runs/acct/run-1/result.json"
	if err := blobs.Put(ctx, key, strings.NewReader(`{"ok":true}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok, err := blobs.Exists(ctx, key); err != nil || !ok {
		t.Fatalf("Exists = %v, %v", ok, err)
	}
	rc, err := blobs.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != `{"ok":true}` {
		t.Fatalf("Get = %q", b)
	}
	if err := blobs.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := blobs.Exists(ctx, key); ok {
		t.Fatal("the object survived its delete")
	}
}
