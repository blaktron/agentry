package api_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/dnsx"
)

// ---- shared helpers ----

func (env *testEnv) selfID(c caller) string {
	env.t.Helper()
	var out struct {
		Id string `json:"id"`
	}
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &out, http.StatusOK)
	return out.Id
}

func (env *testEnv) createOrg(c caller, handle string) string {
	env.t.Helper()
	var out struct {
		Id string `json:"id"`
	}
	env.doJSON(c, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": handle, "displayName": "Org " + handle}, &out, http.StatusCreated)
	return out.Id
}

// freshenSSO stamps a user's sessions SSO-fresh for an org (what a successful
// sign-in through the organization's identity provider would do), so
// enforced-SSO tests need not run a full flow.
func (env *testEnv) freshenSSO(userID, orgID string) {
	env.t.Helper()
	_, err := env.st.Pool().Exec(context.Background(),
		`UPDATE sessions SET sso_tags = jsonb_build_object($1::text, $2::text) WHERE user_id = $3`,
		orgID, time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		env.t.Fatal(err)
	}
}

// staleSSO stamps a user's sessions with an SSO sign-in for an org that is
// older than the freshness the deployment allows.
func (env *testEnv) staleSSO(userID, orgID string) {
	env.t.Helper()
	_, err := env.st.Pool().Exec(context.Background(),
		`UPDATE sessions SET sso_tags = jsonb_build_object($1::text, $2::text) WHERE user_id = $3`,
		orgID, time.Now().Add(-2*24*time.Hour).UTC().Format(time.RFC3339), userID)
	if err != nil {
		env.t.Fatal(err)
	}
}

// insertPAT inserts a PAT directly and returns its token. orgID may be "".
func (env *testEnv) insertPAT(userID, orgID string, scopes ...string) string {
	env.t.Helper()
	token := "agy_" + randToken(env)
	sum := sha256.Sum256([]byte(token))
	var org any
	if orgID != "" {
		org = orgID
	}
	_, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO pats (id, user_id, name, token_sha256, token_prefix, scopes, org_id, expires_at)
		 VALUES (gen_random_uuid(), $1, 'test', $2, $3, $4, $5, now() + interval '1 day')`,
		userID, sum[:], token[:12], scopes, org)
	if err != nil {
		env.t.Fatal(err)
	}
	return token
}

// insertSession inserts a session for a user and returns its cookie token.
func (env *testEnv) insertSession(userID string) string {
	env.t.Helper()
	token := "agys_" + randToken(env)
	sum := sha256.Sum256([]byte(token))
	_, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO sessions (id, token_sha256, user_id, csrf_token, expires_at)
		 VALUES (gen_random_uuid(), $1, $2, 'csrf', now() + interval '1 day')`,
		sum[:], userID)
	if err != nil {
		env.t.Fatal(err)
	}
	return token
}

func randToken(env *testEnv) string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		env.t.Fatal(err)
	}
	return env.sfx + hex.EncodeToString(b[:])
}

// TestEnforcedSSO covers enforced SSO: an sso_required org rejects a non-SSO-fresh
// session and a non-org-bound PAT, and admits an SSO-fresh session and an
// org-bound PAT.
func TestEnforcedSSO(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("es-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	ownerID := env.selfID(sess)
	orgH := "esorg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	// Enable enforced SSO (owner; sso_required still false at check time).
	env.doJSON(sess, http.MethodPatch, "/api/v1/orgs/"+orgH,
		map[string]any{"ssoRequired": true}, nil, http.StatusOK)

	membersPath := "/api/v1/orgs/" + orgH + "/members"

	// 1. Stale session (no SSO tag) is now rejected on org resources.
	res := env.do(sess, http.MethodGet, membersPath, nil)
	if code, slug, _ := problemOf(t, res); code != http.StatusForbidden || slug != "sso-required" {
		t.Fatalf("stale session on enforced-SSO org: got %d %s want 403 sso-required", code, slug)
	}

	// 2. A non-org-bound PAT (even with org:admin) is rejected.
	plainPAT := env.insertPAT(ownerID, "", "org:admin")
	res = env.do(caller{name: "plain-pat", pat: plainPAT}, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-org-bound PAT on enforced-SSO org: got %d want 403", res.StatusCode)
	}

	// 3. An org-bound PAT is admitted, one bound to another organization is
	// not.
	boundPAT := env.insertPAT(ownerID, orgID, "org:admin")
	res = env.do(caller{name: "bound-pat", pat: boundPAT}, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("org-bound PAT on enforced-SSO org: got %d want 200", res.StatusCode)
	}
	otherOwner := env.register("es-other")
	env.verifyEmail(otherOwner)
	otherOrgID := env.createOrg(env.login(otherOwner), "esother"+env.sfx)
	elsewherePAT := env.insertPAT(ownerID, otherOrgID, "org:admin")
	res = env.do(caller{name: "elsewhere-pat", pat: elsewherePAT}, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT bound to another organization on enforced-SSO org: got %d want 403", res.StatusCode)
	}

	// An SSO sign-in older than the deployment allows (eight hours) has
	// lapsed, and a token for the organization cannot be minted from it.
	env.staleSSO(ownerID, orgID)
	res = env.do(sess, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("session with a lapsed SSO sign-in on enforced-SSO org: got %d want 403", res.StatusCode)
	}
	res = env.do(sess, http.MethodPost, "/api/v1/user/tokens",
		map[string]any{"name": "bound", "scopes": []string{"org:admin"}, "orgHandle": orgH})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("minting an org-bound token from a lapsed SSO sign-in: got %d want 403", res.StatusCode)
	}

	// 4. An SSO-fresh session is admitted.
	env.freshenSSO(ownerID, orgID)
	res = env.do(sess, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("SSO-fresh session on enforced-SSO org: got %d want 200", res.StatusCode)
	}

	// 5. Minting an org-bound token now succeeds (fresh session) and is capped.
	var tok struct {
		Token string `json:"token"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/user/tokens",
		map[string]any{"name": "bound", "scopes": []string{"org:admin"}, "orgHandle": orgH}, &tok, http.StatusCreated)
	if tok.Token == "" {
		t.Fatal("expected an org-bound token")
	}
	res = env.do(caller{name: "minted-bound", pat: tok.Token}, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("minted org-bound PAT: got %d want 200", res.StatusCode)
	}

	// The cap: 90 days for a token bound to an organization (a year for
	// any other), by default and as asked for.
	day := 24 * time.Hour
	mint := func(days int) (int, []api.FieldError, time.Time) {
		res := env.do(sess, http.MethodPost, "/api/v1/user/tokens", map[string]any{
			"name": "capped", "scopes": []string{"org:admin"}, "orgHandle": orgH, "expiresAt": time.Now().Add(time.Duration(days) * day),
		})
		defer func() { _ = res.Body.Close() }()
		raw, _ := io.ReadAll(res.Body)
		var body struct {
			Errors    []api.FieldError `json:"errors"`
			ExpiresAt time.Time        `json:"expiresAt"`
		}
		_ = json.Unmarshal(raw, &body)
		return res.StatusCode, body.Errors, body.ExpiresAt
	}
	if code, fields, _ := mint(91); code != http.StatusUnprocessableEntity || len(fields) != 1 || fields[0].Field != "expiresAt" {
		t.Fatalf("an org-bound token for 91 days: %d %+v, want 422 on expiresAt", code, fields)
	}
	if code, _, exp := mint(89); code != http.StatusCreated || exp.Before(time.Now().Add(88*day)) {
		t.Fatalf("an org-bound token for 89 days: %d, expires %v, want 201", code, exp)
	}
	var byDefault struct {
		ExpiresAt time.Time `json:"expiresAt"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/user/tokens",
		map[string]any{"name": "default", "scopes": []string{"org:admin"}, "orgHandle": orgH}, &byDefault, http.StatusCreated)
	if got := time.Until(byDefault.ExpiresAt); got > 90*day || got < 90*day-time.Hour {
		t.Fatalf("an org-bound token with no expiry given lasts %v, want the 90-day cap", got)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/user/tokens",
		map[string]any{"name": "plain", "scopes": []string{"user:profile"}, "expiresAt": time.Now().Add(300 * day)}, nil, http.StatusCreated)
}

// TestDomainVerification covers domain verification with an injected fake resolver: a present
// TXT record verifies (and sets the org verified domain), an absent one does
// not.
func TestDomainVerification(t *testing.T) {
	fake := &fakeResolver{txt: map[string][]string{}}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetResolver(fake) })
	owner := env.register("dv-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "dvorg" + env.sfx
	env.createOrg(sess, orgH)

	// A claim names a domain: a dot, letters, digits and hyphens, at most
	// 253 characters, written the way DNS writes it.
	for name, bad := range map[string]string{
		"no dot":              "nodot",
		"an underscore":       "bad_name.example",
		"a space":             "bad name.example",
		"254 characters":      strings.Repeat("a", 252) + ".b",
		"nothing":             "",
		"only a trailing dot": ".",
	} {
		res := env.do(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims", map[string]any{"domain": bad})
		if code, slug, _ := problemOf(t, res); code != http.StatusUnprocessableEntity || slug != "validation" {
			t.Errorf("a claim for a domain with %s: %d %s, want 422 validation", name, code, slug)
		}
	}
	var widest struct {
		Domain string `json:"domain"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims",
		map[string]any{"domain": strings.Repeat("a", 251) + ".b"}, &widest, http.StatusCreated)
	if len(widest.Domain) != 253 {
		t.Fatalf("a 253-character domain was claimed as %q", widest.Domain)
	}
	var spelled struct {
		Domain string `json:"domain"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims",
		map[string]any{"domain": "Mixed-Case-" + env.sfx + ".Example."}, &spelled, http.StatusCreated)
	if spelled.Domain != "mixed-case-"+env.sfx+".example" {
		t.Fatalf("a claim for a domain written in capitals with a trailing dot is kept as %q", spelled.Domain)
	}
	// A space after the trailing dot does not keep the dot.
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims",
		map[string]any{"domain": " Spaced-" + env.sfx + ".Example. "}, &spelled, http.StatusCreated)
	if spelled.Domain != "spaced-"+env.sfx+".example" {
		t.Fatalf("a claim with a trailing dot and a space is kept as %q", spelled.Domain)
	}

	domain := "acme-" + env.sfx + ".example"
	var claim struct {
		VerificationToken string `json:"verificationToken"`
		Verified          bool   `json:"verified"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims",
		map[string]any{"domain": domain}, &claim, http.StatusCreated)
	if claim.VerificationToken == "" || claim.Verified {
		t.Fatalf("unexpected new claim: %+v", claim)
	}

	// Absent TXT → not verified.
	var res1 struct {
		Verified bool `json:"verified"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims/verify",
		map[string]any{"domain": domain}, &res1, http.StatusOK)
	if res1.Verified {
		t.Fatal("verification should fail with no TXT record")
	}

	// A record that carries another token, bare or prefixed, proves nothing.
	fake.txt[dnsx.TXTName(domain)] = []string{"agentry-domain-verification=not-the-token", "not-the-token", "agentry-domain-verification="}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims/verify",
		map[string]any{"domain": domain}, &res1, http.StatusOK)
	if res1.Verified {
		t.Fatal("verification should fail with a TXT record that carries another token")
	}

	// Publish the TXT record → verified.
	fake.txt[dnsx.TXTName(domain)] = []string{"agentry-domain-verification=" + claim.VerificationToken}
	var res2 struct {
		Verified bool `json:"verified"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/domain-claims/verify",
		map[string]any{"domain": domain}, &res2, http.StatusOK)
	if !res2.Verified {
		t.Fatal("verification should succeed with the TXT record present")
	}
	// The accounts already known at the verified domain are folded in.
	var sweeps int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'domain' = $2`, api.JobFoldInSweep, domain).Scan(&sweeps); err != nil {
		t.Fatal(err)
	}
	if sweeps != 1 {
		t.Errorf("fold-in sweeps queued for the verified domain: %d, want 1", sweeps)
	}
	for action, n := range map[string]int{"domain.claim": 1, "domain.verified": 1} {
		var got int
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.org_id WHERE h.handle = $1 AND a.action = $2 AND a.detail->>'domain' = $3`,
			orgH, action, domain).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != n {
			t.Errorf("%s rows for %s: %d, want %d", action, domain, got, n)
		}
	}
}

type fakeResolver struct{ txt map[string][]string }

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}
