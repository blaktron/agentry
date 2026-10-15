package api_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/dnsx"
)

// ---- shared M6 helpers ----

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
// SAML/OIDC login would do), so enforced-SSO tests need not run a full flow.
func (env *testEnv) freshenSSO(userID, orgID string) {
	env.t.Helper()
	_, err := env.st.Pool().Exec(context.Background(),
		`UPDATE sessions SET sso_tags = jsonb_build_object($1::text, $2::text) WHERE user_id = $3`,
		orgID, time.Now().UTC().Format(time.RFC3339), userID)
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

// TestEnforcedSSO covers §12.4: an sso_required org rejects a non-SSO-fresh
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
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("stale session on enforced-SSO org: got %d want 403", res.StatusCode)
	}

	// 2. A non-org-bound PAT (even with org:admin) is rejected.
	plainPAT := env.insertPAT(ownerID, "", "org:admin")
	res = env.do(caller{name: "plain-pat", pat: plainPAT}, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-org-bound PAT on enforced-SSO org: got %d want 403", res.StatusCode)
	}

	// 3. An org-bound PAT is admitted.
	boundPAT := env.insertPAT(ownerID, orgID, "org:admin")
	res = env.do(caller{name: "bound-pat", pat: boundPAT}, http.MethodGet, membersPath, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("org-bound PAT on enforced-SSO org: got %d want 200", res.StatusCode)
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
}

// TestDomainVerification covers §12.4 with an injected fake resolver: a present
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
}

type fakeResolver struct{ txt map[string][]string }

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}
