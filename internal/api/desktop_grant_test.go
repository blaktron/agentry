package api_test

// The desktop browser sign-in's code exchange (agentry#19). A signed-in
// session records a grant bound to the app's state nonce; the app exchanges
// the code — once — for a PAT that works; wrong state, reuse, and expiry all
// answer 403; the grant endpoint is session-only.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestDesktopGrantExchange(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("dsk-user")
	env.verifyEmail(h)
	sess := env.login(h)

	const state = "app-nonce-0123456789abcdef"
	var grant struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expiresAt"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/user/tokens/desktop-grant",
		map[string]any{"state": state}, &grant, http.StatusCreated)
	if grant.Code == "" || grant.ExpiresAt == "" {
		t.Fatalf("grant lacks code or expiry: %+v", grant)
	}

	exchange := func(code, st string) (int, map[string]any) {
		res := env.do(anonymous, http.MethodPost, "/api/v1/auth/desktop/exchange",
			map[string]any{"code": code, "state": st})
		var out map[string]any
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		_ = json.Unmarshal(b, &out)
		return res.StatusCode, out
	}

	// Wrong state: refused, and the grant is NOT consumed by the attempt.
	if code, _ := exchange(grant.Code, "someone-elses-nonce-1234"); code != http.StatusForbidden {
		t.Fatalf("wrong state: got %d want 403", code)
	}
	// The right pair mints a PAT with the desktop scope set.
	code, pat := exchange(grant.Code, state)
	if code != http.StatusCreated {
		t.Fatalf("exchange: got %d %v want 201", code, pat)
	}
	tok, _ := pat["token"].(string)
	if tok == "" {
		t.Fatal("exchange returned no token")
	}
	scopes, _ := pat["scopes"].([]any)
	if len(scopes) != 7 {
		t.Fatalf("desktop PAT scopes = %v, want the seven desktop scopes", scopes)
	}
	has := map[string]bool{}
	for _, sc := range scopes {
		if sc == "review:act" || sc == "org:admin" {
			t.Fatalf("desktop PAT carries %v", sc)
		}
		if s, ok := sc.(string); ok {
			has[s] = true
		}
	}
	// The hosted-run scopes ride on the desktop grant (agentry#353): In
	// Agentry on RunPanel creates and reads runs with this token.
	if !has["run:read"] || !has["run:write"] {
		t.Fatalf("desktop PAT lacks the hosted-run scopes: %v", scopes)
	}
	// The PAT authenticates.
	var me struct {
		Handle string `json:"handle"`
	}
	env.doJSON(caller{name: "desktop-pat", pat: tok}, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.Handle != h {
		t.Fatalf("whoami via desktop PAT = %q want %q", me.Handle, h)
	}
	// Single use.
	if code, _ := exchange(grant.Code, state); code != http.StatusForbidden {
		t.Fatalf("reuse: got %d want 403", code)
	}
	// Garbage code: same answer, nothing leaks.
	if code, _ := exchange("agd_not-a-real-code", state); code != http.StatusForbidden {
		t.Fatalf("unknown code: got %d want 403", code)
	}

	// Expiry: a fresh grant aged past its TTL is refused.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/tokens/desktop-grant",
		map[string]any{"state": state}, &grant, http.StatusCreated)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE desktop_grants SET expires_at = now() - interval '1 second' WHERE consumed_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code, _ := exchange(grant.Code, state); code != http.StatusForbidden {
		t.Fatalf("expired: got %d want 403", code)
	}

	// The grant endpoint is session-only: the desktop PAT itself cannot mint
	// further grants (SessionOnly decl), and anonymous callers are refused.
	res := env.do(caller{name: "pat", pat: tok}, http.MethodPost, "/api/v1/user/tokens/desktop-grant", map[string]any{"state": state})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("grant via PAT: got %d want 401/403", res.StatusCode)
	}
	res = env.do(anonymous, http.MethodPost, "/api/v1/user/tokens/desktop-grant", map[string]any{"state": state})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("grant anonymous: got %d want 401", res.StatusCode)
	}
}
