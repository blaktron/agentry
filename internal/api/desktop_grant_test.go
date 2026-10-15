package api_test

// The desktop browser sign-in's code exchange. A signed-in
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
	if len(scopes) != 13 {
		t.Fatalf("desktop PAT scopes = %v, want the thirteen desktop scopes", scopes)
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
	// The hosted-run scopes ride on the desktop grant: In
	// Agentry on RunPanel creates and reads runs with this token.
	if !has["run:read"] || !has["run:write"] {
		t.Fatalf("desktop PAT lacks the hosted-run scopes: %v", scopes)
	}
	// The knowledge scopes too: the Knowledge panel wraps,
	// unwraps, uploads and downloads packs with this token.
	if !has["knowledge:read"] || !has["knowledge:write"] {
		t.Fatalf("desktop PAT lacks the knowledge scopes: %v", scopes)
	}
	// And secret:write: the hosted-run start sets
	// a secret the account does not keep, and deletes it if the create is
	// refused.
	if !has["secret:write"] {
		t.Fatalf("desktop PAT lacks secret:write: %v", scopes)
	}
	// And the voice scopes: the desktop's Voice panel submits
	// this computer's voice and downloads the account's.
	if !has["voice:read"] || !has["voice:write"] {
		t.Fatalf("desktop PAT lacks the voice scopes: %v", scopes)
	}
	// And agent:manage: the desktop's Publisher section makes
	// a QuickAgent private or public, retires, restores and deletes it.
	if !has["agent:manage"] {
		t.Fatalf("desktop PAT lacks agent:manage: %v", scopes)
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

// Erasure consumes the account's unconsumed desktop codes in its own
// transaction: a code minted by another session moments before
// the erasure cannot be exchanged for a token afterwards.
func TestErasureConsumesDesktopGrants(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("dsk-erase")
	env.verifyEmail(h)
	sess := env.login(h)
	uid := env.selfID(sess)
	other := env.login(h) // the session that mints the code

	const state = "app-nonce-erase-0123456789"
	var grant struct {
		Code string `json:"code"`
	}
	env.doJSON(other, http.MethodPost, "/api/v1/user/tokens/desktop-grant",
		map[string]any{"state": state}, &grant, http.StatusCreated)
	if grant.Code == "" {
		t.Fatal("grant lacks a code")
	}

	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)

	ctx := context.Background()
	var unconsumed int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM desktop_grants WHERE user_id = $1 AND consumed_at IS NULL`, uid).Scan(&unconsumed); err != nil {
		t.Fatal(err)
	}
	if unconsumed != 0 {
		t.Fatalf("unconsumed desktop codes after erasure: %d, want 0", unconsumed)
	}

	res := env.do(anonymous, http.MethodPost, "/api/v1/auth/desktop/exchange",
		map[string]any{"code": grant.Code, "state": state})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("exchange after erasure: got %d, want 403", res.StatusCode)
	}
	var livePATs int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&livePATs); err != nil {
		t.Fatal(err)
	}
	if livePATs != 0 {
		t.Fatalf("live PATs for the erased account: %d, want 0", livePATs)
	}

	var detail []byte
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT detail FROM audit_events WHERE action = 'user.delete' AND target_id = $1`, uid).Scan(&detail); err != nil {
		t.Fatalf("audit user.delete: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(detail, &d)
	if d["desktopCodes"] != float64(1) {
		t.Errorf("user.delete audit detail = %s, want desktopCodes 1", detail)
	}
}
