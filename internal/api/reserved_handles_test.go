package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/testidp"
)

// Root paths of the server and the site are not handles: `ui` is
// the server's own surface, and a person named `settings` would shadow a
// page. The product's own names are reserved too, so nobody can pass
// content off as first-party.
func TestReservedHandlesAreRefused(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	// A first sign-in asking for a reserved name as its username is given
	// another handle, never the reserved one.
	for _, h := range []string{"ui", "settings", "api", "agentry", "secureagentry"} {
		in := env.signInOIDC(t, idp, config.OIDCProviderID, testidp.Person{
			Subject: "sub-resv-" + h + env.sfx, Email: h + env.sfx + "@example.test", EmailVerified: true, Username: h,
		})
		if in.status != http.StatusOK || in.handle == "" || in.handle == h {
			t.Fatalf("sign-in asking for %q: %d, handle %q", h, in.status, in.handle)
		}
		// The handle keeps the name asked for, suffixed: the reserved
		// form with -1, or, when that is taken, the derived fallback.
		if !strings.HasPrefix(in.handle, h+"-") {
			t.Fatalf("sign-in asking for %q got handle %q, want the name with a suffix", h, in.handle)
		}
	}
	owner := env.register("resv")
	env.verifyEmail(owner)
	sess := env.login(owner)
	for _, h := range []string{"ui", "agentry"} {
		res := env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": h, "displayName": "Reserved"})
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode < 400 || res.StatusCode >= 500 || !strings.Contains(string(b), "reserved") {
			t.Fatalf("createOrg %q as a member: %d %s", h, res.StatusCode, b)
		}
	}
}

// Platform staff may create an org with a first-party name — that is how
// the `agentry` org that publishes the examples comes to exist — but a
// root path stays refused for staff too: an org named `ui` would shadow
// the server's own pages.
func TestStaffMayCreateFirstPartyOrg(t *testing.T) {
	env := newTestEnv(t)
	staff := env.register("fpstaff")
	env.verifyEmail(staff)
	env.makePlatformStaff(t, staff)
	sess := env.login(staff)

	res := env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "ui", "displayName": "UI"})
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode < 400 || res.StatusCode >= 500 || !strings.Contains(string(b), "reserved") {
		t.Fatalf("createOrg ui as staff: %d %s", res.StatusCode, b)
	}

	res = env.do(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": "secureagentry", "displayName": "SecureAgentry"})
	b, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	switch {
	case res.StatusCode == http.StatusCreated:
	case res.StatusCode == http.StatusConflict && strings.Contains(string(b), "already in use"):
		// The test database persists between local runs and the handle is
		// fixed by design; a second run finds the org from the first. What
		// matters is that staff is not refused as "reserved".
		t.Logf("secureagentry already exists from an earlier run: %s", b)
	default:
		t.Fatalf("createOrg secureagentry as staff (a reserved refusal here is the bug): %d %s", res.StatusCode, b)
	}
}
