package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

const callbackSecret = "callback-secret-0123456789abcdef0123"

// callbackServer serves one extension's callback mount whose one route
// reports whether it saw a principal, so a test can tell the gate let a
// request through and that nothing resolved a caller for it.
func callbackServer(t *testing.T, cb api.ExtensionCallbacks, cfgFn func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	if cfgFn != nil {
		cfgFn(&cfg)
	}
	srv := api.New(cfg, nil, nil)
	cb.Routes = func(m *http.ServeMux) {
		m.HandleFunc("POST /check", func(w http.ResponseWriter, r *http.Request) {
			p := api.PrincipalFrom(r.Context())
			if p != nil && !p.Anonymous {
				_, _ = io.WriteString(w, "principal")
				return
			}
			_, _ = io.WriteString(w, "reached")
		})
	}
	srv.RegisterExtensionCallbacks("directory", cb)
	hs := httptest.NewServer(api.NewHandler(srv))
	t.Cleanup(hs.Close)
	return hs
}

func postCallback(t *testing.T, hs *httptest.Server, header map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, hs.URL+"/internal/x/directory/check", strings.NewReader(`{}`))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// TestExtensionCallbacksAreGatedByTheCore: an extension's callback mount is
// reached only with its secret, never through a proxy, and never with a
// principal resolved; with no secret it does not exist.
func TestExtensionCallbacksAreGatedByTheCore(t *testing.T) {
	hs := callbackServer(t, api.ExtensionCallbacks{Secret: callbackSecret, Class: api.RateNone, Why: "the directory's flow, on the private network"}, nil)
	bearer := map[string]string{"Authorization": "Bearer " + callbackSecret}

	if code, body := postCallback(t, hs, bearer); code != http.StatusOK || body != "reached" {
		t.Fatalf("with the secret: %d %q, want 200 reached (and no principal)", code, body)
	}
	if code, _ := postCallback(t, hs, nil); code != http.StatusUnauthorized {
		t.Errorf("no secret presented: %d, want 401", code)
	}
	if code, _ := postCallback(t, hs, map[string]string{"Authorization": "Bearer " + callbackSecret + "x"}); code != http.StatusUnauthorized {
		t.Errorf("a wrong secret: %d, want 401", code)
	}
	for _, h := range []string{"X-Forwarded-For", "Forwarded"} {
		hdr := map[string]string{"Authorization": "Bearer " + callbackSecret, h: "203.0.113.9"}
		if code, _ := postCallback(t, hs, hdr); code != http.StatusNotFound {
			t.Errorf("through a proxy (%s): %d, want 404 whatever the secret", h, code)
		}
	}
	// A session cookie is not a way in, and resolves no principal.
	if code, body := postCallback(t, hs, map[string]string{
		"Authorization": "Bearer " + callbackSecret, "Cookie": "agentry_session=whatever",
	}); code != http.StatusOK || body != "reached" {
		t.Errorf("with a session cookie beside the secret: %d %q, want 200 reached", code, body)
	}

	off := callbackServer(t, api.ExtensionCallbacks{Class: api.RateNone, Why: "switched off"}, nil)
	if code, _ := postCallback(t, off, bearer); code != http.StatusNotFound {
		t.Errorf("with no secret configured: %d, want 404", code)
	}
}

// TestExtensionCallbacksDrawFromTheDeclaredClass: a mount declared in the
// anonymous class is refused once its address has spent the bucket; one
// declared in none is not.
func TestExtensionCallbacksDrawFromTheDeclaredClass(t *testing.T) {
	small := func(c *config.Config) { c.Limits.AnonymousPerMin = 2 }
	bearer := map[string]string{"Authorization": "Bearer " + callbackSecret}

	anon := callbackServer(t, api.ExtensionCallbacks{Secret: callbackSecret, Class: "anon", Why: "per address"}, small)
	refused := false
	for range 10 {
		if code, _ := postCallback(t, anon, bearer); code == http.StatusTooManyRequests {
			refused = true
			break
		}
	}
	if !refused {
		t.Error("a mount in the anonymous class was never refused past its bucket")
	}

	none := callbackServer(t, api.ExtensionCallbacks{Secret: callbackSecret, Class: api.RateNone, Why: "one caller for everyone"}, small)
	for i := range 10 {
		if code, _ := postCallback(t, none, bearer); code != http.StatusOK {
			t.Fatalf("a mount in no class, request %d: %d, want 200", i, code)
		}
	}
}

// TestExtensionCallbacksRefuseAWeakDeclaration: the declaration is checked
// at start-up, so a mount with no reason, an unknown class or a short
// secret never serves.
func TestExtensionCallbacksRefuseAWeakDeclaration(t *testing.T) {
	routes := func(*http.ServeMux) {}
	for name, cb := range map[string]api.ExtensionCallbacks{
		"no reason":      {Class: api.RateNone, Routes: routes},
		"unknown class":  {Class: "authed", Why: "x", Routes: routes},
		"short secret":   {Secret: "short", Class: api.RateNone, Why: "x", Routes: routes},
		"no routes":      {Class: api.RateNone, Why: "x"},
		"principal rate": {Class: api.RatePerPrincipal, Why: "x", Routes: routes},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DevMode = true
			srv := api.New(cfg, nil, nil)
			defer func() {
				if recover() == nil {
					t.Error("the declaration was accepted")
				}
			}()
			srv.RegisterExtensionCallbacks("directory", cb)
		})
	}
}

// TestExtensionCallbacksAreDeclared: the completeness gate reads a callback
// mount's declaration from the server that mounted it, as the extension
// declared it.
func TestExtensionCallbacksAreDeclared(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, nil, nil)
	srv.RegisterExtensionCallbacks("directory", api.ExtensionCallbacks{
		Class: "anon", Why: "per address", Routes: func(*http.ServeMux) {},
	})
	decl, ok := srv.MountAuthzDecl("/internal/x/directory/")
	if !ok || decl.Gate != api.GateExtensionSecret || decl.Class != "anon" || decl.Why != "per address" {
		t.Fatalf("declaration %+v (%v), want the extension's own", decl, ok)
	}
	if _, ok := srv.MountAuthzDecl("/internal/x/other/"); ok {
		t.Error("a callback mount nobody registered is declared")
	}
	if _, ok := api.MountAuthzDecl("/internal/x/directory/"); ok {
		t.Error("the package table declares an extension's mount it cannot know")
	}
}
