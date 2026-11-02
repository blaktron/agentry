package api_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
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
	code, _, body := postCallbackFull(t, hs, header)
	return code, body
}

// postCallbackFull is postCallback with the response headers.
func postCallbackFull(t *testing.T, hs *httptest.Server, header map[string]string) (int, http.Header, string) {
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
	return res.StatusCode, res.Header, string(body)
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
	served := 0
	for range 10 {
		code, hdr, _ := postCallbackFull(t, anon, bearer)
		if code == http.StatusTooManyRequests {
			refused = true
			if retry, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || retry < 1 {
				t.Errorf("a refused callback's Retry-After = %q, want a whole number of seconds >= 1", hdr.Get("Retry-After"))
			}
			if hdr.Get("RateLimit-Limit") != "2" || hdr.Get("RateLimit-Remaining") != "0" {
				t.Errorf("a refused callback's budget headers: limit %q remaining %q, want 2 and 0", hdr.Get("RateLimit-Limit"), hdr.Get("RateLimit-Remaining"))
			}
			break
		}
		served++
		if want := strconv.Itoa(2 - served); hdr.Get("RateLimit-Limit") != "2" || hdr.Get("RateLimit-Remaining") != want {
			t.Errorf("callback %d's budget headers: limit %q remaining %q, want 2 and %s", served, hdr.Get("RateLimit-Limit"), hdr.Get("RateLimit-Remaining"), want)
		}
	}
	if !refused {
		t.Error("a mount in the anonymous class was never refused past its bucket")
	}
	if served != 2 {
		t.Errorf("%d callbacks served before the refusal, want the bucket's 2", served)
	}

	// The class is spent before the secret is read, so guesses at the secret
	// draw from it too: two wrong secrets, then the bucket is empty for
	// the right one.
	guessed := callbackServer(t, api.ExtensionCallbacks{Secret: callbackSecret, Class: "anon", Why: "per address"}, small)
	wrong := map[string]string{"Authorization": "Bearer " + callbackSecret + "x"}
	for i := range 2 {
		if code, _ := postCallback(t, guessed, wrong); code != http.StatusUnauthorized {
			t.Fatalf("wrong secret %d: %d, want 401", i+1, code)
		}
	}
	if code, _ := postCallback(t, guessed, wrong); code != http.StatusTooManyRequests {
		t.Errorf("a third wrong secret: %d, want 429 (guesses spend the class)", code)
	}
	if code, _ := postCallback(t, guessed, bearer); code != http.StatusTooManyRequests {
		t.Errorf("the right secret after the guesses: %d, want 429", code)
	}

	// The bucket is the caller's address's: a second address has its own.
	t.Run("a second address has its own bucket", func(t *testing.T) {
		shared := callbackServer(t, api.ExtensionCallbacks{Secret: callbackSecret, Class: "anon", Why: "per address"}, small)
		for i := range 2 {
			if code, _ := postCallback(t, shared, bearer); code != http.StatusOK {
				t.Fatalf("request %d from the first address: %d, want 200", i+1, code)
			}
		}
		if code, _ := postCallback(t, shared, bearer); code != http.StatusTooManyRequests {
			t.Fatalf("a third request from the first address: %d, want 429", code)
		}
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
		client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
		t.Cleanup(client.CloseIdleConnections)
		req, _ := http.NewRequest(http.MethodPost, shared.URL+"/internal/x/directory/check", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+callbackSecret)
		res, err := client.Do(req)
		if err != nil {
			// Linux routes all of 127.0.0.0/8 to loopback, so there this
			// is a failure; elsewhere the second address may not exist.
			if runtime.GOOS == "linux" {
				t.Fatalf("send from a second loopback address: %v", err)
			}
			t.Skipf("cannot send from a second loopback address: %v", err)
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusOK {
			t.Errorf("a request from a second address: %d, want 200 from its own bucket", res.StatusCode)
		}
	})

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

	// The reason must say something, the secret has a floor of 32
	// characters, the name has a shape, and a name serves one mount.
	valid := api.ExtensionCallbacks{Class: api.RateNone, Why: "x", Routes: routes}
	panics := func(f func(srv *api.Server)) (panicked bool) {
		cfg := config.Default()
		cfg.DevMode = true
		srv := api.New(cfg, nil, nil)
		defer func() { panicked = recover() != nil }()
		f(srv)
		return false
	}
	register := func(name string, cb api.ExtensionCallbacks) func(*api.Server) {
		return func(srv *api.Server) { srv.RegisterExtensionCallbacks(name, cb) }
	}
	withReason := func(why string) api.ExtensionCallbacks { c := valid; c.Why = why; return c }
	withSecret := func(n int) api.ExtensionCallbacks { c := valid; c.Secret = strings.Repeat("s", n); return c }
	for name, f := range map[string]func(*api.Server){
		"a blank reason":        register("directory", withReason("  \t ")),
		"a 31-character secret": register("directory", withSecret(31)),
		"an uppercase name":     register("Directory", valid),
		"a name with a slash":   register("a/b", valid),
		"an empty name":         register("", valid),
		"a name registered a second time": func(srv *api.Server) {
			srv.RegisterExtensionCallbacks("directory", valid)
			srv.RegisterExtensionCallbacks("directory", valid)
		},
	} {
		if !panics(f) {
			t.Errorf("%s: the declaration was accepted", name)
		}
	}
	for name, f := range map[string]func(*api.Server){
		"a 32-character secret":            register("directory", withSecret(32)),
		"no secret (the mount off)":        register("directory", valid),
		"a name with a digit and a hyphen": register("dir-2", valid),
		"two names": func(srv *api.Server) {
			srv.RegisterExtensionCallbacks("directory", valid)
			srv.RegisterExtensionCallbacks("other", valid)
		},
	} {
		if panics(f) {
			t.Errorf("%s: a sound declaration was refused", name)
		}
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
