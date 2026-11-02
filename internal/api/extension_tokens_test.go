package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
)

const (
	ownPrefix = "agym_"
	ownToken  = ownPrefix + "knowntokenvalue"
	ownBroken = ownPrefix + "breakstheresolver"
	// ownNobody is a token the resolver knows and says belongs to no one.
	ownNobody = ownPrefix + "knownbutnobodys"
)

var ownUser = uuid.MustParse("6a1f7f4e-6d3a-4c47-9d3e-1b2c3d4e5f60")

// ownTokenServer serves two extensions: "meter", which takes tokens of its
// own, and "other", which takes none. Each has one route that reports the
// principal it was handed.
func ownTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, nil, nil)
	who := func(w http.ResponseWriter, r *http.Request) {
		p := api.PrincipalFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"anonymous": p.Anonymous, "via": p.Via, "user": p.UserID.String(),
			"scopes": len(p.Scopes), "roles": len(p.OrgRoles), "scopeBound": p.ScopeBound(),
		})
	}
	srv.RegisterExtension("meter", func(m *http.ServeMux) { m.HandleFunc("GET /who", who) })
	srv.RegisterExtension("other", func(m *http.ServeMux) { m.HandleFunc("GET /who", who) })
	srv.SetExtensionTokens("meter", ownPrefix, func(_ context.Context, tok string) (uuid.UUID, bool, error) {
		switch tok {
		case ownToken:
			return ownUser, true, nil
		case ownBroken:
			return uuid.Nil, false, errors.New("store down")
		case ownNobody:
			return uuid.Nil, true, nil
		}
		return uuid.Nil, false, nil
	})
	hs := httptest.NewServer(api.NewHandler(srv))
	t.Cleanup(hs.Close)
	return hs
}

func getWithBearer(t *testing.T, hs *httptest.Server, path, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, hs.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return res.StatusCode, body
}

// TestExtensionOwnTokensResolveUnderTheirMountAlone: an extension's own
// token becomes a principal with no scopes and no roles under that
// extension's mount, and is not recognized anywhere else.
func TestExtensionOwnTokensResolveUnderTheirMountAlone(t *testing.T) {
	hs := ownTokenServer(t)

	code, body := getWithBearer(t, hs, "/api/v1/x/meter/who", ownToken)
	if code != http.StatusOK {
		t.Fatalf("own mount: %d %v", code, body)
	}
	if body["via"] != "extension" || body["user"] != ownUser.String() || body["anonymous"] != false {
		t.Errorf("own mount principal = %v", body)
	}
	if body["scopes"] != float64(0) || body["roles"] != float64(0) || body["scopeBound"] != true {
		t.Errorf("an extension's token must carry no scopes and no roles, and be scope-bound: %v", body)
	}

	for _, path := range []string{"/api/v1/x/other/who", "/api/v1/meta"} {
		if code, body := getWithBearer(t, hs, path, ownToken); code != http.StatusUnauthorized {
			t.Errorf("%s with the extension's token: %d %v, want 401", path, code, body)
		}
	}
}

// TestExtensionOwnTokensUnknownOrFailing: a token of the prefix the
// extension does not know is 401; a resolver that fails is 500; a request
// with no bearer is anonymous, as before.
func TestExtensionOwnTokensUnknownOrFailing(t *testing.T) {
	hs := ownTokenServer(t)
	if code, _ := getWithBearer(t, hs, "/api/v1/x/meter/who", ownPrefix+"nobodyknowsthis"); code != http.StatusUnauthorized {
		t.Errorf("unknown token: %d, want 401", code)
	}
	if code, _ := getWithBearer(t, hs, "/api/v1/x/meter/who", ownBroken); code != http.StatusInternalServerError {
		t.Errorf("failing resolver: %d, want 500", code)
	}
	if code, _ := getWithBearer(t, hs, "/api/v1/x/meter/who", "agyq_someoneelses"); code != http.StatusUnauthorized {
		t.Errorf("another prefix: %d, want 401", code)
	}
	if code, body := getWithBearer(t, hs, "/api/v1/x/meter/who", ownNobody); code != http.StatusUnauthorized {
		t.Errorf("a token the resolver says is no one's: %d %v, want 401", code, body)
	}
	code, body := getWithBearer(t, hs, "/api/v1/x/meter/who", "")
	if code != http.StatusOK || body["anonymous"] != true {
		t.Errorf("no bearer: %d %v, want anonymous", code, body)
	}
}

// TestCreditsSessionRoutesRefuseABadDeclaration: a route of the wrong
// shape, a wildcard broader than one segment, an empty list, a second
// declaration or an unregistered extension panics at start-up.
func TestCreditsSessionRoutesRefuseABadDeclaration(t *testing.T) {
	cases := map[string]func(s *api.Server){
		"no method":       func(s *api.Server) { s.SetExtensionCreditsSessions("meter", []string{"/sessions"}) },
		"a prefix":        func(s *api.Server) { s.SetExtensionCreditsSessions("meter", []string{"POST /sessions/"}) },
		"a rest wildcard": func(s *api.Server) { s.SetExtensionCreditsSessions("meter", []string{"POST /{rest...}"}) },
		"the whole mount": func(s *api.Server) { s.SetExtensionCreditsSessions("meter", []string{"GET /"}) },
		"empty":           func(s *api.Server) { s.SetExtensionCreditsSessions("meter", nil) },
		"unregistered":    func(s *api.Server) { s.SetExtensionCreditsSessions("nobody", []string{"POST /sessions"}) },
		"set twice": func(s *api.Server) {
			s.SetExtensionCreditsSessions("meter", []string{"POST /sessions"})
			s.SetExtensionCreditsSessions("meter", []string{"DELETE /sessions/{id}"})
		},
	}
	for name, declare := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DevMode = true
			srv := api.New(cfg, nil, nil)
			srv.RegisterExtension("meter", func(*http.ServeMux) {})
			defer func() {
				if recover() == nil {
					t.Error("the declaration was accepted")
				}
			}()
			declare(srv)
		})
	}
}

// TestExtensionOwnTokensRefuseABadDeclaration: a prefix of the wrong shape,
// one of the core's, one claimed twice, a nil resolver or an unregistered
// extension panics at start-up.
func TestExtensionOwnTokensRefuseABadDeclaration(t *testing.T) {
	resolve := func(context.Context, string) (uuid.UUID, bool, error) { return uuid.Nil, false, nil }
	cases := map[string]func(s *api.Server){
		"not the agy family": func(s *api.Server) { s.SetExtensionTokens("meter", "tok_", resolve) },
		"no underscore":      func(s *api.Server) { s.SetExtensionTokens("meter", "agym", resolve) },
		"too long":           func(s *api.Server) { s.SetExtensionTokens("meter", "agymodel_", resolve) },
		"the core's PAT":     func(s *api.Server) { s.SetExtensionTokens("meter", "agy_", resolve) },
		"the core's session": func(s *api.Server) { s.SetExtensionTokens("meter", "agys_", resolve) },
		"no resolver":        func(s *api.Server) { s.SetExtensionTokens("meter", "agym_", nil) },
		"unregistered":       func(s *api.Server) { s.SetExtensionTokens("nobody", "agym_", resolve) },
		"claimed twice": func(s *api.Server) {
			s.SetExtensionTokens("meter", "agym_", resolve)
			s.SetExtensionTokens("other", "agym_", resolve)
		},
		"set twice": func(s *api.Server) {
			s.SetExtensionTokens("meter", "agym_", resolve)
			s.SetExtensionTokens("meter", "agyn_", resolve)
		},
		"the core's invitation": func(s *api.Server) { s.SetExtensionTokens("meter", auth.InvitePrefix, resolve) },
		"the core's activation": func(s *api.Server) { s.SetExtensionTokens("meter", auth.VerificationPrefix, resolve) },
		"the core's remembered browser": func(s *api.Server) {
			s.SetExtensionTokens("meter", auth.TrustedDevicePrefix, resolve)
		},
		"a capital letter":     func(s *api.Server) { s.SetExtensionTokens("meter", "agyM_", resolve) },
		"a digit":              func(s *api.Server) { s.SetExtensionTokens("meter", "agy1_", resolve) },
		"a leading character":  func(s *api.Server) { s.SetExtensionTokens("meter", "xagym_", resolve) },
		"a trailing character": func(s *api.Server) { s.SetExtensionTokens("meter", "agym_x", resolve) },
		"no letter after agy":  func(s *api.Server) { s.SetExtensionTokens("meter", "agy_", resolve) },
		"an empty prefix":      func(s *api.Server) { s.SetExtensionTokens("meter", "", resolve) },
	}
	for name, declare := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DevMode = true
			srv := api.New(cfg, nil, nil)
			srv.RegisterExtension("meter", func(*http.ServeMux) {})
			srv.RegisterExtension("other", func(*http.ServeMux) {})
			defer func() {
				if recover() == nil {
					t.Error("the declaration was accepted")
				}
			}()
			declare(srv)
		})
	}

	// And the shapes that are sound: one to four letters after "agy".
	for _, prefix := range []string{"agyx_", "agyxy_", "agyxyz_", "agyxyzw_"} {
		cfg := config.Default()
		cfg.DevMode = true
		srv := api.New(cfg, nil, nil)
		srv.RegisterExtension("meter", func(*http.ServeMux) {})
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("prefix %q was refused: %v", prefix, r)
				}
			}()
			srv.SetExtensionTokens("meter", prefix, resolve)
		}()
	}
}

// TestExtensionRegistrationRefusesABadDeclaration: an extension's name is a
// lowercase letter and up to 31 lowercase letters, digits and hyphens, and
// serves one mount; the routes it leaves out of the anonymous rate class are
// exact "METHOD /path" patterns of an extension that is mounted. Anything else
// panics at start-up, where it is found.
func TestExtensionRegistrationRefusesABadDeclaration(t *testing.T) {
	routes := func(*http.ServeMux) {}
	panics := func(f func(*api.Server)) (panicked bool) {
		cfg := config.Default()
		cfg.DevMode = true
		srv := api.New(cfg, nil, nil)
		defer func() { panicked = recover() != nil }()
		f(srv)
		return false
	}
	register := func(name string) func(*api.Server) {
		return func(s *api.Server) { s.RegisterExtension(name, routes) }
	}
	unthrottle := func(extension string, routes ...string) func(*api.Server) {
		return func(s *api.Server) {
			s.RegisterExtension("meter", func(*http.ServeMux) {})
			s.SetExtensionUnthrottled(extension, routes)
		}
	}
	refused := map[string]func(*api.Server){
		"an uppercase name":        register("Meter"),
		"an empty name":            register(""),
		"a leading digit":          register("1meter"),
		"a leading hyphen":         register("-meter"),
		"an underscore":            register("me_ter"),
		"a slash":                  register("me/ter"),
		"a name of 33 characters":  register("m" + strings.Repeat("a", 32)),
		"a name registered twice":  func(s *api.Server) { s.RegisterExtension("meter", routes); s.RegisterExtension("meter", routes) },
		"a route with no method":   unthrottle("meter", "/webhooks/pay"),
		"a method in lowercase":    unthrottle("meter", "post /webhooks/pay"),
		"text before the method":   unthrottle("meter", "XPOST /webhooks/pay"),
		"a method that is no verb": unthrottle("meter", "OPTIONS /webhooks/pay"),
		"a route with no slash":    unthrottle("meter", "POST webhooks"),
		"a wildcard":               unthrottle("meter", "POST /webhooks/{id}"),
		"a query":                  unthrottle("meter", "POST /webhooks?x=1"),
		"a space in the path":      unthrottle("meter", "POST /web hooks"),
		"a route among good ones":  unthrottle("meter", "POST /webhooks/pay", "GET status"),
		"an unregistered mount":    unthrottle("nobody", "POST /webhooks/pay"),
	}
	for name, f := range refused {
		if !panics(f) {
			t.Errorf("%s: the declaration was accepted", name)
		}
	}
	accepted := map[string]func(*api.Server){
		"a name of 32 characters": register("m" + strings.Repeat("a", 31)),
		"digits and hyphens":      register("m-2-x"),
		"two extensions":          func(s *api.Server) { s.RegisterExtension("meter", routes); s.RegisterExtension("other", routes) },
		"exact routes":            unthrottle("meter", "POST /webhooks/pay", "DELETE /a/b-c_d.e", "GET /"),
		"no routes":               unthrottle("meter"),
	}
	for name, f := range accepted {
		if panics(f) {
			t.Errorf("%s: a sound declaration was refused", name)
		}
	}
}
