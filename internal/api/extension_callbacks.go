package api

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/blaktron/agentry/internal/httpmux"
)

// Extension callbacks: the mount an extension serves calls from a service
// of its own on, such as a directory's sign-in flow asking whether a
// browser is remembered. The caller is infrastructure holding a shared
// secret, never a person, so the routes sit outside /api/ under
// /internal/x/<name>/, where no edge shipped with the registry routes, and
// pass no principal middleware: a handler reads no Principal, and acts on
// nothing but what its request names.
//
// The core holds the gate, so an extension cannot open it wider:
//
//   - a request carrying a proxy's forwarding header (X-Forwarded-For or
//     Forwarded) came through an edge or an ingress and is answered 404,
//     the right secret or not;
//   - with no secret configured the whole mount answers 404, as though it
//     did not exist;
//   - the rate class the extension declared is spent, wrong secret or not;
//   - every request must present the secret as a bearer token, compared in
//     constant time, or is answered 401.

// extensionCallbackPrefix is where every extension's callback mount sits.
const extensionCallbackPrefix = "/internal/x/"

// GateExtensionSecret is gated by the shared secret an extension's
// callback mount declares, and absent (404) while that is unset or the
// request came through a proxy.
const GateExtensionSecret MountGate = "extension-secret"

// minCallbackSecret is the shortest secret a callback mount accepts, the
// length auth.idpTrustCheckToken is held to.
const minCallbackSecret = 32

// ExtensionCallbacks is an extension's callback mount.
type ExtensionCallbacks struct {
	// Secret is the bearer secret every caller presents. Empty switches the
	// mount off: every route answers 404. Set, it is at least 32
	// characters.
	Secret string
	// Class is the rate-limit bucket the core applies before the handler:
	// "anon", the anonymous bucket per client address, or RateNone for a
	// caller that speaks for everyone signing in and must never be
	// throttled as one address.
	Class string
	// Why says what bounds the mount's use, which the route declaration
	// records. Required.
	Why string
	// Routes registers the handlers on a mux rooted at the mount
	// ("POST /trusted-device" is /internal/x/<name>/trusted-device).
	Routes func(mux *http.ServeMux)
}

type extensionCallbackMount struct {
	name string
	cb   ExtensionCallbacks
}

// RegisterExtensionCallbacks mounts an extension's callbacks under
// /internal/x/<name>/ when the handler is built. A malformed name or
// class, a missing reason, a short secret or a second registration
// under one name panics at start-up, where it is found.
func (s *Server) RegisterExtensionCallbacks(name string, cb ExtensionCallbacks) {
	if !reExtensionName.MatchString(name) {
		panic("api: extension name must match " + reExtensionName.String() + ": " + name)
	}
	if cb.Routes == nil {
		panic("api: extension " + name + ": a callback mount needs routes")
	}
	if cb.Class != RateAnon && cb.Class != RateNone {
		panic("api: extension " + name + ": a callback mount draws from \"" + RateAnon + "\" or \"" + RateNone + "\", not " + cb.Class)
	}
	if strings.TrimSpace(cb.Why) == "" {
		panic("api: extension " + name + ": a callback mount says what bounds its use")
	}
	if cb.Secret != "" && len(cb.Secret) < minCallbackSecret {
		panic("api: extension " + name + ": a callback secret is at least 32 characters")
	}
	for _, m := range s.extensionCallbacks {
		if m.name == name {
			panic("api: extension callbacks registered twice: " + name)
		}
	}
	s.extensionCallbacks = append(s.extensionCallbacks, extensionCallbackMount{name: name, cb: cb})
}

func (s *Server) mountExtensionCallbacks(mux httpmux.Mux) {
	for _, m := range s.extensionCallbacks {
		sub := http.NewServeMux()
		m.cb.Routes(sub)
		prefix := extensionCallbackPrefix + m.name
		// Not Mount: the names are the extensions', so no entry in
		// authz_routes.go can list them. The server's own declaration of
		// each mount (MountAuthzDecl) is what the completeness gate reads.
		mux.Handle(prefix+"/", s.extensionCallbackGate(m.cb, http.StripPrefix(prefix, sub)))
	}
}

func (s *Server) extensionCallbackGate(cb ExtensionCallbacks, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cb.Secret == "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
			http.NotFound(w, r)
			return
		}
		// The class is spent before the secret is read, so it bounds the
		// guesses at the secret as well as the calls that present it.
		if cb.Class == RateAnon {
			res := s.limits.Allow(RateAnon, clientIP(r), s.classes.anon, s.classes.anonBurst)
			writeRateLimitHeaders(w, res)
			if !res.OK {
				s.rateLimited(r, RateAnon)
				problemTooMany(w, r, "This caller has used up its rate limit. Wait for the Retry-After interval.")
				return
			}
		}
		given, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(given), []byte(cb.Secret)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MountAuthzDecl is the declaration of a pattern this server's mux was
// given: the core's own table (the package-level MountAuthzDecl), then the
// callback mounts its extensions registered, each declared as the
// extension declared it.
func (s *Server) MountAuthzDecl(pattern string) (MountDecl, bool) {
	if d, ok := MountAuthzDecl(pattern); ok {
		return d, true
	}
	for _, m := range s.extensionCallbacks {
		if pattern == extensionCallbackPrefix+m.name+"/" {
			return MountDecl{Gate: GateExtensionSecret, Class: m.cb.Class, Why: m.cb.Why}, true
		}
	}
	return MountDecl{}, false
}
