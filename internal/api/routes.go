package api

import (
	"net/http"

	"github.com/blaktron/agentry/internal/httpmux"
)

// recordingMux records every pattern it is handed and registers it
// underneath. The recording is what the completeness gate reads: a mount
// added tomorrow is in it whether or not its author declared anything,
// which is the point — the OpenAPI spec does not mention the root mounts.
//
// Registration is single-threaded: it all happens inside NewHandlerWithGit,
// before the handler serves a request, so the list needs no lock.
type recordingMux struct {
	*http.ServeMux
	patterns []string
}

func newRecordingMux() *recordingMux { return &recordingMux{ServeMux: http.NewServeMux()} }

func (m *recordingMux) Handle(pattern string, handler http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, handler)
}

func (m *recordingMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, handler)
}

// recorded returns the patterns in registration order.
func (m *recordingMux) recorded() []string { return append([]string(nil), m.patterns...) }

// Mount registers one root mount under the declaration authz_routes.go
// carries for its pattern. A pattern with no declaration panics at start-up:
// the completeness gate fails in CI first, and this catches a mount no test
// fixture ever builds — including on the `git` role's own mux, which no
// recorder sees.
func Mount(mux httpmux.Mux, pattern string, handler http.Handler) {
	if _, ok := MountAuthzDecl(pattern); !ok {
		panic("api: the root mount " + pattern + " has no declaration in authz_routes.go")
	}
	mux.Handle(pattern, handler)
}

// MountFunc is Mount for a bare handler function.
func MountFunc(mux httpmux.Mux, pattern string, handler func(http.ResponseWriter, *http.Request)) {
	Mount(mux, pattern, http.HandlerFunc(handler))
}
