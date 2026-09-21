// Package httpmux names the one thing a package that registers HTTP routes
// and a package that serves them must agree on: what a mux is. It exists
// because internal/api cannot import internal/gitsrv — gitsrv's own
// in-package test builds an api.Server, so the import would be a cycle in
// the test build — and the api role registers gitsrv's routes on a mux that
// records what it was given (agentry#415).
package httpmux

import "net/http"

// Mux is what a mount registers on. An *http.ServeMux is one; so is a
// recorder that keeps every pattern it was handed, which is how the
// authorization completeness gate sees the routes that are not part of the
// generated OpenAPI surface.
type Mux interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}
