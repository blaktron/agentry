// RFC 9457 problem+json helpers (D-10). Every non-2xx response the API emits
// goes through this file so the error contract can't drift per-handler.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ProblemTypeBase prefixes stable problem type URIs. The domain is a
// placeholder per PLAN §0.8 / Q1.
const ProblemTypeBase = "https://agentry.dev/problems/"

// FieldError describes one field-level validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// problemBody is the wire shape; kept private so writers go through helpers.
type problemBody struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail,omitempty"`
	Instance string       `json:"instance,omitempty"`
	Errors   []FieldError `json:"errors,omitempty"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, slug, title, detail string, fields ...FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := problemBody{
		Type:     ProblemTypeBase + slug,
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
		Errors:   fields,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("problem encode failed", "err", err)
	}
}

// Common problem writers. Add new slugs here, not inline in handlers.

func problemInternal(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusInternalServerError, "internal", "Internal server error", "")
}

func problemNotFound(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusNotFound, "not-found", "Not found", "")
}

func problemValidation(w http.ResponseWriter, r *http.Request, detail string, fields ...FieldError) {
	writeProblem(w, r, http.StatusUnprocessableEntity, "validation", "Validation failed", detail, fields...)
}

func problemBadRequest(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusBadRequest, "bad-request", "Bad request", detail)
}

func problemUnauthorized(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", detail)
}

func problemForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", detail)
}

func problemConflict(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", detail)
}

func problemTooMany(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusTooManyRequests, "rate-limited", "Too many requests", detail)
}

func problemGone(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusGone, "gone", "Gone", detail)
}

func problemUnavailable(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusServiceUnavailable, "unavailable", "Service unavailable", detail)
}
