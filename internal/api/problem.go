// RFC 9457 problem+json helpers (D-10). Every non-2xx response the API emits
// goes through this file so the error contract can't drift per-handler.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blaktron/agentry/internal/registry"
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
	writeProblemWith(w, r, status, slug, title, detail, nil, fields...)
}

// writeProblemWith is writeProblem with RFC 9457 extension members: ext's
// keys land at the top level of the body beside the standard ones (an
// admission refusal's balance and reset date, say), so a client can render
// its own sentence without parsing detail. Standard members win a
// collision.
func writeProblemWith(w http.ResponseWriter, r *http.Request, status int, slug, title, detail string, ext map[string]any, fields ...FieldError) {
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
	var out any = body
	if len(ext) > 0 {
		m := make(map[string]any, len(ext)+6)
		for k, v := range ext {
			m[k] = v
		}
		raw, err := json.Marshal(body)
		if err == nil {
			var std map[string]any
			if json.Unmarshal(raw, &std) == nil {
				for k, v := range std {
					m[k] = v
				}
				out = m
			}
		}
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		slog.Warn("problem encode failed", "err", err)
	}
}

// sentence renders an error's text as a problem detail. Go errors are
// lowercase fragments and never end in punctuation (ST1005), while a detail
// is read verbatim as a sentence by the site's flash, the core's pages and
// the CLI — so the two registers meet here, at the API boundary, rather than
// in the packages that raise the error. It strips the domain sentinel's own
// prefix (ErrDenied wraps its reason, so the reader would otherwise see
// "registry: denied: …"), upper-cases the first rune, and ends the sentence.
// An empty message stays empty: problemNotFound and problemInternal say
// nothing on purpose.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if rest, cut := strings.CutPrefix(s, registry.ErrDenied.Error()); cut {
		s = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	}
	if s == "" {
		return ""
	}
	if r, size := utf8.DecodeRuneInString(s); unicode.ToUpper(r) != r {
		s = string(unicode.ToUpper(r)) + s[size:]
	}
	switch {
	case strings.HasSuffix(s, "."), strings.HasSuffix(s, "!"), strings.HasSuffix(s, "?"):
		return s
	}
	return s + "."
}

// Common problem writers. Add new slugs here, not inline in handlers.

func problemInternal(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusInternalServerError, "internal", "Internal server error", "")
}

func problemNotFound(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusNotFound, "not-found", "Not found", "")
}

func problemValidation(w http.ResponseWriter, r *http.Request, detail string, fields ...FieldError) {
	writeProblem(w, r, http.StatusUnprocessableEntity, "validation", "Validation error", detail, fields...)
}

func problemBadRequest(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusBadRequest, "bad-request", "Bad request", detail)
}

func problemUnauthorized(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", detail)
}

func problemForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusForbidden, "forbidden", "Access denied", detail)
}

func problemConflict(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", detail)
}

func problemTooMany(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusTooManyRequests, "rate-limited", "Too many requests", detail)
}

func problemGone(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusGone, "gone", "No longer available", detail)
}

// problemAdmissionRefused answers a registry admission refusal (plan
// subscription-tiers §5.1) with the refusal's own status and slug — 402
// credits-exhausted from the billing extension, which says so explicitly —
// and its fields at top level. A refusal that names no status is a 403
// admission-refused: "payment required" is a claim an extension makes,
// never a default.
func problemAdmissionRefused(w http.ResponseWriter, r *http.Request, ref registry.Refusal) {
	status, slug, title := ref.Status, ref.Slug, ref.Title
	if status == 0 {
		status = http.StatusForbidden
	}
	if slug == "" {
		slug = "admission-refused"
	}
	if title == "" {
		title = "Submission refused"
	}
	writeProblemWith(w, r, status, slug, title, sentence(ref.Detail), ref.Fields)
}

// problemPrivateAgentCap answers the namespace's private-agent cap (plan
// subscription-tiers §5.3): a 422 with its own slug, so a client can offer
// the upgrade rather than a generic validation message.
func problemPrivateAgentCap(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusUnprocessableEntity, "private-agent-cap",
		"Private agent cap reached",
		"This namespace holds as many private agents as its subscription tier allows. Make one public, or upgrade the account.")
}

func problemUnavailable(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusServiceUnavailable, "unavailable", "Service unavailable", detail)
}
