package api

// Shared request-parameter handling for the §9.1 conventions: limit/offset
// clamping, opaque keyset cursors, and RFC 8288 Link headers. Every list
// endpoint goes through these so the pagination contract cannot drift
// per-handler (the same reason problem.go owns every error response).

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// clampLimit resolves a ?limit= into the endpoint's bounds.
//
// §9.1 says limits are clamped, not policed: a client asking for 1,000 rows
// gets the maximum page, and a negative or zero value gets the default. This
// replaces the "reject with 422" and — worse — the "pass it straight to
// LIMIT/OFFSET and 500 on a negative value" patterns the audit found.
func clampLimit(v *int, def, max int) int {
	if v == nil {
		return def
	}
	switch {
	case *v < 1:
		return def
	case *v > max:
		return max
	default:
		return *v
	}
}

// clampOffset resolves a ?offset= to a non-negative value bounded by max.
func clampOffset(v *int, max int) int {
	if v == nil || *v < 0 {
		return 0
	}
	if *v > max {
		return max
	}
	return *v
}

// maxListOffset bounds deep offset paging (cursor endpoints are unbounded;
// offset paging past this is a crawler, not a reader).
const maxListOffset = 10000

// ---- Opaque keyset cursors ----

// encodeCursor renders a (timestamp, uuid) keyset position as an opaque
// string. It is deliberately not a page number: rows inserted at the head
// between requests must not shift a reader's window.
func encodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

// decodeCursor parses a cursor produced by encodeCursor.
func decodeCursor(s string) (time.Time, uuid.UUID, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, false
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	return t, id, true
}

// cursorParams reads a ?cursor= into the (before_time, before_id) pair the
// keyset queries take. It reports false (after writing a problem) when the
// cursor is present but unreadable — silently ignoring a corrupt cursor would
// restart the caller at page one without telling them.
func cursorParams(w http.ResponseWriter, r *http.Request, cursor *string) (*time.Time, *uuid.UUID, bool) {
	if cursor == nil || *cursor == "" {
		return nil, nil, true
	}
	t, id, ok := decodeCursor(*cursor)
	if !ok {
		problemValidation(w, r, "invalid cursor")
		return nil, nil, false
	}
	return &t, &id, true
}

// setNextLink writes the RFC 8288 `Link: <…>; rel="next"` header for a
// cursor-paged response, preserving the request's other query parameters so
// filters survive paging.
func setNextLink(w http.ResponseWriter, r *http.Request, cursor string) {
	if cursor == "" {
		return
	}
	next := *r.URL
	q := next.Query()
	q.Set("cursor", cursor)
	next.RawQuery = q.Encode()
	// Path-relative: the API is served behind proxies that rewrite the host,
	// and a relative Link target is resolved against the request URI.
	w.Header().Add("Link", "<"+escapeLinkTarget(next.RequestURI())+`>; rel="next"`)
}

// escapeLinkTarget keeps a URI safe to embed between angle brackets.
func escapeLinkTarget(s string) string {
	s = strings.ReplaceAll(s, "<", url.QueryEscape("<"))
	return strings.ReplaceAll(s, ">", url.QueryEscape(">"))
}
