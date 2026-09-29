package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

const (
	searchDefaultLimit = 25
	searchMaxLimit     = 100
)

// SearchAgents implements GET /search (§10.4, D-20): Postgres FTS over public
// agents with the §9.2 facets — kind, capability, license, verified — and a
// sort selector. capability/license read the LATEST PUBLISHED version, so a
// filter always describes what someone would install today. Blocked agents
// never appear.
func (s *Server) SearchAgents(w http.ResponseWriter, r *http.Request, params SearchAgentsParams) {
	if !s.authorize(w, r, auth.ActPublicRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	query := ""
	if params.Q != nil {
		query = strings.TrimSpace(*params.Q)
	}
	// §9.1: out-of-range paging parameters are clamped, not rejected. A
	// negative limit used to reach LIMIT/OFFSET verbatim and 500.
	limit := clampLimit(params.Limit, searchDefaultLimit, searchMaxLimit)
	offset := clampOffset(params.Offset)

	sort := "relevance"
	if params.Sort != nil && *params.Sort != "" {
		sort = string(*params.Sort)
	}
	qp := storegen.SearchAgentsParams{
		Query: query, Limit: int32(limit), Offset: int32(offset), Sort: sort,
	}
	if params.Mode != nil {
		m := string(*params.Mode)
		qp.Mode = &m
	}
	if params.Capability != nil {
		if c := strings.TrimSpace(*params.Capability); c != "" {
			qp.Capability = &c
		}
	}
	if params.License != nil {
		if l := strings.TrimSpace(*params.License); l != "" {
			qp.License = &l
		}
	}
	if params.Verified != nil {
		qp.VerifiedOnly = *params.Verified
	}
	rows, err := s.q().SearchAgents(r.Context(), qp)
	if err != nil {
		s.log.ErrorContext(r.Context(), "search", "err", err)
		problemInternal(w, r)
		return
	}
	// total is the hit count for the same predicate before paging
	// (agentry#290): without it every client that printed the count said
	// "0 results" above a full list.
	n, err := s.q().CountSearchAgents(r.Context(), storegen.CountSearchAgentsParams{
		Query: qp.Query, Mode: qp.Mode, Capability: qp.Capability, License: qp.License, VerifiedOnly: qp.VerifiedOnly,
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "search: count", "err", err)
		problemInternal(w, r)
		return
	}
	total := int(n)
	hits := make([]SearchHit, 0, len(rows))
	for _, row := range rows {
		installs := int(row.Installs)
		qs := SearchHitQuarantineState(row.QuarantineState)
		hit := SearchHit{
			Namespace: row.Namespace, Name: row.Name, Modes: apiModes(row.Modes),
			Summary: row.Summary, Installs30d: &installs, QuarantineState: &qs, Builtin: row.Builtin,
		}
		if u := logoURL(row.Namespace, row.LogoObjectKey); u != "" {
			hit.LogoUrl = &u
		}
		hits = append(hits, hit)
	}

	// Facet counts describe the unfiltered corpus for this query, so the UI
	// can show "12 MIT, 3 Apache-2.0" alongside an active license filter
	// rather than only the count of what is already selected.
	facets := map[string]map[string]int{}
	// The run-mode facet (DEV-088) replaced the kind facet in 0.3.0.
	if mrows, err := s.q().SearchFacetModes(r.Context(), query); err == nil && len(mrows) > 0 {
		modes := map[string]int{}
		for _, f := range mrows {
			modes[f.Mode] = int(f.N)
		}
		facets["mode"] = modes
	}
	if lrows, err := s.q().SearchFacetLicenses(r.Context(), query); err == nil && len(lrows) > 0 {
		licenses := map[string]int{}
		for _, f := range lrows {
			licenses[f.License] = int(f.N)
		}
		facets["license"] = licenses
	}

	writeJSON(w, http.StatusOK, SearchResults{Results: hits, Facets: &facets, Total: &total})
}

// GetAgentReadme implements GET /agents/{ns}/{name}/readme (§10.3): the
// README of a published version, rendered server-side through the strict
// sanitizer. The web app never parses user markdown client-side (D-11).
func (s *Server) GetAgentReadme(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, params GetAgentReadmeParams) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}

	// Pick the version: explicit param, else latest published.
	var v registry.Version
	if params.Version != nil && *params.Version != "" {
		row, err := s.q().GetVersion(r.Context(), storegen.GetVersionParams{AgentID: a.ID, Version: *params.Version})
		if err != nil {
			problemNotFound(w, r)
			return
		}
		v = row
	} else {
		if a.LatestPublishedVersionID == nil {
			writeHTMLFragment(w, "")
			return
		}
		row, err := s.q().GetVersionByID(r.Context(), *a.LatestPublishedVersionID)
		if err != nil {
			problemNotFound(w, r)
			return
		}
		v = row
	}
	if v.ArchiveKey == nil || s.blobs == nil {
		writeHTMLFragment(w, "")
		return
	}

	md, err := s.readmeFromArchive(r, *v.ArchiveKey, v.ArchiveSize)
	if err != nil {
		if errors.Is(err, errNoReadme) {
			writeHTMLFragment(w, "")
			return
		}
		s.log.ErrorContext(r.Context(), "readme render", "err", err)
		problemInternal(w, r)
		return
	}
	out, err := s.renderer.Markdown(md)
	if err != nil {
		problemInternal(w, r)
		return
	}
	if a.Visibility == "public" {
		w.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	writeHTMLFragment(w, out)
}

// inertDocumentCSP is the policy on every response of this origin a
// browser might render as a document but never should: nothing loads,
// nothing runs, sandboxed. The image proxy and the README fragment share
// it.
const inertDocumentCSP = "default-src 'none'; sandbox"

// writeHTMLFragment serves rendered markdown for a page to embed. It is
// text/html on the API origin, where the session cookie lives, so it
// carries inertDocumentCSP: a browser that renders it directly gets a
// document that can do nothing, whatever the sanitiser let through
// (agentry#413). The site embeds the body server-side and never sees the
// header.
func writeHTMLFragment(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", inertDocumentCSP)
	_, _ = w.Write([]byte(html))
}
