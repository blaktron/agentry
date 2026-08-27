package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// SearchAgents implements GET /search (§10.4, D-20): Postgres FTS over public
// agents with kind facets. Blocked agents never appear.
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
	limit := 25
	if params.Limit != nil {
		limit = *params.Limit
	}
	offset := 0
	if params.Offset != nil {
		offset = *params.Offset
	}

	qp := storegen.SearchAgentsParams{Query: query, Limit: int32(limit), Offset: int32(offset)}
	if params.Kind != nil {
		k := string(*params.Kind)
		qp.Kind = &k
	}
	rows, err := s.q().SearchAgents(r.Context(), qp)
	if err != nil {
		s.log.Error("search", "err", err)
		problemInternal(w, r)
		return
	}
	hits := make([]SearchHit, 0, len(rows))
	for _, row := range rows {
		installs := int(row.Installs)
		qs := SearchHitQuarantineState(row.QuarantineState)
		hits = append(hits, SearchHit{
			Namespace: row.Namespace, Name: row.Name, Kind: AgentKind(row.Kind),
			Summary: row.Summary, Installs30d: &installs, QuarantineState: &qs,
		})
	}

	facets := map[string]map[string]int{}
	if frows, err := s.q().SearchFacetKinds(r.Context(), query); err == nil {
		kinds := map[string]int{}
		for _, f := range frows {
			kinds[f.Kind] = int(f.N)
		}
		facets["kind"] = kinds
	}

	writeJSON(w, http.StatusOK, SearchResults{Results: hits, Facets: &facets})
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
		s.log.Error("readme render", "err", err)
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

func writeHTMLFragment(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(html))
}
