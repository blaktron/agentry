package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Version progress as server-sent events. The pipeline persists per stage, so
// progress is a read of what is already durable: no new state, no
// coupling to the worker — the stream is a poll the server does on the
// client's behalf, which also means a disconnected client loses nothing.
const (
	versionEventsTick    = time.Second
	versionEventsMaxLife = 5 * time.Minute
)

type versionEvent struct {
	Version      string   `json:"version"`
	Status       string   `json:"status"`
	StatusReason *string  `json:"statusReason,omitempty"`
	Stages       []string `json:"stages"`
	Done         bool     `json:"done"`
}

func versionIsTerminal(status string) bool {
	switch status {
	case "published", "rejected", "needs_review", "quarantined", "yanked", "blocked":
		return true
	}
	return false
}

// StreamVersionEvents implements GET /agents/{ns}/{name}/versions/{version}/events.
func (s *Server) StreamVersionEvents(w http.ResponseWriter, r *http.Request, ns Namespace, name AgentName, version VersionString) {
	if !s.requireDB(w, r) {
		return
	}
	a, _, ok := s.resolveAgentForAction(w, r, ns, name, auth.ActAgentRead)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // the edge must not buffer the stream
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil && errors.Is(err, http.ErrNotSupported) {
		// No streaming through this writer: send one snapshot and stop.
		if ev, found := s.versionEventSnapshot(r, a.ID, version); found {
			payload, _ := json.Marshal(ev)
			_, _ = w.Write([]byte("event: status\ndata: "))
			_, _ = w.Write(payload)
			_, _ = w.Write([]byte("\n\n"))
		}
		return
	}

	deadline := time.NewTimer(versionEventsMaxLife)
	defer deadline.Stop()
	tick := time.NewTicker(versionEventsTick)
	defer tick.Stop()
	last := ""
	for {
		ev, found := s.versionEventSnapshot(r, a.ID, version)
		if !found {
			_, _ = w.Write([]byte("event: gone\ndata: {}\n\n"))
			_ = rc.Flush()
			return
		}
		if payload, _ := json.Marshal(ev); string(payload) != last {
			last = string(payload)
			_, _ = w.Write([]byte("event: status\ndata: "))
			_, _ = w.Write(payload)
			_, _ = w.Write([]byte("\n\n"))
			_ = rc.Flush()
		}
		if ev.Done {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			_, _ = w.Write([]byte("event: timeout\ndata: {}\n\n"))
			_ = rc.Flush()
			return
		case <-tick.C:
		}
	}
}

// versionEventSnapshot reads the version and its latest run's completed
// stages. A version row that is gone ends the stream.
func (s *Server) versionEventSnapshot(r *http.Request, agentID [16]byte, version string) (versionEvent, bool) {
	q := s.q()
	v, err := q.GetVersion(r.Context(), storegen.GetVersionParams{AgentID: agentID, Version: version})
	if err != nil {
		return versionEvent{}, false
	}
	ev := versionEvent{Version: v.Version, Status: v.Status, StatusReason: v.StatusReason, Stages: []string{}}
	if run, err := q.LatestScanRunForVersion(r.Context(), v.ID); err == nil {
		if rows, err := q.ListStageResults(r.Context(), run.ID); err == nil {
			for _, st := range rows {
				ev.Stages = append(ev.Stages, st.Scanner)
			}
			sort.Strings(ev.Stages)
		}
	}
	ev.Done = versionIsTerminal(v.Status)
	return ev, true
}
