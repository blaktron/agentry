package api_test

import (
	"context"
	"maps"
	"net/http"
	"testing"
)

// A rescan in flight does not blank a published version's verdict:
// the report and the account install row describe
// the latest finished run and the report names the rescan beside it. A
// rescan that finishes in error is still the report's run: an error is
// never hidden behind the verdict before it.
func TestRescanInFlightKeepsThePublishedVerdict(t *testing.T) {
	env := newTestEnv(t)
	authorH := env.register("rr-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "steady", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, author, authorH, "steady", []versionFiles{
		{"1.0.0", installCapsFiles(authorH, "steady", "1.0.0", nil, nil)},
	})
	personH := env.register("rr-person")
	env.verifyEmail(personH)
	person := env.login(personH)
	ref := authorH + "/steady"
	if code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("install: %d %+v", code, prob)
	}

	type inFlight struct {
		ScanRunId string `json:"scanRunId"`
		StartedAt string `json:"startedAt"`
	}
	type report struct {
		ScanRunId      string         `json:"scanRunId"`
		ScanStatus     string         `json:"scanStatus"`
		Verdict        *string        `json:"verdict"`
		FinishedAt     *string        `json:"finishedAt"`
		FindingCounts  map[string]int `json:"findingCounts"`
		RescanInFlight *inFlight      `json:"rescanInFlight"`
	}
	reportPath := "/api/v1/agents/" + ref + "/versions/1.0.0/report"
	read := func() report {
		t.Helper()
		var rep report
		env.doJSON(anonymous, http.MethodGet, reportPath, nil, &rep, http.StatusOK)
		return rep
	}

	published := read()
	if deref(published.Verdict) != "scanned" || published.RescanInFlight != nil {
		t.Fatalf("before any rescan: %+v", published)
	}

	// The findings of the run are counted by severity, on the report and on
	// the install row alike.
	for severity, n := range map[string]int{"info": 1, "low": 2} {
		for i := 0; i < n; i++ {
			if _, err := env.st.Pool().Exec(context.Background(),
				`INSERT INTO findings (id, scan_run_id, scanner, severity, confidence, title) VALUES (gen_random_uuid(), $1, 'S0/counted', $2, 'high', 'counted')`,
				published.ScanRunId, severity); err != nil {
				t.Fatal(err)
			}
		}
	}
	wantCounts := map[string]int{"info": 1, "low": 2}
	if counted := read().FindingCounts; !maps.Equal(counted, wantCounts) {
		t.Fatalf("the report counts %v, want %v", counted, wantCounts)
	}
	if list := env.listInstalls(t, person); len(list) != 1 || !maps.Equal(list[0].FindingCounts, wantCounts) {
		t.Fatalf("the install row counts %+v, want %v", list, wantCounts)
	}

	// A sweep starts a rescan of the published version.
	ctx := context.Background()
	var rescan string
	if err := env.st.Pool().QueryRow(ctx, `
		INSERT INTO scan_runs (id, version_id, trigger, ruleset_release_id, policy_snapshot, status)
		SELECT gen_random_uuid(), version_id, 'rescan', ruleset_release_id, policy_snapshot, 'running'
		FROM scan_runs WHERE id = $1
		RETURNING id::text`, published.ScanRunId).Scan(&rescan); err != nil {
		t.Fatal(err)
	}

	during := read()
	if deref(during.Verdict) != "scanned" || during.ScanRunId != published.ScanRunId || during.ScanStatus != published.ScanStatus || during.FinishedAt == nil {
		t.Fatalf("during the rescan the report lost the published verdict: %+v", during)
	}
	if during.RescanInFlight == nil || during.RescanInFlight.ScanRunId != rescan || during.RescanInFlight.StartedAt == "" {
		t.Fatalf("the report does not name the rescan in flight %s: %+v", rescan, during.RescanInFlight)
	}
	if list := env.listInstalls(t, person); len(list) != 1 || deref(list[0].Verdict) != "scanned" || list[0].FindingCounts == nil {
		t.Fatalf("during the rescan the install row lost the verdict: %+v", list)
	}

	// The rescan ends in error: that run is the report now, with no verdict.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE scan_runs SET status = 'error', finished_at = now() WHERE id = $1`, rescan); err != nil {
		t.Fatal(err)
	}
	after := read()
	if after.ScanRunId != rescan || after.ScanStatus != "error" || after.Verdict != nil || after.RescanInFlight != nil {
		t.Fatalf("an errored rescan is hidden behind the earlier verdict: %+v", after)
	}
	if list := env.listInstalls(t, person); len(list) != 1 || list[0].Verdict != nil {
		t.Fatalf("the install row keeps a verdict over an errored rescan: %+v", list)
	}
}
