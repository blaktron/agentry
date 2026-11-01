package api_test

// The api and git roles hand a submitted version to the worker: they
// enqueue scan.version on the sandbox queue and never scan untrusted
// content themselves; the worker's handler runs the pipeline, gates and
// signs.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/scan"
)

func TestHandedOffPublishIsScannedByTheWorkerNotTheReceivingRole(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) { s.HandOffScans() })
	authorH := env.register("ho-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "handoff", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(author, "pub-handoff-"+env.sfx, "agent:publish", "agent:read")

	if code, body := env.uploadVersionCLI(authorH, "handoff", pat, skillFiles(authorH, "handoff", "1.0.0", nil)); code != http.StatusAccepted {
		t.Fatalf("publish: %d %s", code, body)
	}

	ctx := context.Background()
	var versionID string
	if err := env.st.Pool().QueryRow(ctx, `
		SELECT v.id::text FROM agent_versions v
		JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		WHERE a.name = 'handoff' AND h.handle = $1 AND v.version = '1.0.0'`, authorH).Scan(&versionID); err != nil {
		t.Fatalf("version row: %v", err)
	}
	status := func() string {
		var st string
		if err := env.st.Pool().QueryRow(ctx, `SELECT status FROM agent_versions WHERE id = $1`, versionID).Scan(&st); err != nil {
			t.Fatalf("status: %v", err)
		}
		return st
	}

	// The receiving role left the version in scanning, with one scan job
	// for the worker and no scan run of its own.
	if st := status(); st != "scanning" {
		t.Fatalf("after the request the version is %q, want scanning (the receiving role scanned it)", st)
	}
	var runs, jobs int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM scan_runs WHERE version_id = $1`, versionID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("the receiving role created %d scan run(s)", runs)
	}
	if err := env.st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM river_job
		WHERE kind = 'scan.version' AND queue = 'sandbox' AND args->>'trigger' = 'publish' AND args->>'versionId' = $1`, versionID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("scan.version jobs on the sandbox queue for the version = %d, want 1", jobs)
	}

	// The worker takes it to a verdict: the pipeline the api role built,
	// registered on a worker's queue client, as newWorkerQueue does.
	w := queue.NewRiverClient(env.st, nil)
	w.SetTestOnly(true)
	env.srvObj.Pipeline().RegisterHandlers(w)
	w.Drain(ctx, "sandbox")

	if st := status(); st != "published" {
		t.Fatalf("after the worker ran the version is %q, want published", st)
	}
	var att struct {
		PayloadType string `json:"payloadType"`
	}
	res := env.do(anonymous, http.MethodGet, "/api/v1/agents/"+authorH+"/handoff/versions/1.0.0/attestation", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("attestation after the worker published: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&att); err != nil || att.PayloadType == "" {
		t.Fatalf("attestation body: %v %+v", err, att)
	}

	// Delivery is at-least-once: the same job arriving after the version
	// was published is a no-op — no second run, no review item, still one
	// attestation, still published.
	if _, err := w.Enqueue(ctx, scan.JobScanVersion, "sandbox",
		scan.ScanJobArgs{VersionID: uuid.MustParse(versionID), Trigger: "publish"}); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	w.Drain(ctx, "sandbox")
	var items, atts int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM scan_runs WHERE version_id = $1`, versionID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM review_items WHERE version_id = $1`, versionID).Scan(&items); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM attestations WHERE version_id = $1`, versionID).Scan(&atts); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || items != 0 || atts != 1 || status() != "published" {
		t.Fatalf("after a redelivered publish scan: runs=%d review items=%d attestations=%d status=%s, want 1/0/1/published",
			runs, items, atts, status())
	}

	// A queue that cannot take the job leaves the recorded version in
	// scanning, says so to the submitter, and queues nothing: the scan
	// watchdog owns it from there.
	env.srvObj.Reg().SetPipeline(scan.QueuePipeline{Q: downQueue{}})
	code, body := env.uploadVersionCLI(authorH, "handoff", pat, skillFiles(authorH, "handoff", "1.0.1", nil))
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "scan-not-scheduled") {
		t.Fatalf("publish while the queue is down: %d %s, want 503 scan-not-scheduled", code, body)
	}
	var stuck string
	if err := env.st.Pool().QueryRow(ctx, `
		SELECT v.status FROM agent_versions v
		JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		WHERE a.name = 'handoff' AND h.handle = $1 AND v.version = '1.0.1'`, authorH).Scan(&stuck); err != nil {
		t.Fatalf("version row: %v", err)
	}
	if stuck != "scanning" {
		t.Fatalf("the version the queue could not take is %q, want scanning", stuck)
	}
	if err := env.st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM river_job
		WHERE kind = 'scan.version' AND args->>'versionId' IN (
		  SELECT v.id::text FROM agent_versions v
		  JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id
		  WHERE a.name = 'handoff' AND h.handle = $1 AND v.version = '1.0.1')`, authorH).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("%d scan.version jobs were queued for a version the queue refused", jobs)
	}
}

// downQueue is a queue that takes no job.
type downQueue struct{ queue.Client }

func (downQueue) Enqueue(context.Context, string, string, any, ...queue.EnqueueOption) (uuid.UUID, error) {
	return uuid.Nil, errors.New("the queue is unavailable")
}
