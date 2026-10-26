package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The catalog events a registry action emits:
// agent.created, version.submitted, scan.completed, policy.updated. Each
// lands a delivery row for a subscribed org endpoint.
func TestWebhookCatalogEventsAreEmitted(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("wc-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "wcorg" + env.sfx
	env.createOrg(sess, orgH)

	var hook struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url":    "https://example.invalid/hook",
		"events": []string{"agent.created", "version.submitted", "scan.completed", "policy.updated"},
	}, &hook, http.StatusCreated)

	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "hooked", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/policy", map[string]any{"requireEvals": false}, nil, http.StatusOK)

	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	files := map[string]string{
		"agent.yaml": skillYAML(orgH, "hooked", "1.0.0"),
		"README.md":  "# hooked\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
	if status, body := env.uploadVersionCLI(orgH, "hooked", pat, files); status != http.StatusAccepted {
		t.Fatalf("upload: %d %s", status, body)
	}
	// Any terminal outcome will do: scan.completed fires before the gate
	// decides, and the org's default policy may route to review.
	var status string
	for i := 0; i < 100; i++ {
		var v struct {
			Status string `json:"status"`
		}
		env.doJSON(sess, http.MethodGet, "/api/v1/agents/"+orgH+"/hooked/versions/1.0.0", nil, &v, http.StatusOK)
		status = v.Status
		if status != "submitted" && status != "scanning" && status != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status == "submitted" || status == "scanning" || status == "" {
		t.Fatalf("version did not finish scanning: %q", status)
	}

	var deliveries []struct {
		EventType string `json:"eventType"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+hook.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	got := map[string]bool{}
	for _, d := range deliveries {
		got[d.EventType] = true
	}
	for _, want := range []string{"agent.created", "version.submitted", "scan.completed", "policy.updated"} {
		if !got[want] {
			t.Errorf("%s delivery not recorded (have %v)", want, got)
		}
	}

	// Only what the endpoint subscribed to, once each, and what each tells
	// a consumer.
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT event_type, payload FROM webhook_deliveries WHERE endpoint_id = $1`, hook.Id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	data := map[string]map[string]any{}
	for rows.Next() {
		var ev string
		var raw []byte
		if err := rows.Scan(&ev, &raw); err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Event string         `json:"event"`
			Data  map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		if _, dup := data[ev]; dup {
			t.Errorf("%s was delivered twice", ev)
		}
		if wire.Event != ev {
			t.Errorf("a %s delivery carries the event %q", ev, wire.Event)
		}
		data[ev] = wire.Data
	}
	if len(data) != 4 {
		t.Errorf("deliveries by event = %v, want exactly the four subscribed to", data)
	}
	if d := data["agent.created"]; d["namespace"] != orgH || d["name"] != "hooked" || d["visibility"] != "private" || fmt.Sprint(d["modes"]) != "[autonomous]" || len(d) != 4 {
		t.Errorf("agent.created data = %v, want namespace %s, name hooked, modes [autonomous], visibility private", d, orgH)
	}
	if d := data["policy.updated"]; d["org"] != orgH || fmt.Sprint(d["keys"]) != "[requireEvals]" || len(d) != 2 {
		t.Errorf("policy.updated data = %v, want org %s and keys [requireEvals]", d, orgH)
	}
	if d := data["version.submitted"]; d["version"] != "1.0.0" || d["source"] != "cli-upload" || d["channel"] != "stable" || len(d) != 3 {
		t.Errorf("version.submitted data = %v, want version 1.0.0, source cli-upload, channel stable", d)
	}
	d := data["scan.completed"]
	vid, _ := d["versionId"].(string)
	rid, _ := d["runId"].(string)
	digest, _ := d["reportDigest"].(string)
	_, verr := uuid.Parse(vid)
	_, rerr := uuid.Parse(rid)
	if verr != nil || rerr != nil || d["version"] != "1.0.0" || d["outcome"] != "published" || !strings.HasPrefix(digest, "sha256:") ||
		d["reason"] == nil || d["reason"] == "" || d["findings"] == nil || len(d) != 7 {
		t.Errorf("scan.completed data = %v, want version 1.0.0 and its id and the run id as uuids, outcome published, a sha256 report digest, a reason and findings", d)
	}
}
