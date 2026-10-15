package api_test

import (
	"net/http"
	"testing"
	"time"
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
}
