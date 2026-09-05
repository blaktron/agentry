package api_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// GET …/versions/{v}/events streams status snapshots until the version
// reaches a terminal state (agentry#65).
func TestVersionEventsStream(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("sse-owner")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "streamed", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	files := map[string]string{
		"agent.yaml": skillYAML(user, "streamed", "1.0.0"),
		"README.md":  "# streamed\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
	if status, body := env.uploadVersionCLI(user, "streamed", pat, files); status != http.StatusAccepted {
		t.Fatalf("upload: %d %s", status, body)
	}

	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/agents/"+user+"/streamed/versions/1.0.0/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	client := *env.srv.Client()
	client.Timeout = 60 * time.Second
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	var last struct {
		Status string   `json:"status"`
		Stages []string `json:"stages"`
		Done   bool     `json:"done"`
	}
	events := 0
	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &last); err != nil {
			continue
		}
		events++
		if last.Done {
			break
		}
	}
	if !last.Done || events == 0 {
		t.Fatalf("stream did not reach a terminal snapshot: events=%d last=%+v", events, last)
	}
	if last.Status == "scanning" || last.Status == "submitted" || len(last.Stages) == 0 {
		t.Fatalf("terminal snapshot must carry the outcome and the stages run: %+v", last)
	}

	// An unknown version ends the stream with a gone event rather than hanging.
	req2, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/agents/"+user+"/streamed/versions/9.9.9/events", nil)
	res2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 64)
	n, _ := res2.Body.Read(body)
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusOK || !strings.Contains(string(body[:n]), "event: gone") {
		t.Fatalf("unknown version: %d %q", res2.StatusCode, body[:n])
	}
}
