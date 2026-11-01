package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// GET …/versions/{v}/events streams status snapshots until the version
// reaches a terminal state.
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
	// Nothing along the way may keep or buffer it.
	if cc, buf := res.Header.Get("Cache-Control"), res.Header.Get("X-Accel-Buffering"); cc != "no-store" || buf != "no" {
		t.Fatalf("stream headers: Cache-Control %q, X-Accel-Buffering %q, want no-store and no", cc, buf)
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
	if !sort.StringsAreSorted(last.Stages) {
		t.Fatalf("the stages run are not listed in order: %v", last.Stages)
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

	// The stream ends at a state that only a person or the platform moves
	// the version out of, and carries the reason it was given; a version
	// still in the pipeline keeps it open.
	// A version cannot go back to submitted, so that one is recorded as such.
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source, status, status_reason)
		 SELECT gen_random_uuid(), a.id, '2.0.0', '{}', '{}', 'stable', h.id, 'cli-upload', 'submitted', 'reason for submitted'
		 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'streamed'`, user); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status  string
		version string
		done    bool
	}{
		{"submitted", "2.0.0", false}, {"scanning", "1.0.0", false},
		{"published", "1.0.0", true}, {"rejected", "1.0.0", true}, {"needs_review", "1.0.0", true},
		{"quarantined", "1.0.0", true}, {"yanked", "1.0.0", true}, {"blocked", "1.0.0", true},
	} {
		reason := "reason for " + tc.status
		if tc.version == "1.0.0" {
			if _, err := env.st.Pool().Exec(context.Background(),
				`UPDATE agent_versions av SET status = $2, status_reason = $3 FROM agents a JOIN handles h ON h.id = a.namespace_id
				 WHERE av.agent_id = a.id AND h.handle = $1 AND a.name = 'streamed' AND av.version = '1.0.0'`, user, tc.status, reason); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, env.srv.URL+"/api/v1/agents/"+user+"/streamed/versions/"+tc.version+"/events", nil)
		res, err := client.Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var first struct {
			Status       string  `json:"status"`
			StatusReason *string `json:"statusReason"`
			Done         bool    `json:"done"`
		}
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &first); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		_ = res.Body.Close()
		cancel()
		if first.Status != tc.status || first.Done != tc.done || first.StatusReason == nil || *first.StatusReason != reason {
			t.Fatalf("a version %s: first event %+v, want that status, done %v and the reason %q", tc.status, first, tc.done, reason)
		}
	}

	// A private agent's progress is not a stranger's to watch: the stream
	// of a version they cannot read is the missing name's 404.
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "hushed", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	stranger := env.login(env.register("sse-str"))
	for _, c := range []caller{stranger, anonymous} {
		res := env.do(c, http.MethodGet, "/api/v1/agents/"+user+"/hushed/versions/1.0.0/events", nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("the stream of a private agent's version for %s: %d, want 404", c.name, res.StatusCode)
		}
	}
}
