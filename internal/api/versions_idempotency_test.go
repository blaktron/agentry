package api_test

// Idempotency-Key on POST /agents/{ns}/{name}/versions:
// a retried multipart upload — new boundary, same files — replays the 202
// instead of hitting V3 "version exists"; the same key with different files
// is a 409; and an archive over 1 MiB is accepted.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSubmitVersionIdempotencyReplay(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("idem-v")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "replay", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")

	// A body past 1 MiB once archived: bytes that do not compress away (the
	// archive builder refuses zip-bomb ratios, and hex text would shrink
	// under the line). It is an image, not text: the text files of a
	// package are capped at 1 MiB in total (V8), so a large README would be
	// refused before the replay under test.
	var sb strings.Builder
	sb.WriteString("\x89PNG\r\n\x1a\n")
	seed := sha256.Sum256([]byte("idempotency fixture"))
	for sb.Len() < 1400*1024 {
		seed = sha256.Sum256(seed[:])
		sb.Write(seed[:])
	}
	big := sb.String()
	files := map[string]string{
		"agent.yaml": strings.Replace(skillYAML(user, "replay", "1.0.0"),
			"include: [agent.yaml, README.md, SKILL.md, LICENSE]", "include: [agent.yaml, README.md, SKILL.md, LICENSE, logo.png]", 1),
		"README.md": "# replay\n",
		"logo.png":  big,
		"SKILL.md":  "Summarize politely and cite sources.\n",
		"LICENSE":   "Apache-2.0\n",
	}
	key := map[string]string{"Idempotency-Key": "publish-" + randSuffix()}

	status, body, firstHeader := env.uploadVersionCLIResult(user, "replay", pat, files, key, "", nil)
	if status != http.StatusAccepted {
		t.Fatalf("first upload: %d %s", status, body)
	}
	if firstHeader.Get("Idempotency-Replayed") != "" {
		t.Fatalf("the first answer is marked as a replay: %q", firstHeader.Get("Idempotency-Replayed"))
	}
	var first struct {
		Id string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &first)

	// A key outlives the purge of expired ones for as long as it is
	// replayable.
	if _, err := env.st.Queries().PurgeExpiredIdempotencyKeys(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Same files, new multipart boundary, same key: replayed, same version.
	status, body2, replayHeader := env.uploadVersionCLIResult(user, "replay", pat, files, key, "", nil)
	if status != http.StatusAccepted {
		t.Fatalf("retry: %d %s (want a replayed 202, not V3 'version exists')", status, body2)
	}
	if replayHeader.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("the replayed answer is not marked as one: %q", replayHeader.Get("Idempotency-Replayed"))
	}
	var second struct {
		Id string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body2), &second)
	if first.Id == "" || first.Id != second.Id {
		t.Fatalf("replay returned a different version: %q vs %q", first.Id, second.Id)
	}

	// Same key, different content: refused, nothing created.
	original := files["SKILL.md"]
	files["SKILL.md"] = "Something else entirely.\n"
	status, body3 := env.uploadVersionCLIWithHeaders(user, "replay", pat, files, key)
	if status != http.StatusConflict || !strings.Contains(body3, "different request body") {
		t.Fatalf("different body under the same key: %d %s (want 409 saying the key carried a different body)", status, body3)
	}
	if n := countVersions(env, user, "replay"); n != 1 {
		t.Fatalf("a refused retry left %d versions, want the 1 submitted", n)
	}

	// A first attempt that has not finished answers nothing yet: the same
	// request under its key is told so, not handed another's answer.
	files["SKILL.md"] = original
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE idempotency_keys SET response_status = NULL, response_body = NULL WHERE key = $1`, key["Idempotency-Key"]); err != nil {
		t.Fatal(err)
	}
	status, body4 := env.uploadVersionCLIWithHeaders(user, "replay", pat, files, key)
	if status != http.StatusConflict || !strings.Contains(body4, "still in flight") {
		t.Fatalf("a retry of a request still in flight: %d %s, want 409 saying so", status, body4)
	}

	// A key is at most 255 characters: one of that length is honoured, one
	// more is refused before anything is read.
	long := strings.Repeat("k", 255)
	status, body5 := env.uploadVersionCLIWithHeaders(user, "replay", pat, skillFiles(user, "replay", "1.0.1", nil), map[string]string{"Idempotency-Key": long})
	if status != http.StatusAccepted {
		t.Fatalf("a key of 255 characters: %d %s, want 202", status, body5)
	}
	status, body6 := env.uploadVersionCLIWithHeaders(user, "replay", pat, skillFiles(user, "replay", "1.0.2", nil), map[string]string{"Idempotency-Key": long + "k"})
	if status != http.StatusUnprocessableEntity || !strings.Contains(body6, "at most 255 characters") {
		t.Fatalf("a key of 256 characters: %d %s, want 422 naming the limit", status, body6)
	}
	if n := countVersions(env, user, "replay"); n != 2 {
		t.Fatalf("after the two keyed uploads the agent holds %d versions, want 1.0.0 and 1.0.1", n)
	}

	// A request that fails gives its key back: the same request, retried
	// once what stopped it is put right, is taken.
	ghost := map[string]string{"Idempotency-Key": "publish-ghost-" + randSuffix()}
	ghostFiles := skillFiles(user, "ghost", "1.0.0", nil)
	if status, body := env.uploadVersionCLIWithHeaders(user, "ghost", pat, ghostFiles, ghost); status != http.StatusNotFound {
		t.Fatalf("upload to an agent that does not exist yet: %d %s, want 404", status, body)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "ghost", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if status, body := env.uploadVersionCLIWithHeaders(user, "ghost", pat, ghostFiles, ghost); status != http.StatusAccepted {
		t.Fatalf("the same request once the agent exists: %d %s, want 202", status, body)
	}
}
