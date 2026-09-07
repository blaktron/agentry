package api_test

// Idempotency-Key on POST /agents/{ns}/{name}/versions (agentry#22, DEV-021.2):
// a retried multipart upload — new boundary, same files — replays the 202
// instead of hitting V3 "version exists"; the same key with different files
// is a 409; and an archive over the old 1 MiB body cap is accepted.

import (
	"crypto/sha256"
	"encoding/hex"
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

	// A body past 1 MiB that does not compress away (the archive builder
	// refuses zip-bomb ratios): the guard used to refuse to read it at all.
	// It is an image, not text: §19 caps the text files of a package at
	// 1 MiB in total (V8, agentry#44), so a large README would be refused
	// before the replay under test.
	var sb strings.Builder
	sb.WriteString("\x89PNG\r\n\x1a\n")
	seed := sha256.Sum256([]byte("idempotency fixture"))
	for sb.Len() < 1400*1024 {
		seed = sha256.Sum256(seed[:])
		sb.WriteString(hex.EncodeToString(seed[:]))
		sb.WriteByte('\n')
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

	status, body := env.uploadVersionCLIWithHeaders(user, "replay", pat, files, key)
	if status != http.StatusAccepted {
		t.Fatalf("first upload: %d %s", status, body)
	}
	var first struct {
		Id string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &first)

	// Same files, new multipart boundary, same key: replayed, same version.
	status, body2 := env.uploadVersionCLIWithHeaders(user, "replay", pat, files, key)
	if status != http.StatusAccepted {
		t.Fatalf("retry: %d %s (want a replayed 202, not V3 'version exists')", status, body2)
	}
	var second struct {
		Id string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body2), &second)
	if first.Id == "" || first.Id != second.Id {
		t.Fatalf("replay returned a different version: %q vs %q", first.Id, second.Id)
	}

	// Same key, different content: refused, nothing created.
	files["SKILL.md"] = "Something else entirely.\n"
	status, body3 := env.uploadVersionCLIWithHeaders(user, "replay", pat, files, key)
	if status != http.StatusConflict {
		t.Fatalf("different body under the same key: %d %s (want 409)", status, body3)
	}
}
