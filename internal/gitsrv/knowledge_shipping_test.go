package gitsrv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/manifest"
)

// A tag push carries no request, so no confirmation of the packs a release
// ships: it is accepted, and the version's record says it was published
// that way and by no one's confirmation.
func TestTagPushShippingIsRecordedAsTagPush(t *testing.T) {
	env := newGitEnv(t)
	name := "shipper"
	env.seedAgentModes(name, []string{"autonomous"}, "public")

	tree := map[string][]byte{
		"wiki/index.md":        []byte("# Index\n\n- [Notes](topics/notes.md)\n"),
		"wiki/log.md":          []byte("# Log\n"),
		"wiki/topics/notes.md": []byte("---\ntitle: Notes\n---\nA short note. [src: doc:notes.txt]\n"),
		"sources/notes.txt":    []byte("A short note.\n"),
	}
	digest, size, pages, err := manifest.KnowledgeTreeDigest(tree)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := json.Marshal(map[string]any{
		"schema": manifest.KnowledgePackSchema, "name": "notes", "pages": pages, "bytes": size, "sha256": digest, "scan": "not scanned",
	})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"README.md": "# shipper\n",
		"LICENSE":   "Apache-2.0 placeholder text\n",
		"AGENT.md":  "---\nname: shipper\n---\nAnswer from the pack at /knowledge/notes.\n",
		"agent.yaml": fmt.Sprintf(`schemaVersion: "2"
name: %s
namespace: %s
version: 1.0.0
summary: "Ships a pack"
license: Apache-2.0
modes: [autonomous]
entrypoints:
  instruction: AGENT.md
knowledge:
  ships:
    - name: notes
publish:
  include: [agent.yaml, README.md, AGENT.md, LICENSE, knowledge/**]
`, name, env.owner.handle),
		"knowledge/notes/manifest.json": string(pm),
	}
	for p, b := range tree {
		files["knowledge/notes/"+p] = string(b)
	}
	work := seedWorkdir(t, files)
	mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "main")
	mustGit(t, work, "tag", "v1.0.0")
	mustGit(t, work, "push", env.cloneURL(name, env.owner.patRW), "v1.0.0")
	env.waitPublished(name, "1.0.0")

	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.knowledge_shipping FROM agent_versions v JOIN agents a ON a.id = v.agent_id
		 WHERE a.name = $1 AND v.version = '1.0.0'`, name).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rec registry.ShippedKnowledgeRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("record %q: %v", raw, err)
	}
	if rec.Via != registry.ShippedViaTagPush || rec.By != nil || len(rec.Packs) != 1 || rec.Packs[0].Name != "notes" || rec.Packs[0].Origin != nil {
		t.Fatalf("record = %+v", rec)
	}
	if strings.Contains(string(raw), `"by"`) {
		t.Fatalf("a tag push names no account: %s", raw)
	}
}
