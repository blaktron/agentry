package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestAnUploadKeepsItsClaimedDraftAsAClaim: an upload may name the hosted
// draft it was published from (plan drafter-revisions.md §6; agentry#794).
// The registry keeps the id as a claim and nothing more: the version is a
// cli-upload, and a core registry, which has no DraftProvenance, never
// makes it a drafter-revision. A draftRun that is not an id is refused
// before anything is stored.
func TestAnUploadKeepsItsClaimedDraftAsAClaim(t *testing.T) {
	env := newTestEnv(t)
	author := env.register("claim-auth")
	env.verifyEmail(author)
	pat, files := submitFixture(env, author, "claimed")

	if status, body := env.uploadVersionCLIWithFields(author, "claimed", pat, files, map[string]string{"draftRun": "not-a-draft"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("a malformed draftRun: got %d %s", status, body)
	}
	if n := countVersions(env, author, "claimed"); n != 0 {
		t.Fatalf("a refused upload stored %d versions", n)
	}

	run := uuid.New()
	if status, body := env.uploadVersionCLIWithFields(author, "claimed", pat, files, map[string]string{"draftRun": run.String()}); status != http.StatusAccepted {
		t.Fatalf("submit with a draftRun: %d %s", status, body)
	}
	env.waitStatus(author, "claimed", "1.0.0", "published")
	var source string
	var claim *uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT v.source, v.draft_run FROM agent_versions v JOIN agents a ON a.id = v.agent_id
		 JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'claimed'`, author).Scan(&source, &claim); err != nil {
		t.Fatal(err)
	}
	if source != "cli-upload" || claim == nil || *claim != run {
		t.Fatalf("the version is %q claiming %v, want a cli-upload claiming %s", source, claim, run)
	}
}
