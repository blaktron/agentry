package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

// A subagent that leaves published reaches the holders of each persistent
// release whose constraint admits it, as an advisory on that release: medium
// for a yank, high for a quarantine. A release whose constraint does not
// admit the version, and an autonomous release whose dependencies are only
// informational, get none, and no parent's own version changes.
func TestASubagentLeavingPublishedAdvisesItsParentsHolders(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	ns := u.Handle
	none := "  network:\n    egress: none\n"
	sub := e.submitModes("sub", "public", []string{"autonomous"}, releaseFiles(ns, "sub", "1.0.0", "autonomous", none, ""))
	deps := func(constraint string) string {
		return "dependencies:\n  agents:\n    - ref: " + ns + "/sub\n      version: \"" + constraint + "\"\n      why: Does one part of the work\n"
	}
	caps := none + "  persistent:\n    memory: true\n"
	parent := e.submitModes("parent", "public", []string{"persistent"}, releaseFiles(ns, "parent", "1.0.0", "persistent", caps, deps("^1.0.0")))
	later := e.submitModes("later", "public", []string{"persistent"}, releaseFiles(ns, "later", "1.0.0", "persistent", caps, deps(">=1.0.0")))
	// later's constraint will not admit sub 1.1.0 once it names only 1.0.0.
	pinned := e.publishExisting("later", releaseFiles(ns, "later", "1.1.0", "persistent", caps, deps("1.0.0")))
	auto := e.submitModes("auto", "public", []string{"autonomous"}, releaseFiles(ns, "auto", "1.0.0", "autonomous", none, deps("^1.0.0")))
	for _, v := range []string{parent.Status, later.Status, pinned.Status, auto.Status, sub.Status} {
		if v != "published" {
			t.Fatalf("a fixture did not publish: %s", v)
		}
	}
	advisories := func(agent string) []string {
		t.Helper()
		a, err := e.reg.Resolve(ctx, ns, agent)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := e.st.Queries().ListAdvisoriesForAgent(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Severity+" "+r.AffectedVersions+" "+r.Summary)
		}
		return out
	}

	if err := e.reg.Transition(ctx, sub.ID, registry.StatusYanked, "superseded", staffEvent()); err != nil {
		t.Fatal(err)
	}
	got := advisories("parent")
	if len(got) != 1 || !strings.HasPrefix(got[0], "medium 1.0.0 ") || !strings.Contains(got[0], ns+"/sub 1.0.0, was withdrawn by its publisher") {
		t.Fatalf("parent's advisories after the yank = %q", got)
	}
	if got := advisories("later"); len(got) != 1 || !strings.HasPrefix(got[0], "medium 1.0.0 || 1.1.0 ") {
		t.Fatalf("later's advisories after the yank = %q; want one naming both versions", got)
	}
	if got := advisories("auto"); len(got) != 0 {
		t.Fatalf("an autonomous release's informational dependency was advised: %q", got)
	}

	next := e.publishExisting("sub", releaseFiles(ns, "sub", "1.1.0", "autonomous", none, ""))
	if err := e.pipe.Quarantine(ctx, next.ID, "confirmed harmful", staffEvent()); err != nil {
		t.Fatal(err)
	}
	got = advisories("parent")
	if len(got) != 2 || !strings.HasPrefix(got[0], "high 1.0.0 ") || !strings.Contains(got[0], "1.1.0, was quarantined") {
		t.Fatalf("parent's advisories after the quarantine = %q", got)
	}
	if got := advisories("later"); len(got) != 2 || !strings.HasPrefix(got[0], "high 1.0.0 ") {
		t.Fatalf("later's advisories after the quarantine = %q; want only the version whose constraint admits 1.1.0", got)
	}
	if v := versionStatus(t, e, parent.ID); v.Status != "published" {
		t.Fatalf("the parent's own version moved to %s", v.Status)
	}
}
