package scan_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// submitModes creates an agent with the given modes and visibility and
// submits its files, returning the version as the synchronous pipeline left
// it.
func (e *pipeEnv) submitModes(name, visibility string, modes []string, files map[string]string) storegen.AgentVersion {
	e.t.Helper()
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	p := &auth.Principal{UserID: e.owner, Handle: u.Handle, Via: "session", EmailVerified: true, OrgRoles: map[uuid.UUID]auth.OrgRole{}}
	a, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{Namespace: u.Handle, Name: name, Modes: modes, Visibility: visibility},
		audit.Event{Actor: e.owner, ActorKind: audit.ActorUser})
	if err != nil {
		e.t.Fatalf("create %s: %v", name, err)
	}
	v, err := e.reg.SubmitVersion(ctx, p, a, registry.SubmitInput{Source: "cli-upload", Workspace: writeWorkspace(e.t, files)},
		audit.Event{Actor: e.owner, ActorKind: audit.ActorUser})
	if err != nil {
		e.t.Fatalf("submit %s: %v", name, err)
	}
	return versionStatus(e.t, e, v.ID)
}

// releaseFiles is a release's files: its manifest, with the given modes and
// extra lines after capabilities, and the files the manifest includes.
func releaseFiles(ns, name, version, modes, capabilities, extra string) map[string]string {
	return map[string]string{
		"agent.yaml": `schemaVersion: "2"
name: ` + name + `
namespace: ` + ns + `
version: ` + version + `
summary: "A test release"
license: Apache-2.0
modes: [` + modes + `]
capabilities:
` + capabilities + extra + `
publish:
  include: [agent.yaml, README.md, AGENT.md, LICENSE]
`,
		"README.md": "# " + name + "\nA test release.\n",
		"AGENT.md":  "Summarize the input politely.\n",
		"LICENSE":   "Apache-2.0\n",
	}
}

// subagentRecord is S7's record of the subagents on the version's newest
// scan run.
func subagentRecord(t *testing.T, e *pipeEnv, v storegen.AgentVersion) []scan.Subagent {
	t.Helper()
	ctx := context.Background()
	run, err := e.st.Queries().LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	stages, err := e.st.Queries().ListStageResults(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range stages {
		if st.Scanner == "S7" {
			var rec []scan.Subagent
			if err := scan.DecodeSubagentRecord(st.Detail, &rec); err != nil {
				t.Fatal(err)
			}
			return rec
		}
	}
	t.Fatal("no S7 stage row")
	return nil
}

// A persistent release's subagents are resolved at publish: one that
// resolves is recorded with its version and reach, and each that does not
// (absent, persistent itself, private in another's namespace, no matching
// version) is a high S7 finding that holds the version for a person.
func TestPipelineResolvesAPersistentReleasesSubagents(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	ns := u.Handle

	none := "  network:\n    egress: none\n"
	for _, s := range []struct{ name, version, visibility, modes, caps string }{
		{"sum", "1.0.0", "public", "autonomous", none},
		{"pers", "1.0.0", "public", "persistent", "  persistent:\n    clock: true\n"},
		{"old", "0.1.0", "public", "autonomous", none},
	} {
		if v := e.submitModes(s.name, s.visibility, []string{s.modes}, releaseFiles(ns, s.name, s.version, s.modes, s.caps, "")); v.Status != "published" {
			t.Fatalf("%s: status %s (%v)", s.name, v.Status, v.StatusReason)
		}
	}
	reach := "  network:\n    egress: [api.example.com]\n  secrets: [SUM_KEY]\n  exec:\n    commands: [pdftotext]\n"
	if v := e.publishExisting("sum", releaseFiles(ns, "sum", "1.2.0", "autonomous", reach, "")); v.Status != "published" {
		t.Fatalf("sum 1.2.0: status %s (%v)", v.Status, v.StatusReason)
	}
	// A private release in a user's namespace: not one the parent's holders
	// could run, whoever publishes the parent.
	if v := e.submitModes("mine", "private", []string{"autonomous"}, releaseFiles(ns, "mine", "1.0.0", "autonomous", none, "")); v.Status != "published" {
		t.Fatalf("mine: status %s (%v)", v.Status, v.StatusReason)
	}

	deps := func(refs ...string) string {
		out := "dependencies:\n  agents:\n"
		for _, r := range refs {
			out += "    - ref: " + r + "\n      version: ^1.0.0\n      why: Does one part of the work\n"
		}
		return out
	}
	parentCaps := "  network:\n    egress: none\n  persistent:\n    memory: true\n"
	held := e.submitModes("helper", "public", []string{"persistent"},
		releaseFiles(ns, "helper", "1.0.0", "persistent", parentCaps, deps(ns+"/sum", ns+"/pers", ns+"/ghost", ns+"/mine", ns+"/old")))
	if held.Status != "needs_review" {
		t.Fatalf("a release with unresolved subagents: status %s (%v)", held.Status, held.StatusReason)
	}

	rec := subagentRecord(t, e, held)
	if len(rec) != 5 {
		t.Fatalf("record = %+v", rec)
	}
	sum := rec[0]
	if sum.Ref != ns+"/sum" || sum.Version != "1.2.0" || sum.Problem != "" || sum.Reach == nil ||
		!slices.Equal(sum.Reach.Egress, []string{"api.example.com"}) || !slices.Equal(sum.Reach.Secrets, []string{"SUM_KEY"}) ||
		!slices.Equal(sum.Reach.Exec, []string{"pdftotext"}) || sum.Why == "" {
		t.Fatalf("the resolved subagent = %+v (reach %+v)", sum, sum.Reach)
	}
	for i, want := range map[int]string{1: "itself a persistent agent", 2: "not in the registry", 3: "private and not in this release's organization", 4: "no published version matches ^1.0.0"} {
		if rec[i].Version != "" || rec[i].Reach != nil || !strings.Contains(rec[i].Problem, want) {
			t.Errorf("subagent %d = %+v; want a problem saying %q", i, rec[i], want)
		}
	}

	run, err := e.st.Queries().LatestScanRunForVersion(ctx, held.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, e, `SELECT count(*) FROM findings WHERE scan_run_id = $1 AND scanner = 'S7/subagent-unresolved' AND severity = 'high'`, run.ID); n != 4 {
		t.Fatalf("S7/subagent-unresolved high findings = %d, want 4", n)
	}

	// Every subagent resolving, the release publishes with the record.
	ok := e.submitModes("helper-ok", "public", []string{"persistent"},
		releaseFiles(ns, "helper-ok", "1.0.0", "persistent", parentCaps, deps(ns+"/sum")))
	if ok.Status != "published" {
		t.Fatalf("a release whose subagent resolves: status %s (%v)", ok.Status, ok.StatusReason)
	}
	if rec := subagentRecord(t, e, ok); len(rec) != 1 || rec[0].Version != "1.2.0" {
		t.Fatalf("record = %+v", rec)
	}
}

// A private subagent resolves for a release of the same organization, and
// not for one of another: the people who can install the parent are the
// organization's members, who can run its private releases.
func TestAPrivateSubagentResolvesInItsOwnOrganization(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	org := e.seedOrg("subs" + suffix())
	// A user is active in one organization at a time: another organization
	// is another owner's.
	e2 := newPipeEnv(t)
	other := e2.seedOrg("others" + suffix())
	submit := func(e *pipeEnv, o testOrg, name string, modes []string, files map[string]string) storegen.AgentVersion {
		t.Helper()
		a, err := e.reg.CreateAgent(ctx, e.orgPrincipal(o), registry.CreateAgentInput{Namespace: o.handle, Name: name, Modes: modes, Visibility: "private"},
			audit.Event{Actor: e.owner, ActorKind: audit.ActorUser})
		if err != nil {
			t.Fatal(err)
		}
		v, err := e.reg.SubmitVersion(ctx, e.orgPrincipal(o), a, registry.SubmitInput{Source: "cli-upload", Workspace: writeWorkspace(t, files)},
			audit.Event{Actor: e.owner, ActorKind: audit.ActorUser})
		if err != nil {
			t.Fatal(err)
		}
		return versionStatus(t, e, v.ID)
	}
	none := "  network:\n    egress: none\n"
	if v := submit(e, org, "inner", []string{"autonomous"}, releaseFiles(org.handle, "inner", "1.0.0", "autonomous", none, "")); v.Status != "published" {
		t.Fatalf("inner: %s (%v)", v.Status, v.StatusReason)
	}
	deps := "dependencies:\n  agents:\n    - ref: " + org.handle + "/inner\n      version: ^1.0.0\n      why: Does one part of the work\n"
	caps := none + "  persistent:\n    memory: true\n"
	same := submit(e, org, "helper", []string{"persistent"}, releaseFiles(org.handle, "helper", "1.0.0", "persistent", caps, deps))
	if rec := subagentRecord(t, e, same); same.Status != "published" || len(rec) != 1 || rec[0].Version != "1.0.0" {
		t.Fatalf("the same organization's release: %s, record %+v", same.Status, rec)
	}
	elsewhere := submit(e2, other, "helper", []string{"persistent"}, releaseFiles(other.handle, "helper", "1.0.0", "persistent", caps, deps))
	if rec := subagentRecord(t, e, elsewhere); elsewhere.Status == "published" || len(rec) != 1 || !strings.Contains(rec[0].Problem, "private") {
		t.Fatalf("another organization's release: %s, record %+v", elsewhere.Status, rec)
	}
}
