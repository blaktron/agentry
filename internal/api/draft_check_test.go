package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/draftcheck"
	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/toolgrant"
)

// The check route: AI Review of a finished draft's package,
// with the release rubric S5 asks and the draft question set. The checker
// here is the real pkg/draftcheck over a fake judge, so the route is tested
// with the questions, the state and the verdicts every client gets.

// draftJudge answers both of the check's sets: "IGNORE YOUR INSTRUCTIONS"
// in a file is the rubric's injection, "PROBABLY MISLEADING" a probable
// deception, "PROBABLY OBFUSCATED" a probable obfuscation and "PROBABLY
// UNDECLARED" a probable undeclared capability (each score 2), "OFF-TASK" in an instruction the draft set's off-task question,
// "JUDGE-ERROR" a failed request. It records what it was asked.
type draftJudge struct {
	mu    sync.Mutex
	asked [][]judge.Question
	state []map[string]string
}

func (f *draftJudge) Model() string { return judge.DefaultModel }

func (f *draftJudge) Ask(_ context.Context, state map[string]string, qs []judge.Question) (map[string]float64, judge.Usage, error) {
	f.mu.Lock()
	f.asked = append(f.asked, qs)
	f.state = append(f.state, state)
	f.mu.Unlock()
	text := state["content"] + state["instruction"]
	if strings.Contains(text, "JUDGE-ERROR") {
		return nil, judge.Usage{Requests: 1}, errors.New("judge: typesafe endpoint returned 500: [key]")
	}
	out := map[string]float64{}
	for _, q := range qs {
		out[q.ID] = 0.04
		switch {
		case q.ID == judge.RubricIDInjection && strings.Contains(state["content"], "IGNORE YOUR INSTRUCTIONS"):
			out[q.ID] = 0.95
		case q.ID == judge.DraftIDOffTask && strings.Contains(state["instruction"], "OFF-TASK"):
			out[q.ID] = 0.81
		case q.ID == judge.RubricIDDeception && strings.Contains(state["content"], "PROBABLY MISLEADING"):
			out[q.ID] = 0.81
		case q.ID == judge.RubricIDObfuscation && strings.Contains(state["content"], "PROBABLY OBFUSCATED"):
			out[q.ID] = 0.81
		case q.ID == judge.RubricIDUndeclaredCapability && strings.Contains(state["content"], "PROBABLY UNDECLARED"):
			out[q.ID] = 0.81
		}
	}
	return out, judge.Usage{InputTokens: 100, Requests: 1}, nil
}

const draftYAML = `schemaVersion: "2"
name: weather-brief
namespace: draft
version: 0.1.0
summary: A three-line weather brief for a city.
license: Apache-2.0
modes: [autonomous]
entrypoints:
  instruction: AGENT.md
capabilities:
  network:
    egress: [api.open-meteo.com]
publish:
  include: [agent.yaml, AGENT.md]
`

type draftCheckBody struct {
	Rubric struct {
		Verdict  string         `json:"verdict"`
		Scores   map[string]int `json:"scores"`
		Findings []struct {
			ID       string `json:"id"`
			Score    int    `json:"score"`
			Path     string `json:"path"`
			Severity string `json:"severity"`
		} `json:"findings"`
		RubricHash string `json:"rubricHash"`
		Failure    string `json:"failure"`
	} `json:"rubric"`
	Draft struct {
		Verdict     string         `json:"verdict"`
		Score       int            `json:"score"`
		Scores      map[string]int `json:"scores"`
		Flagged     []string       `json:"flagged"`
		QuestionSet string         `json:"questionSet"`
		Failure     string         `json:"failure"`
	} `json:"draft"`
	Ungranted []struct {
		Tool   string `json:"tool"`
		Grant  string `json:"grant"`
		Path   string `json:"path"`
		Line   int    `json:"line"`
		Reason string `json:"reason"`
	} `json:"ungranted"`
	Model string `json:"model"`
	Usage struct {
		Requests    int `json:"requests"`
		InputTokens int `json:"inputTokens"`
	} `json:"usage"`
}

func draftFiles(instruction string) []map[string]string {
	return []map[string]string{{"path": "agent.yaml", "content": draftYAML}, {"path": "AGENT.md", "content": instruction}}
}

func checkDraft(t *testing.T, env *testEnv, c caller, headers map[string]string, body map[string]any) (int, draftCheckBody, problemBody) {
	t.Helper()
	res := env.doWithHeaders(c, http.MethodPost, "/api/v1/model-input/check", body, headers)
	var b draftCheckBody
	var p problemBody
	if res.StatusCode == http.StatusOK {
		readBody(t, res, &b)
	} else {
		readBody(t, res, &p)
	}
	return res.StatusCode, b, p
}

// The draft check flags what would hold the version, as the gate does: a
// probable obfuscation is a medium finding, a note on a pass; a probable
// undeclared capability is high and flags, and so is a probable
// deception.
func TestTheDraftCheckFlagsOnlyWhatTheGateHolds(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) { s.SetDraftChecker(draftcheck.New(&draftJudge{})) })
	staff := staffCaller(t, env, "dc-bar")
	desc := "Give me a three-line weather brief for a city I name."

	st, b, _ := checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": draftFiles("# Weather\nPROBABLY OBFUSCATED\n")})
	if st != http.StatusOK || b.Rubric.Verdict != "pass" || len(b.Rubric.Findings) != 1 ||
		b.Rubric.Findings[0].ID != "C5_obfuscation" || b.Rubric.Findings[0].Score != 2 || b.Rubric.Findings[0].Severity != "medium" {
		t.Fatalf("a medium is a note on a pass: %d %+v", st, b.Rubric)
	}

	st, b, _ = checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": draftFiles("# Weather\nPROBABLY MISLEADING\n")})
	if st != http.StatusOK || b.Rubric.Verdict != "flagged" || len(b.Rubric.Findings) != 1 ||
		b.Rubric.Findings[0].ID != "C4_user_deception" || b.Rubric.Findings[0].Score != 2 || b.Rubric.Findings[0].Severity != "high" {
		t.Fatalf("a deception at 2 flags: %d %+v", st, b.Rubric)
	}

	st, b, _ = checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": draftFiles("# Weather\nPROBABLY UNDECLARED\n")})
	if st != http.StatusOK || b.Rubric.Verdict != "flagged" || len(b.Rubric.Findings) != 1 ||
		b.Rubric.Findings[0].ID != "C3_undeclared_capability" || b.Rubric.Findings[0].Score != 2 || b.Rubric.Findings[0].Severity != "high" {
		t.Fatalf("an undeclared capability at 2 flags: %d %+v", st, b.Rubric)
	}
}

func TestTheDraftCheckReadsThePackageAsS5AndAsksTheDraftSet(t *testing.T) {
	fj := &draftJudge{}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetDraftChecker(draftcheck.New(fj)) })
	staff := staffCaller(t, env, "dc-staff")
	desc := "Give me a three-line weather brief for a city I name."

	st, b, _ := checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": draftFiles("# Weather\nFetch the forecast and write three lines.\n")})
	if st != http.StatusOK || b.Rubric.Verdict != "pass" || len(b.Rubric.Findings) != 0 || b.Draft.Verdict != "pass" || len(b.Draft.Flagged) != 0 {
		t.Fatalf("pass: %d %+v", st, b)
	}
	ck := draftcheck.New(fj)
	if b.Model != judge.DefaultModel || b.Rubric.RubricHash != ck.RubricHash() || b.Draft.QuestionSet != ck.QuestionSet() || len(b.Rubric.Scores) != 6 || len(b.Draft.Scores) != 1 {
		t.Fatalf("the record: %+v", b)
	}
	// The rubric is asked as S5 asks it: the canonical manifest as
	// agent.yaml first, then every file, with the declared capabilities
	// beside each chunk; the draft set once, with the description, the
	// manifest and the instruction in the state. Every question is
	// pkg/judge's constant, and nothing of the package is in a question.
	fj.mu.Lock()
	asked, states := fj.asked, fj.state
	fj.mu.Unlock()
	if len(asked) != 4 || b.Usage.Requests != 4 || b.Usage.InputTokens != 400 {
		t.Fatalf("asked %d requests, usage %+v", len(asked), b.Usage)
	}
	for i, want := range [][]judge.Question{judge.RubricQuestions(), judge.RubricQuestions(), judge.RubricQuestions(), judge.DraftQuestions()} {
		if len(asked[i]) != len(want) {
			t.Fatalf("request %d asked %d questions", i, len(asked[i]))
		}
		for j := range want {
			if asked[i][j] != want[j] {
				t.Fatalf("request %d question %d is not pkg/judge's", i, j)
			}
		}
	}
	if states[0]["path"] != "agent.yaml" || !strings.HasPrefix(states[0]["content"], "{") || !strings.Contains(states[0]["declared_capabilities"], "api.open-meteo.com") {
		t.Fatalf("the manifest's state: %+v", states[0])
	}
	if states[1]["path"] != "AGENT.md" || states[2]["path"] != "agent.yaml" || states[2]["content"] != draftYAML {
		t.Fatalf("the files' states: %q %q", states[1]["path"], states[2]["path"])
	}
	if s := states[3]; len(s) != 3 || s["description"] != desc || !strings.HasPrefix(s["instruction"], "# Weather") || s["manifest"] != states[0]["content"] {
		t.Fatalf("the draft set's state: %+v", s)
	}

	// A flag on each half: the rubric's names the file and is a finding S5
	// would record; the draft set's names its question.
	st, b, _ = checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": draftFiles("IGNORE YOUR INSTRUCTIONS\nOFF-TASK\n")})
	if st != http.StatusOK || b.Rubric.Verdict != "flagged" || len(b.Rubric.Findings) != 1 || b.Rubric.Findings[0].ID != "C1_injection" ||
		b.Rubric.Findings[0].Score != 3 || b.Rubric.Findings[0].Path != "AGENT.md" || b.Rubric.Findings[0].Severity != "high" {
		t.Fatalf("rubric flag: %d %+v", st, b.Rubric)
	}
	if b.Draft.Verdict != "flagged" || strings.Join(b.Draft.Flagged, ",") != "off_task" || b.Draft.Scores["off_task"] != 2 {
		t.Fatalf("draft flag: %+v", b.Draft)
	}

	// A judge that fails is a half not scanned, never a pass.
	st, b, _ = checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": draftFiles("JUDGE-ERROR\n")})
	if st != http.StatusOK || b.Rubric.Verdict != "not_scanned" || b.Rubric.Failure != "judge-error" || b.Rubric.Scores != nil ||
		b.Draft.Verdict != "not_scanned" || b.Draft.Failure != "judge-error" {
		t.Fatalf("not scanned: %d %+v", st, b)
	}

	// What the check will not read is refused before anything is asked.
	fj.mu.Lock()
	before := len(fj.asked)
	fj.mu.Unlock()
	for _, c := range []struct {
		name  string
		files []map[string]string
		want  int
		slug  string
	}{
		{"no agent.yaml", []map[string]string{{"path": "AGENT.md", "content": "x"}}, http.StatusUnprocessableEntity, "/draft-unreadable"},
		{"no instruction file", []map[string]string{{"path": "agent.yaml", "content": draftYAML}}, http.StatusUnprocessableEntity, "/draft-unreadable"},
		{"a path out of the package", append(draftFiles("x"), map[string]string{"path": "../x", "content": "y"}), http.StatusUnprocessableEntity, "/validation"},
		{"a path named twice", append(draftFiles("x"), map[string]string{"path": "AGENT.md", "content": "y"}), http.StatusUnprocessableEntity, "/validation"},
		{"past the bytes", draftFiles(strings.Repeat("x", draftcheck.MaxBytes)), http.StatusRequestEntityTooLarge, "/draft-too-large"},
	} {
		st, _, p := checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": c.files})
		if st != c.want || !strings.HasSuffix(p.Type, c.slug) {
			t.Fatalf("%s: %d %+v", c.name, st, p)
		}
	}
	fj.mu.Lock()
	after := len(fj.asked)
	fj.mu.Unlock()
	if after != before {
		t.Fatalf("a refused check asked the judge %d times", after-before)
	}
}

// A description of up to 24 KiB, the most a client accepts for a draft's
// task, is checked and reaches the draft set whole; one byte more is
// refused with the bound named, and the judge is not asked.
func TestTheDraftCheckTakesADescriptionUpTo24KiB(t *testing.T) {
	fj := &draftJudge{}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetDraftChecker(draftcheck.New(fj)) })
	staff := staffCaller(t, env, "dc-long-staff")
	files := draftFiles("# Weather\nFetch the forecast and write three lines.\n")

	for _, n := range []int{20 << 10, 24 << 10} {
		desc := strings.Repeat("d", n)
		st, b, p := checkDraft(t, env, staff, nil, map[string]any{"description": desc, "files": files})
		if st != http.StatusOK || b.Draft.Verdict != "pass" || b.Rubric.Verdict != "pass" {
			t.Fatalf("a %d-byte description: %d %+v %+v", n, st, b, p)
		}
		fj.mu.Lock()
		last := fj.state[len(fj.state)-1]
		fj.mu.Unlock()
		if last["description"] != desc {
			t.Fatalf("a %d-byte description reached the draft set as %d bytes", n, len(last["description"]))
		}
	}

	fj.mu.Lock()
	before := len(fj.asked)
	fj.mu.Unlock()
	st, _, p := checkDraft(t, env, staff, nil, map[string]any{"description": strings.Repeat("d", 24<<10+1), "files": files})
	if st != http.StatusUnprocessableEntity || !strings.Contains(p.Detail, "24576") {
		t.Fatalf("one byte over: %d %+v", st, p)
	}
	fj.mu.Lock()
	after := len(fj.asked)
	fj.mu.Unlock()
	if after != before {
		t.Fatalf("a refused description asked the judge %d times", after-before)
	}
}

// The check answers staff by session and an admitted job credential, never
// a token whatever its scopes, and a job's check is admitted as the check
// op and recorded against it.
func TestTheDraftCheckAnswersStaffAndAdmittedJobsOnly(t *testing.T) {
	callers := &fakeCallers{
		jobs: map[string]string{"agyj_valid": "01draft"},
		refuse: map[string]*registry.Refusal{"agyj_capped": {Status: http.StatusForbidden, Slug: "draft-cap-reached",
			Title: "The draft's cap is reached", Detail: "This draft has made its 2 checks."}},
	}
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetDraftChecker(draftcheck.New(&draftJudge{}))
		s.SetModelInputCallers(callers)
	})
	staff := staffCaller(t, env, "dc-callers")
	plainH := env.register("dc-plain")
	env.verifyEmail(plainH)
	plain := env.login(plainH)
	_, staffPAT := env.mintPAT(staff, "dc-staff-pat", "agent:read", "user:profile", "review:act", "run:write")
	body := map[string]any{"description": "a weather brief", "files": draftFiles("# Weather\n")}
	job := func(tok string) map[string]string { return map[string]string{"X-Agentry-Job-Token": tok} }
	for _, c := range []struct {
		name    string
		caller  caller
		headers map[string]string
		want    int
	}{
		{"anonymous", anonymous, nil, http.StatusUnauthorized},
		{"a signed-in account", plain, nil, http.StatusForbidden},
		{"a staff token, whatever its scopes", caller{name: "staff-pat", pat: staffPAT}, nil, http.StatusForbidden},
		{"staff by session", staff, nil, http.StatusOK},
		{"an admitted job", anonymous, job("agyj_valid"), http.StatusOK},
		{"a credential that names no job", anonymous, job("agyj_unknown"), http.StatusUnauthorized},
		{"a job the extension refuses", anonymous, job("agyj_capped"), http.StatusForbidden},
	} {
		if st, _, _ := checkDraft(t, env, c.caller, c.headers, body); st != c.want {
			t.Fatalf("%s: %d, want %d", c.name, st, c.want)
		}
	}
	// What the check will not read is refused before the extension is
	// asked, so it costs a job nothing.
	for _, files := range [][]map[string]string{{{"path": "AGENT.md", "content": "x"}}, draftFiles(strings.Repeat("x", draftcheck.MaxBytes))} {
		if st, _, _ := checkDraft(t, env, anonymous, job("agyj_valid"), map[string]any{"description": "d", "files": files}); st != http.StatusUnprocessableEntity && st != http.StatusRequestEntityTooLarge {
			t.Fatalf("a refused package from a job: %d", st)
		}
	}
	callers.mu.Lock()
	defer callers.mu.Unlock()
	var checks []api.ModelInputCall
	for _, call := range callers.calls {
		if call.Op == api.ModelInputOpCheck {
			checks = append(checks, call)
		}
	}
	if len(checks) != 3 || checks[0].Bytes != len(draftYAML)+len("# Weather\n") || checks[0].Source != "" {
		t.Fatalf("admitted as: %+v", checks)
	}
	if len(callers.uses) != 1 || callers.usesJob[0] != "01draft" || callers.uses[0].Op != api.ModelInputOpCheck ||
		callers.uses[0].Scanned != 1 || callers.uses[0].Withheld != 0 || callers.uses[0].Requests != 4 {
		t.Fatalf("recorded: %+v %+v", callers.usesJob, callers.uses)
	}
}

func TestTheDraftCheckIsOffWithoutAJevJudge(t *testing.T) {
	env := newTestEnv(t)
	staff := staffCaller(t, env, "dc-off")
	st, _, p := checkDraft(t, env, staff, nil, map[string]any{"description": "d", "files": draftFiles("# x\n")})
	if st != http.StatusServiceUnavailable || !strings.HasSuffix(p.Type, "/model-input-unavailable") {
		t.Fatalf("no checker: %d %+v", st, p)
	}
}

// The check lists the runner tools the instruction calls for that the
// manifest does not grant, with no judge: the weather draft declares an
// egress host, so fetch is granted and the browser and run_command are
// not. A draft naming only granted tools lists none, and the list is
// present and empty rather than absent.
func TestTheDraftCheckListsTheToolsTheManifestDoesNotGrant(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) { s.SetDraftChecker(draftcheck.New(&draftJudge{})) })
	staff := staffCaller(t, env, "dc-tools")
	desc := "Give me a three-line weather brief for a city I name."

	st, b, _ := checkDraft(t, env, staff, nil, map[string]any{"description": desc,
		"files": draftFiles("# Weather\nRead the forecast with the `fetch` tool.\nOpen the map with browser_navigate, then run_command jq.\n")})
	if st != http.StatusOK || len(b.Ungranted) != 2 {
		t.Fatalf("%d %+v", st, b.Ungranted)
	}
	if u := b.Ungranted[0]; u.Tool != "browser_navigate" || u.Grant != "browser" || u.Path != "capabilities.browser" || u.Line != 3 || u.Reason == "" {
		t.Fatalf("browser: %+v", u)
	}
	if u := b.Ungranted[1]; u.Tool != "run_command" || u.Grant != "exec" || u.Path != "capabilities.exec.commands" {
		t.Fatalf("exec: %+v", u)
	}

	res := env.doWithHeaders(staff, http.MethodPost, "/api/v1/model-input/check",
		map[string]any{"description": desc, "files": draftFiles("# Weather\nRead the forecast with the `fetch` tool.\n")}, nil)
	var raw map[string]any
	readBody(t, res, &raw)
	if u, ok := raw["ungranted"].([]any); res.StatusCode != http.StatusOK || !ok || len(u) != 0 {
		t.Fatalf("a granted draft: %d %v", res.StatusCode, raw["ungranted"])
	}
}

// Every grant the reading can name is a word of the spec's enum.
func TestEveryGrantIsInTheSpec(t *testing.T) {
	for _, g := range toolgrant.Grants() {
		if !api.DraftUngrantedToolGrant(g).Valid() {
			t.Errorf("grant %q is not in DraftUngrantedTool.grant", g)
		}
	}
}
