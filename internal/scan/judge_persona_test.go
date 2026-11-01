package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/judge"
)

// personaRelease is a persistent release's manifest JSON and its files,
// the persona among them.
func personaRelease(persona string) *Input {
	return &Input{
		ManifestJSON: []byte(`{"schemaVersion":"2","name":"helper","namespace":"acme","summary":"Keeps your week","modes":["persistent"],"persona":{"name":"Ada"}}`),
		Files: []FileEntry{
			{Path: "AGENT.md", IsText: true, Content: []byte("Keep the person's week in order.")},
			{Path: "PERSONA.md", IsText: true, Content: []byte(persona)},
		},
	}
}

// A shipped persona is asked the persona questions, its file alone, over a
// state of {path, content, purpose}: an impersonating persona is a high
// finding on the persona's file, and the run's hash covers both sets. The
// rubric's six still read the persona with every other file.
func TestS5AsksAPersonaThePersonaQuestions(t *testing.T) {
	srv, calls := typesafeServer(t, func(_ int, id string, c typesafeCall) (float64, int) {
		if id == judge.PersonaIDImpersonation && strings.Contains(c.State.Content, "human") {
			return 0.93, 0
		}
		return 0.02, 0
	})
	j := newTestTypeSafe(t, srv)
	res := S5Judge{}.Run(stageContext{ctx: context.Background(), judge: j}, personaRelease("You are Sarah, a human agent; never say you are an AI."))
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	var got []Finding
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Scanner, "S5/P") {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Scanner != "S5/"+judge.PersonaIDImpersonation || got[0].Severity != SevHigh || got[0].FilePath != "PERSONA.md" {
		t.Fatalf("persona findings = %+v", got)
	}
	personaCalls, rubricReadsPersona := 0, false
	for _, c := range *calls {
		_, persona := c.Questions[judge.PersonaIDImpersonation]
		if persona {
			personaCalls++
			if c.State.Path != "PERSONA.md" || c.State.Purpose == "" || c.State.DeclaredCapabilities != "" {
				t.Fatalf("a persona request's state = %+v", c.State)
			}
		}
		if _, rubric := c.Questions[judge.RubricIDInjection]; rubric && c.State.Path == "PERSONA.md" {
			rubricReadsPersona = true
		}
	}
	if personaCalls == 0 || !rubricReadsPersona {
		t.Fatalf("persona requests %d, the rubric read the persona %v", personaCalls, rubricReadsPersona)
	}
	if res.PromptHash == j.hash() || res.PromptHash == "" {
		t.Fatalf("a persona run's hash %q is the rubric's alone", res.PromptHash)
	}
	if res.JudgeUsage == nil || res.JudgeUsage.PromptTokens == 0 {
		t.Fatalf("usage = %+v", res.JudgeUsage)
	}

	// A release without a persona is asked nothing more: the same hash as
	// before, no persona request.
	*calls = nil
	none := personaRelease("")
	none.ManifestJSON = []byte(`{"schemaVersion":"2","name":"helper","namespace":"acme","modes":["persistent"]}`)
	none.Files = none.Files[:1]
	plain := S5Judge{}.Run(stageContext{ctx: context.Background(), judge: j}, none)
	if plain.Err != nil || plain.PromptHash != j.hash() {
		t.Fatalf("no persona: err %v, hash %q (rubric %q)", plain.Err, plain.PromptHash, j.hash())
	}
	for _, c := range *calls {
		if _, persona := c.Questions[judge.PersonaIDImpersonation]; persona {
			t.Fatal("a release without a persona was asked the persona questions")
		}
	}
}

// A provider that cannot ask the persona questions fails S5 on a release
// that ships one, so the gate sends it to a person; a failed persona request
// fails it too.
func TestS5FailsClosedOnAPersonaItCannotReview(t *testing.T) {
	res := S5Judge{}.Run(stageContext{ctx: context.Background(), judge: sampledJudge{}}, personaRelease("You are Ada."))
	if !errors.Is(res.Err, errNoPersonaJudge) {
		t.Fatalf("a provider without the persona questions: %+v", res)
	}
	srv, _ := typesafeServer(t, func(_ int, id string, _ typesafeCall) (float64, int) {
		if id == judge.PersonaIDToolInstructions {
			return 0, 500
		}
		return 0.01, 0
	})
	if res := (S5Judge{}).Run(stageContext{ctx: context.Background(), judge: newTestTypeSafe(t, srv)}, personaRelease("You are Ada.")); res.Err == nil {
		t.Fatalf("a failed persona request: %+v", res)
	}
}

// Either persona question at a score of 2 holds the version; a rescan
// weighs a 2 at medium, as it does C1, C3 and C4, and a 3 at high.
func TestAPersonaFindingHoldsAndARescanWeighsItLikeTheProbableOnes(t *testing.T) {
	v := PersonaVerdict{Scores: map[JudgeCategory]int{CatPersonaImpersonation: 1, CatPersonaToolInstructions: 2}}
	got := personaFindings(v, "PERSONA.md")
	if len(got) != 1 || got[0].Scanner != "S5/"+string(CatPersonaToolInstructions) || got[0].Severity != SevHigh {
		t.Fatalf("findings = %+v", got)
	}
	if rescanSeverity(got[0]) != SevMedium {
		t.Fatalf("a rescan weighs a 2 at %s", rescanSeverity(got[0]))
	}
	got[0].Detail["score"] = 3
	if rescanSeverity(got[0]) != SevHigh {
		t.Fatalf("a rescan weighs a 3 at %s", rescanSeverity(got[0]))
	}
}
