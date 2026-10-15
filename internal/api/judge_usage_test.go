package api_test

import (
	"context"
	"net/http"
	"testing"
)

// TestReportShowsJudgeUsageToStaffOnly pins where the judge's token use
// surfaces: the scan run records it, the
// report carries it for platform staff, and the public report is the same
// report as before — what a review cost is the platform's measurement, not
// part of the verdict anyone else reads.
func TestReportShowsJudgeUsageToStaffOnly(t *testing.T) {
	env := newTestEnv(t)
	author := env.register("usage-auth")
	env.verifyEmail(author)
	authorSess := env.login(author)
	_, _ = env.st.Pool().Exec(context.Background(),
		`UPDATE users SET created_at = now() - interval '30 days' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, author)

	env.doJSON(authorSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "measured", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(authorSess, "pub", "agent:publish", "agent:read", "repo:read")
	if status, body := env.uploadVersionCLI(author, "measured", pat, map[string]string{
		"agent.yaml": skillYAML(author, "measured", "1.0.0"),
		"README.md":  "# measured\n",
		"SKILL.md":   "Summarise the incident politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	env.waitStatus(author, "measured", "1.0.0", "published")

	// The static judge reports no usage, so the run holds NULL — unknown,
	// not zero. The counts a live provider would have written are set
	// afterwards; the columns existing at all is part of what this proves.
	runFor := `SELECT v.id FROM agent_versions v JOIN agents a ON a.id = v.agent_id
	           JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'measured'`
	var promptNull, completionNull bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT judge_prompt_tokens IS NULL, judge_completion_tokens IS NULL FROM scan_runs WHERE version_id = (`+runFor+`)`, author,
	).Scan(&promptNull, &completionNull); err != nil {
		t.Fatal(err)
	}
	if !promptNull || !completionNull {
		t.Fatal("the static judge must leave the token columns NULL, not zero")
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE scan_runs SET judge_prompt_tokens = 812, judge_completion_tokens = 97 WHERE version_id = (`+runFor+`)`, author); err != nil {
		t.Fatal(err)
	}

	reportPath := "/api/v1/agents/" + author + "/measured/versions/1.0.0/report"
	var rep struct {
		JudgeUsage *struct {
			PromptTokens     int `json:"promptTokens"`
			CompletionTokens int `json:"completionTokens"`
		} `json:"judgeUsage"`
	}
	env.doJSON(anonymous, http.MethodGet, reportPath, nil, &rep, http.StatusOK)
	if rep.JudgeUsage != nil {
		t.Fatalf("the public report must not carry judge usage, got %+v", *rep.JudgeUsage)
	}
	env.doJSON(authorSess, http.MethodGet, reportPath, nil, &rep, http.StatusOK)
	if rep.JudgeUsage != nil {
		t.Fatalf("the author is not staff and must not see judge usage, got %+v", *rep.JudgeUsage)
	}

	staff := env.register("usage-staff")
	env.verifyEmail(staff)
	env.makePlatformStaff(t, staff)
	env.doJSON(env.login(staff), http.MethodGet, reportPath, nil, &rep, http.StatusOK)
	if rep.JudgeUsage == nil || rep.JudgeUsage.PromptTokens != 812 || rep.JudgeUsage.CompletionTokens != 97 {
		t.Fatalf("staff must see the recorded usage, got %+v", rep.JudgeUsage)
	}
}
