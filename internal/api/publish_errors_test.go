package api_test

// What a publish that fails says: a record that does not exist (or is out of
// the caller's sight), a token without the scope, a manifest rule's field,
// and a manifest that does not parse.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type publishProblem struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Errors []struct {
		Field   string `json:"field"`
		Message string `json:"message"`
	} `json:"errors"`
}

func readPublishProblem(t *testing.T, body string) publishProblem {
	t.Helper()
	var p publishProblem
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("not a problem: %v\n%s", err, body)
	}
	return p
}

func publishFiles(manifest string) map[string]string {
	return map[string]string{
		"agent.yaml": manifest,
		"README.md":  "# check\n",
		"SKILL.md":   "Say hello.\n",
		"LICENSE":    "Apache-2.0\n",
	}
}

func TestPublishErrorsSayWhatIsMissing(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("pub-errs")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "errs", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")

	t.Run("no record", func(t *testing.T) {
		status, body, _ := env.uploadVersionCLIResult(user, "nothing-here", pat, publishFiles(skillYAML(user, "nothing-here", "1.0.0")), nil, "", nil)
		p := readPublishProblem(t, body)
		if status != http.StatusNotFound || !strings.HasSuffix(p.Type, "/not-found") ||
			!strings.Contains(p.Detail, user+"/nothing-here") || !strings.Contains(p.Detail, "POST /api/v1/agents") {
			t.Fatalf("%d %+v", status, p)
		}
	})

	t.Run("a token without the scope", func(t *testing.T) {
		_, readOnly := env.mintPAT(sess, "read-only", "agent:read")
		status, body, _ := env.uploadVersionCLIResult(user, "errs", readOnly, publishFiles(skillYAML(user, "errs", "1.0.0")), nil, "", nil)
		p := readPublishProblem(t, body)
		if status != http.StatusForbidden || !strings.Contains(p.Detail, "agent:publish scope") {
			t.Fatalf("%d %+v", status, p)
		}
	})

	t.Run("a rule's field", func(t *testing.T) {
		m := strings.Replace(skillYAML(user, "errs", "1.0.0"), "entrypoints:", "intake:\n  - id: api_token\n    prompt: \"Your token\"\n    type: secret\n    required: true\nentrypoints:", 1)
		status, body, _ := env.uploadVersionCLIResult(user, "errs", pat, publishFiles(m), nil, "", nil)
		p := readPublishProblem(t, body)
		if status != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "intake[0].type" || !strings.HasPrefix(p.Errors[0].Message, "V10: ") {
			t.Fatalf("%d %+v", status, p)
		}
	})

	t.Run("a manifest that does not parse", func(t *testing.T) {
		m := strings.Replace(skillYAML(user, "errs", "1.0.0"), "license: Apache-2.0", "licence: Apache-2.0", 1)
		status, body, _ := env.uploadVersionCLIResult(user, "errs", pat, publishFiles(m), nil, "", nil)
		p := readPublishProblem(t, body)
		if status != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "manifest" ||
			!strings.HasPrefix(p.Errors[0].Message, "Line ") ||
			!strings.Contains(p.Errors[0].Message, `has no field "licence"`) || !strings.Contains(p.Errors[0].Message, `did you mean "license"`) ||
			strings.Contains(p.Errors[0].Message, "manifest.Manifest") {
			t.Fatalf("%d %+v", status, p)
		}
	})
}
