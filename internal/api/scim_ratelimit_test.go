package api_test

// SCIM's rate class: one bucket per organization, since a
// directory syncs from one place and a token is the organization's. Both
// halves are tested: a sync of realistic size goes through
// untouched, and a burst beyond the budget is refused, with the headers and
// the SCIM error body an IdP retries on, while another organization's
// directory is unaffected.

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

func TestSCIMBudgetAdmitsASyncAndRefusesTheBurstPerOrganization(t *testing.T) {
	const budget, users = 400, 300
	env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.SCIMPerMin = budget })
	scim, _ := env.scimOrg(t, "scimrl")
	other, _ := env.scimOrg(t, "scimrl2")

	// The sync: every user provisioned, none refused, and the budget told
	// back on each answer.
	for i := 0; i < users; i++ {
		email := fmt.Sprintf("sync-%d-%s@acme.example", i, env.sfx)
		res := env.do(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": email,
			"emails":   []map[string]any{{"value": email, "primary": true}},
			"active":   true,
		})
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("user %d of a %d-user sync under a budget of %d: %d", i+1, users, budget, res.StatusCode)
		}
		if res.Header.Get("RateLimit-Limit") != strconv.Itoa(budget) {
			t.Fatalf("RateLimit-Limit = %q, want %d", res.Header.Get("RateLimit-Limit"), budget)
		}
	}

	// The burst: reads until the budget runs out. It must, well inside the
	// refill a slow runner allows while the loop runs.
	var refused *http.Response
	var body string
	for i := 0; i < 4*budget && refused == nil; i++ {
		res := env.do(scim, http.MethodGet, "/scim/v2/Users", nil)
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		switch res.StatusCode {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			refused, body = res, string(b)
		default:
			t.Fatalf("read %d of the burst: %d %s", i+1, res.StatusCode, b)
		}
	}
	if refused == nil {
		t.Fatalf("%d reads past a %d-user sync were never refused under a budget of %d", 4*budget, users, budget)
	}
	if refused.Header.Get("Retry-After") == "" || refused.Header.Get("RateLimit-Remaining") != "0" {
		t.Fatalf("429 headers: Retry-After %q, RateLimit-Remaining %q", refused.Header.Get("Retry-After"), refused.Header.Get("RateLimit-Remaining"))
	}
	if ct := refused.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") ||
		!strings.Contains(body, "urn:ietf:params:scim:api:messages:2.0:Error") || !strings.Contains(body, `"status":"429"`) {
		t.Fatalf("429 body is not a SCIM error: %s %s", ct, body)
	}

	// Another organization's directory has its own budget.
	res := env.do(other, http.MethodGet, "/scim/v2/Users", nil)
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a second organization beside one over its budget: %d", res.StatusCode)
	}
}
