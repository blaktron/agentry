package api

import (
	"strings"
	"testing"
)

// The registry reads whether a directory account has a password from its
// agentry_has_password attribute (agentry#706), which only the account-flows
// blueprint keeps: one policy, run when the step is reached, on every
// binding that writes a password and on sign-in. A binding that lost it, or
// that evaluated it at planning (before the password exists), would leave
// the settings page offering "Add a password" to someone who has one.
func TestDirectoryRecordsHasPasswordBlueprint(t *testing.T) {
	entries := readAccountFlows(t)
	const policyID = "policy-record-has-password"
	var expr string
	for _, e := range entries {
		if e.ID == policyID {
			if scalar(e.Identifiers["name"]) != "agentry-record-has-password" {
				t.Fatalf("policy name = %q", scalar(e.Identifiers["name"]))
			}
			expr = scalar(e.Attrs["expression"])
		}
	}
	for _, want := range []string{`prompt.get("password")`, `"attributes.agentry_has_password"`, "bool(fresh.password)", "fresh.has_usable_password()", "User.objects.filter(pk=user.pk)", `update_fields=["attributes"]`} {
		if !strings.Contains(expr, want) {
			t.Errorf("the policy's expression lacks %s", want)
		}
	}

	bindings := map[string]bool{
		"binding-enrollment-write":      false,
		"binding-recovery-write":        false,
		"binding-password-change-write": false,
		"binding-signin-login":          false,
	}
	for _, e := range entries {
		if e.Model != "authentik_policies.policybinding" {
			continue
		}
		p, target := e.Identifiers["policy"], e.Identifiers["target"]
		if p.Tag != "!KeyOf" || p.Value != policyID || target.Tag != "!KeyOf" {
			continue
		}
		if _, ok := bindings[target.Value]; !ok {
			continue
		}
		bindings[target.Value] = true
		if scalar(e.Attrs["failure_result"]) != "true" {
			t.Errorf("%s: failure_result must be true, so a failing record never blocks the flow", target.Value)
		}
	}
	for id, bound := range bindings {
		if !bound {
			t.Errorf("the policy is not bound to %s", id)
		}
	}
	for _, e := range entries {
		if _, ok := bindings[e.ID]; !ok {
			continue
		}
		if v := scalar(e.Attrs["evaluate_on_plan"]); v == "true" {
			t.Errorf("%s evaluates on plan, before the password exists", e.ID)
		}
		if v := scalar(e.Attrs["re_evaluate_policies"]); v == "false" {
			t.Errorf("%s does not evaluate when the stage is reached", e.ID)
		}
	}
}
