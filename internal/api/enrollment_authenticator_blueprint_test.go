package api

import (
	"slices"
	"strings"
	"testing"
)

// Sign-up may skip the authenticator setup (agentry#894, DEV-211): a choice
// at order 35, after the account is written, and a policy on the setup's
// binding at 40 that skips it only on an explicit "later". These pin the
// settings that decide which way it fails, since a binding policy that fails
// skips its stage: an error, a missing plan or any other answer must show the
// setup, never skip it.

// flowBinding finds the enrolment flow's binding of this stage.
func flowBinding(t *testing.T, entries []blueprintEntry, stage string) blueprintEntry {
	t.Helper()
	for _, e := range entries {
		if e.Model != "authentik_flows.flowstagebinding" {
			continue
		}
		tg, st := e.Identifiers["target"], e.Identifiers["stage"]
		if tg.Tag == "!KeyOf" && tg.Value == "flow-enrollment" && st.Tag == "!KeyOf" && st.Value == stage {
			return e
		}
	}
	t.Fatalf("the enrolment flow does not bind %s", stage)
	return blueprintEntry{}
}

func order(e blueprintEntry) string { n := e.Identifiers["order"]; return n.Value }

func TestEnrollmentAuthenticatorSetupIsSkippable(t *testing.T) {
	entries := readAccountFlows(t)

	// The choice comes after the write and before the setup.
	write := flowBinding(t, entries, "stage-enrollment-user-write")
	choice := flowBinding(t, entries, "stage-enrollment-authenticator-choice")
	setup := flowBinding(t, entries, "stage-totp-setup")
	if order(write) != "20" || order(choice) != "35" || order(setup) != "40" {
		t.Errorf("orders: write %s, choice %s, setup %s; want 20, 35, 40", order(write), order(choice), order(setup))
	}

	// The setup's binding reads the choice when the setup is reached: on the
	// plan, the choice has not been made.
	if setup.ID != "binding-enrollment-totp" {
		t.Fatalf("the setup's binding has id %q", setup.ID)
	}
	for attr, want := range map[string]string{"evaluate_on_plan": "false", "re_evaluate_policies": "true", "policy_engine_mode": "all"} {
		if got := scalar(setup.Attrs[attr]); got != want {
			t.Errorf("the setup's binding %s = %q, want %q", attr, got, want)
		}
	}
	pb := bindingTo(t, entries, "binding-enrollment-totp", "policy-enrollment-authenticator-wanted")
	for attr, want := range map[string]string{"failure_result": "true", "negate": "false", "enabled": "true"} {
		if got := scalar(pb.Attrs[attr]); got != want {
			t.Errorf("the choice policy's binding %s = %q, want %q (an error must show the setup)", attr, got, want)
		}
	}

	// Only an explicit "later" skips; no plan shows the setup.
	policy := scalar(entryByID(t, entries, "policy-enrollment-authenticator-wanted").Attrs["expression"])
	for _, want := range []string{
		"if plan is None:\n    return True",
		`return prompt.get("agentry_authenticator_choice") != "later"`,
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the choice policy lacks %q", want)
		}
	}

	// The field: a required radio of exactly now and later, starting at now,
	// on a flat key (a dotted one would replace the form's nested promo code
	// when the stage's data is merged in).
	field := entryByID(t, entries, "field-authenticator-choice")
	for attr, want := range map[string]string{
		"field_key": "agentry_authenticator_choice", "type": "radio-button-group", "required": "true",
		"initial_value": "now", "initial_value_expression": "false", "placeholder_expression": "true",
	} {
		if got := scalar(field.Attrs[attr]); got != want {
			t.Errorf("the choice field's %s = %q, want %q", attr, got, want)
		}
	}
	choices := scalar(field.Attrs["placeholder"])
	if strings.Count(choices, `"value":`) != 2 || !strings.Contains(choices, `"value": "now"`) || !strings.Contains(choices, `"value": "later"`) {
		t.Errorf("the choices are not exactly now and later: %s", choices)
	}
	stage := entryByID(t, entries, "stage-enrollment-authenticator-choice")
	if got := keyOfs(stage.Attrs["fields"]); !slices.Equal(got, []string{"field-authenticator-intro", "field-authenticator-choice"}) {
		t.Errorf("the choice stage's fields are %v", got)
	}

	// Recovery still makes an account without an authenticator set one up
	// before it may choose a new password: a mailbox alone resets nothing.
	recovery := entryByID(t, entries, "stage-recovery-mfa")
	if got := scalar(recovery.Attrs["not_configured_action"]); got != "configure" {
		t.Errorf("recovery's not_configured_action = %q, want configure", got)
	}
	if !slices.Contains(keyOfs(recovery.Attrs["configuration_stages"]), "stage-totp-setup") {
		t.Error("recovery does not configure the TOTP setup for an account without an authenticator")
	}
}
