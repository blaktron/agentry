package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/internal/auth/social"
)

// The directory's half of remembered browsers (agentry#671, DEV-163) is
// configuration, not code: a blueprint and a template the directory applies.
// Two of its settings decide whether it fails open, and a probe of the pinned
// directory found both by getting them wrong, so they are pinned here:
//
//   - the sign-in's MFA binding must evaluate its policies in mode `all`. The
//     stock binding already carries authentik's passwordless-WebAuthn policy,
//     which passes, so under the default `any` the skip policy's "no" changed
//     nothing and every browser was asked for the code;
//   - our policy bindings must set failure_result: a policy that raises counts
//     as failed, and a failed binding policy skips its stage, so without it an
//     exception in the skip policy would skip the code.
//
// The rest holds the two sides to the same names: the cookie the registry
// sets and the skip policy reads, the intent cookie the template sets and the
// intent policy reads, and the scope and claim the registry asks for.

const (
	accountFlowsBlueprint = "../../deploy/compose/authentik/blueprints/agentry-account-flows.yaml"
	flowTemplate          = "../../deploy/compose/authentik/templates/if/flow.html"
)

// blueprintEntry is one entry of a blueprint, with the custom tags (!Find,
// !KeyOf) kept as the tagged nodes yaml.v3 reads them as.
type blueprintEntry struct {
	Model       string               `yaml:"model"`
	ID          string               `yaml:"id"`
	Identifiers map[string]yaml.Node `yaml:"identifiers"`
	Attrs       map[string]yaml.Node `yaml:"attrs"`
}

func readAccountFlows(t *testing.T) []blueprintEntry {
	t.Helper()
	raw, err := os.ReadFile(accountFlowsBlueprint)
	if err != nil {
		t.Fatal(err)
	}
	var bp struct {
		Entries []blueprintEntry `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &bp); err != nil {
		t.Fatal(err)
	}
	return bp.Entries
}

// entryByID finds the entry the blueprint gives this id.
func entryByID(t *testing.T, entries []blueprintEntry, id string) blueprintEntry {
	t.Helper()
	for _, e := range entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("the account-flows blueprint has no entry with id %q", id)
	return blueprintEntry{}
}

// bindingTo finds the policy binding whose target and policy are the given
// !KeyOf ids.
func bindingTo(t *testing.T, entries []blueprintEntry, target, policy string) blueprintEntry {
	t.Helper()
	for _, e := range entries {
		if e.Model != "authentik_policies.policybinding" {
			continue
		}
		tg, pl := e.Identifiers["target"], e.Identifiers["policy"]
		if tg.Tag == "!KeyOf" && tg.Value == target && pl.Tag == "!KeyOf" && pl.Value == policy {
			return e
		}
	}
	t.Fatalf("no policy binding of %s to %s", policy, target)
	return blueprintEntry{}
}

func scalar(n yaml.Node) string { return n.Value }

// findsName says whether a !Find identifier names this object, e.g.
// [authentik_flows.flow, [slug, default-authentication-flow]].
func findsName(n yaml.Node, value string) bool {
	if n.Tag != "!Find" || len(n.Content) != 2 || len(n.Content[1].Content) != 2 {
		return false
	}
	return n.Content[1].Content[1].Value == value
}

func TestDirectoryRememberBlueprint(t *testing.T) {
	entries := readAccountFlows(t)

	mfa := entryByID(t, entries, "binding-signin-mfa")
	login := entryByID(t, entries, "binding-signin-login")
	for name, b := range map[string]struct {
		e     blueprintEntry
		order string
		stage string
	}{
		"mfa":   {mfa, "30", "default-authentication-mfa-validation"},
		"login": {login, "100", "default-authentication-login"},
	} {
		// Restated by the shipped identifiers, so the shipped binding is
		// updated rather than a second one created beside it.
		if b.e.Model != "authentik_flows.flowstagebinding" || scalar(b.e.Identifiers["order"]) != b.order ||
			!findsName(b.e.Identifiers["stage"], b.stage) || !findsName(b.e.Identifiers["target"], "default-authentication-flow") {
			t.Errorf("%s binding does not restate the shipped sign-in binding (order %s, stage %s)", name, b.order, b.stage)
		}
		// Evaluated when the stage is reached: the cookie arrives with the
		// executor's requests and the factor is validated after planning.
		if scalar(b.e.Attrs["evaluate_on_plan"]) != "false" || scalar(b.e.Attrs["re_evaluate_policies"]) != "true" {
			t.Errorf("%s binding: evaluate_on_plan=%q re_evaluate_policies=%q, want false and true",
				name, scalar(b.e.Attrs["evaluate_on_plan"]), scalar(b.e.Attrs["re_evaluate_policies"]))
		}
	}
	if got := scalar(mfa.Attrs["policy_engine_mode"]); got != "all" {
		t.Errorf("the MFA binding's policy_engine_mode is %q, want all: under any, the stock passwordless policy passes and the skip is ignored", got)
	}

	skip := bindingTo(t, entries, "binding-signin-mfa", "policy-remembered-browser-skip")
	intent := bindingTo(t, entries, "binding-signin-login", "policy-remember-intent")
	for name, b := range map[string]blueprintEntry{"skip": skip, "intent": intent} {
		if scalar(b.Attrs["failure_result"]) != "true" {
			t.Errorf("the %s policy's binding has failure_result %q, want true: a policy that raises would otherwise skip its stage", name, scalar(b.Attrs["failure_result"]))
		}
	}
	// authentik's own passwordless policy is bound to the MFA binding at
	// order 10; a binding's identifiers include its order, so ours must not
	// collide with it and replace it.
	if scalar(skip.Identifiers["order"]) == "10" {
		t.Error("the skip policy's binding takes order 10, which is the stock passwordless policy's")
	}

	skipExpr := scalar(entryByID(t, entries, "policy-remembered-browser-skip").Attrs["expression"])
	// The one "skip" answer is behind the registry's explicit yes.
	if strings.Count(skipExpr, "return False") != 1 ||
		!regexp.MustCompile(`status_code == 200 and answer\.json\(\)\.get\("trusted"\) is True:\n\s+ak_logger\.info\([^\n]*\)\n\s+return False`).MatchString(skipExpr) {
		t.Error("the skip policy returns False somewhere other than directly after the registry's explicit trusted:true")
	}
	if !strings.Contains(skipExpr, `COOKIES.get("`+trustedDeviceCookieName+`")`) {
		t.Errorf("the skip policy does not read the registry's cookie %q", trustedDeviceCookieName)
	}
	if !strings.Contains(skipExpr, `"/internal/directory/trusted-device"`) {
		t.Error("the skip policy does not call the registry's check route")
	}
	for _, line := range strings.Split(skipExpr, "\n") {
		if strings.Contains(line, "ak_logger") && (strings.Contains(line, "cookie") || strings.Contains(line, "secret")) {
			t.Errorf("the skip policy logs a credential: %s", strings.TrimSpace(line))
		}
	}

	scope := entryByID(t, entries, "scope-agentry")
	if got := scalar(scope.Attrs["scope_name"]); got != social.ScopeAgentry {
		t.Errorf("the scope mapping answers %q; the registry asks for %q", got, social.ScopeAgentry)
	}
	if !strings.Contains(scalar(scope.Attrs["expression"]), `"agentry_remember_device"`) {
		t.Error("the scope mapping does not emit agentry_remember_device, the claim the registry reads")
	}

	intentExpr := scalar(entryByID(t, entries, "policy-remember-intent").Attrs["expression"])
	if !strings.Contains(intentExpr, `"mfa_devices" in args`) {
		t.Error("the intent policy does not require a validated factor before carrying the choice")
	}
	tmpl, err := os.ReadFile(flowTemplate)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const COOKIE = "([^"]+)";`).FindSubmatch(tmpl)
	if m == nil {
		t.Fatal("the template names no intent cookie")
	}
	intentCookie := string(m[1])
	// On https the page writes the __Host- name and the policy reads only
	// it, so a sibling host cannot plant a ticked box; plain http has no
	// prefix to use.
	if !strings.Contains(string(tmpl), `(https ? "__Host-" : "") + COOKIE`) ||
		!strings.Contains(intentExpr, `"__Host-`+intentCookie+`" if req is not None and req.is_secure() else "`+intentCookie+`"`) {
		t.Error("the template's intent cookie and the intent policy's do not match, or one of them dropped the __Host- prefix on https")
	}
	if !strings.Contains(string(tmpl), "box.checked = false;") || !strings.Contains(string(tmpl), "setIntent(false);") {
		t.Error("the template no longer starts the box unticked and the intent cleared")
	}
	// Only the sign-in consults the choice; the box on another flow's code
	// page (recovery) would be a promise nothing keeps.
	if !strings.Contains(string(tmpl), `{% if flow.slug == "default-authentication-flow" %}`) {
		t.Error("the template offers the box outside the sign-in flow")
	}
}
