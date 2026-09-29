package api

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/internal/auth/oidc"
)

// The directory's sign-up form carries an optional promo code (plan
// promo-codes.md §5.1, agentry#759). These hold the blueprint to what the
// probe on the pinned image established, since a wrong tag here fails the
// whole blueprint at apply time, on a deployment, and nowhere in CI but
// directory-promo.sh.

// promoBranches asserts n is the promo flag's !If — any non-empty
// AGENTRY_DIRECTORY_PROMO_FIELD, as !Condition [AND, !Env [VAR, ""]] — and
// returns its on and off branches. The probe found a blueprint cannot
// compare strings and !ParseJSON will not take !Env's value.
func promoBranches(t *testing.T, attr string, n yaml.Node) (on, off yaml.Node) {
	t.Helper()
	if n.Tag != "!If" || len(n.Content) != 3 {
		t.Fatalf("%s is not an !If of three: %s %d", attr, n.Tag, len(n.Content))
	}
	cond := n.Content[0]
	if cond.Tag != "!Condition" || len(cond.Content) != 2 || cond.Content[0].Value != "AND" {
		t.Fatalf("%s's condition is not !Condition [AND, …]", attr)
	}
	env := cond.Content[1]
	if env.Tag != "!Env" || len(env.Content) != 2 || env.Content[0].Value != "AGENTRY_DIRECTORY_PROMO_FIELD" || env.Content[1].Value != "" {
		t.Fatalf(`%s's condition is not !Env [AGENTRY_DIRECTORY_PROMO_FIELD, ""]`, attr)
	}
	return *n.Content[1], *n.Content[2]
}

func keyOfs(n yaml.Node) []string {
	var ids []string
	for _, c := range n.Content {
		if c.Tag == "!KeyOf" {
			ids = append(ids, c.Value)
		}
	}
	return ids
}

// TestEnrollmentPromoFieldIsOptIn: the field is hidden unless the deployment
// turns it on, and while hidden it has no initial value — a hidden field
// keeps its initial value whatever is posted, so a promo link cannot put a
// code into a form that does not show one. It is on the enrolment prompt,
// optional, and written to the account's attributes.
func TestEnrollmentPromoFieldIsOptIn(t *testing.T) {
	entries := readAccountFlows(t)
	field := entryByID(t, entries, "field-promo-code")
	if got := scalar(field.Attrs["field_key"]); got != "attributes.agentry_promo_code" {
		t.Errorf("field_key %q", got)
	}
	if got := scalar(field.Attrs["required"]); got != "false" {
		t.Errorf("required %q; the field is optional", got)
	}
	for attr, want := range map[string][2]string{
		"type":                     {"text", "hidden"},
		"initial_value_expression": {"true", "false"},
	} {
		on, off := promoBranches(t, attr, field.Attrs[attr])
		if on.Value != want[0] || off.Value != want[1] {
			t.Errorf("%s: on %q off %q, want %q and %q", attr, on.Value, off.Value, want[0], want[1])
		}
	}
	on, off := promoBranches(t, "initial_value", field.Attrs["initial_value"])
	if off.Value != "" {
		t.Errorf("initial_value when off is %q, want empty", off.Value)
	}
	// On, a link's code fills the field only as it is: an over-long one is
	// not cut into a different code.
	for _, want := range []string{`parse_qs(http.GET.get("query", ""))`, `(query.get("promo") or [""])[0]`, "if len(code) <= 32 else"} {
		if !strings.Contains(on.Value, want) {
			t.Errorf("initial_value when on lacks %q", want)
		}
	}

	stage := entryByID(t, entries, "stage-enrollment-prompt")
	if !slices.Contains(keyOfs(stage.Attrs["fields"]), "field-promo-code") {
		t.Error("the promo field is not a field of agentry-enrollment-prompt")
	}
	if !slices.Contains(keyOfs(stage.Attrs["validation_policies"]), "policy-enrollment-promo-code") {
		t.Error("the promo grammar policy is not a validation policy of agentry-enrollment-prompt")
	}
	raw, err := os.ReadFile(accountFlowsBlueprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"!KeyOf field-promo-code", "!KeyOf policy-enrollment-promo-code"} {
		if n := strings.Count(string(raw), key); n != 1 {
			t.Errorf("%s appears %d times; want once, on the enrolment prompt", key, n)
		}
	}
	if strings.Contains(string(raw), "!ParseJSON [!Env") {
		t.Error("!ParseJSON over !Env fails the blueprint on 2026.8 (agentry#759's probe)")
	}
}

// TestEnrollmentPromoGrammarMatchesTheCore: the form's policy and the core's
// claim reader take the same codes, so a code the form accepts is one the
// registry forwards. The policy reads the value nested under attributes,
// where the prompt stage puts a dotted field key at validation.
func TestEnrollmentPromoGrammarMatchesTheCore(t *testing.T) {
	policy := scalar(entryByID(t, readAccountFlows(t), "policy-enrollment-promo-code").Attrs["expression"])
	m := regexp.MustCompile(`re\.fullmatch\(r"([^"]+)", code\)`).FindStringSubmatch(policy)
	if m == nil {
		t.Fatal("the promo grammar policy has no re.fullmatch line")
	}
	form := regexp.MustCompile(`^(?:` + m[1] + `)$`)
	for _, code := range []string{"LAUNCH", "launch-2026", "a1b2", "BY52VFT9PFBP", strings.Repeat("a", 32),
		"", "abc", "-abcd", "ab cd", "ab_cd", strings.Repeat("a", 33), "Ünicode", "ſale", "a\nb"} {
		if got, want := form.MatchString(code), oidc.PromoCodeClaim(code) != ""; got != want {
			t.Errorf("%q: the form accepts it %v, the core %v", code, got, want)
		}
	}
	if !strings.Contains(policy, `(data.get("attributes") or {}).get("agentry_promo_code")`) {
		t.Error("the policy does not read the value nested under attributes, where validation puts it")
	}
}

// TestAgentryScopeCarriesThePromoCode: the agentry scope sends the code only
// when the account has one, beside the directory id.
func TestAgentryScopeCarriesThePromoCode(t *testing.T) {
	scope := scalar(entryByID(t, readAccountFlows(t), "scope-agentry").Attrs["expression"])
	for _, want := range []string{
		`code = str((account.attributes or {}).get("agentry_promo_code") or "").strip()`,
		"if code:\n",
		`claims["agentry_promo_code"] = code`,
	} {
		if !strings.Contains(scope, want) {
			t.Errorf("the agentry scope mapping lacks %q", want)
		}
	}
}
