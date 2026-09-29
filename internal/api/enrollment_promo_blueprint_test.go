package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/auth/oidc"
)

// The directory's sign-up form carries an optional promo code (plan
// promo-codes.md §5.1, agentry#759). These hold the blueprint to what the
// probe on the pinned image established, since a wrong tag here fails the
// whole blueprint at apply time, on a deployment, and nowhere in CI.

func accountFlows(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/compose/authentik/blueprints/agentry-account-flows.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// entry is the text of the blueprint entry whose identifiers name it, up to
// the next entry.
func entry(t *testing.T, bp, name string) string {
	t.Helper()
	i := strings.Index(bp, "name: "+name+"\n")
	if i < 0 {
		t.Fatalf("the blueprint has no entry named %s", name)
	}
	e := bp[i:]
	if j := strings.Index(e, "\n  - model:"); j >= 0 {
		e = e[:j]
	}
	return e
}

// promoOn is the one condition every promo attribute turns on: any
// non-empty AGENTRY_DIRECTORY_PROMO_FIELD. The probe found a blueprint
// cannot compare strings and !ParseJSON will not take !Env's value.
const promoOn = `!Condition [AND, !Env [AGENTRY_DIRECTORY_PROMO_FIELD, ""]]`

// TestEnrollmentPromoFieldIsOptIn: the field is hidden unless the deployment
// turns it on, and while hidden it has no initial value — a hidden field
// keeps its initial value whatever is posted, so a promo link cannot put a
// code into a form that does not show one. It is on the enrolment prompt,
// optional, and written to the account's attributes.
func TestEnrollmentPromoFieldIsOptIn(t *testing.T) {
	bp := accountFlows(t)
	field := entry(t, bp, "agentry-enrollment-promo-code")
	for _, want := range []string{
		"field_key: attributes.agentry_promo_code",
		"required: false",
		"type: !If [" + promoOn + ", text, hidden]",
		"initial_value_expression: !If [" + promoOn + ", true, false]",
		"initial_value: !If\n        - " + promoOn + "\n",
	} {
		if !strings.Contains(field, want) {
			t.Errorf("the promo field lacks %q", want)
		}
	}
	// The initial value's else branch is empty, so off there is nothing to keep.
	if !regexp.MustCompile(`(?s)initial_value: !If\n.*?\n        - ""\n`).MatchString(field) {
		t.Error(`the promo field's initial value is not "" when the field is off`)
	}
	if strings.Contains(bp, "!ParseJSON [!Env") {
		t.Error("!ParseJSON over !Env fails the blueprint on 2026.8 (agentry#759's probe)")
	}
	stage := entry(t, bp, "agentry-enrollment-prompt")
	for _, want := range []string{"- !KeyOf field-promo-code", "- !KeyOf policy-enrollment-promo-code"} {
		if !strings.Contains(stage, want) {
			t.Errorf("agentry-enrollment-prompt lacks %q", want)
		}
	}
	for _, key := range []string{"!KeyOf field-promo-code", "!KeyOf policy-enrollment-promo-code"} {
		if n := strings.Count(bp, key); n != 1 {
			t.Errorf("%s appears %d times; want once, on the enrolment prompt", key, n)
		}
	}
}

// TestEnrollmentPromoGrammarMatchesTheCore: the form's policy and the core's
// claim reader take the same codes, so a code the form accepts is one the
// registry forwards. The policy reads the value nested under attributes,
// where the prompt stage puts a dotted field key at validation.
func TestEnrollmentPromoGrammarMatchesTheCore(t *testing.T) {
	policy := entry(t, accountFlows(t), "agentry-enrollment-promo-code-grammar")
	m := regexp.MustCompile(`re\.fullmatch\(r"([^"]+)", code\)`).FindStringSubmatch(policy)
	if m == nil {
		t.Fatal("the promo grammar policy has no re.fullmatch line")
	}
	form := regexp.MustCompile(`^(?:` + m[1] + `)$`)
	for _, code := range []string{"LAUNCH", "launch-2026", "a1b2", "BY52VFT9PFBP", strings.Repeat("a", 32),
		"", "abc", "-abcd", "ab cd", "ab_cd", strings.Repeat("a", 33), "Ünicode", "a\nb"} {
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
	scope := entry(t, accountFlows(t), "agentry-remember-device")
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
