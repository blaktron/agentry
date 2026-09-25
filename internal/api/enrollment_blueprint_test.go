package api

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The directory's enrolment prompt refuses a username the registry would
// not take as a handle (agentry#590, agentry-web#417): the username seeds
// the handle at the first sign-in (DEV-142). Its policy carries a copy of
// the handle grammar and of the names no sign-up may take, because authentik
// cannot ask the registry. This holds the copy to the code, so a handle rule
// that changes here without the blueprint fails CI instead of letting the
// form accept a username the registry then renames.
func TestEnrollmentUsernamePolicyMatchesHandleRules(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/compose/authentik/blueprints/agentry-account-flows.yaml")
	if err != nil {
		t.Fatal(err)
	}
	bp := string(raw)

	m := regexp.MustCompile(`(?m)^\s*HANDLE = r"([^"]*)"$`).FindStringSubmatch(bp)
	if m == nil {
		t.Fatal("the enrolment username policy has no HANDLE line")
	}
	if m[1] != reHandle.String() {
		t.Errorf("blueprint HANDLE = %q, reHandle = %q", m[1], reHandle.String())
	}

	m = regexp.MustCompile(`(?m)^\s*RESERVED = \{([^}]*)\}$`).FindStringSubmatch(bp)
	if m == nil {
		t.Fatal("the enrolment username policy has no RESERVED line")
	}
	var got []string
	for _, q := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		got = append(got, q[1])
	}
	var want []string
	for h := range pathHandles {
		want = append(want, h)
	}
	for h := range firstPartyHandles {
		want = append(want, h)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("blueprint RESERVED = %v\nwant pathHandles ∪ firstPartyHandles = %v", got, want)
	}
	for _, h := range want {
		if !handleReserved(h) {
			t.Errorf("%q is in the blueprint's list but a sign-up may take it", h)
		}
	}

	// Bound to the enrolment prompt, and only there: recovery never sets a
	// username, and the directory's existing users are not re-checked.
	stage := bp[strings.Index(bp, "name: agentry-enrollment-prompt"):]
	stage = stage[:strings.Index(stage, "- model:")]
	if !strings.Contains(stage, "- !KeyOf policy-enrollment-username") {
		t.Error("the username policy is not a validation policy of agentry-enrollment-prompt")
	}
	if n := strings.Count(bp, "!KeyOf policy-enrollment-username"); n != 1 {
		t.Errorf("the username policy is bound %d times; want once, on the enrolment prompt", n)
	}
}
