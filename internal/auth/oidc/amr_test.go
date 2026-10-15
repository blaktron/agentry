package oidc

import "testing"

// One rule decides whether an ID token's `amr` names a second factor, for the
// directory's callback and an organization's.
func TestAMRNamesSecondFactor(t *testing.T) {
	for _, tc := range []struct {
		amr  []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"pwd"}, false},
		{[]string{"pwd", "kba"}, false},
		{[]string{"mfa"}, true},
		{[]string{"pwd", "otp"}, true},
		{[]string{"hwk"}, true},
		{[]string{"PWD", "MFA"}, true},
		{[]string{"webauthn"}, true},
		{[]string{"totp"}, true},
	} {
		if got := AMRNamesSecondFactor(tc.amr); got != tc.want {
			t.Errorf("AMRNamesSecondFactor(%q) = %v, want %v", tc.amr, got, tc.want)
		}
	}
}
