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
		// Every value the rule names, one by one, and in capitals.
		{[]string{"swk"}, true},
		{[]string{"sms"}, true},
		{[]string{"tel"}, true},
		{[]string{"face"}, true},
		{[]string{"fpt"}, true},
		{[]string{"iris"}, true},
		{[]string{"retina"}, true},
		{[]string{"vbm"}, true},
		{[]string{"pin"}, true},
		{[]string{"u2f"}, true},
		{[]string{"hotp"}, true},
		{[]string{"OTP"}, true},
		{[]string{"WebAuthn"}, true},
		{[]string{"U2F"}, true},
		{[]string{"HOTP"}, true},
		// The factor may come first or last, and one is enough.
		{[]string{"otp", "pwd"}, true},
		{[]string{"pwd", "kba", "hwk"}, true},
		// "pwd" and the knowledge- and possession-proof values that are not a
		// second factor are not one, and neither is anything unnamed.
		{[]string{"PWD"}, false},
		{[]string{"pop"}, false},
		{[]string{"mca"}, false},
		{[]string{""}, false},
		{[]string{"", ""}, false},
		{[]string{"unknown"}, false},
		{[]string{"mfa "}, false},
		{[]string{" mfa"}, false},
		{[]string{"mfa2"}, false},
		{[]string{"multi-factor"}, false},
		{[]string{"otpx"}, false},
		{[]string{"pwd", "unknown"}, false},
	} {
		if got := AMRNamesSecondFactor(tc.amr); got != tc.want {
			t.Errorf("AMRNamesSecondFactor(%q) = %v, want %v", tc.amr, got, tc.want)
		}
	}
}
