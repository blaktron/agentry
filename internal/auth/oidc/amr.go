package oidc

import "strings"

// AMRNamesSecondFactor reports whether an ID token's `amr` names a second
// factor: the RFC 8176 values for possession, biometric and OTP factors,
// "mfa" itself, and the provider-specific spellings seen in practice. "pwd"
// alone is not one. It is the one rule for the directory's sign-in
// (agentry#23) and an organization's OIDC connection (agentry#705).
func AMRNamesSecondFactor(amr []string) bool {
	for _, m := range amr {
		switch strings.ToLower(m) {
		case "mfa", "otp", "hwk", "swk", "sms", "tel", "face", "fpt", "iris", "retina", "vbm", "pin", "totp", "webauthn", "u2f", "hotp":
			return true
		}
	}
	return false
}
