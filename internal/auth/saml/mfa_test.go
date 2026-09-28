package saml

import "testing"

// An assertion is second-factor evidence (agentry#705) when its signed
// AuthnStatement names a multi-factor context class, or when Entra ID's
// authnmethodsreferences attribute names multipleauthn. The expected values
// are the published identifiers, written out, not read from the table.
func TestResultMFAAsserted(t *testing.T) {
	const amrAttr = "http://schemas.microsoft.com/claims/authnmethodsreferences"
	for _, tc := range []struct {
		name string
		res  Result
		want bool
	}{
		{"no statement", Result{}, false},
		{"password", Result{AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"}}, false},
		{"password over TLS", Result{AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}}, false},
		{"REFEDS MFA", Result{AuthnContextClassRefs: []string{"https://refeds.org/profile/mfa"}}, true},
		{"Microsoft multipleauthn as the context", Result{AuthnContextClassRefs: []string{"http://schemas.microsoft.com/claims/multipleauthn"}}, true},
		{"SAML two-factor contract", Result{AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"}}, true},
		{"time-sync token", Result{AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"}}, true},
		{"context with surrounding space", Result{AuthnContextClassRefs: []string{"  https://refeds.org/profile/mfa\n"}}, true},
		{"Entra attribute names multipleauthn", Result{
			AuthnContextClassRefs: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
			Attributes:            map[string][]string{amrAttr: {"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password", "http://schemas.microsoft.com/claims/multipleauthn"}},
		}, true},
		{"Entra attribute names a password only", Result{
			Attributes: map[string][]string{amrAttr: {"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"}},
		}, false},
		{"the multipleauthn value in some other attribute", Result{
			Attributes: map[string][]string{"department": {"http://schemas.microsoft.com/claims/multipleauthn"}},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.MFAAsserted(); got != tc.want {
				t.Fatalf("MFAAsserted() = %v, want %v", got, tc.want)
			}
		})
	}
}
