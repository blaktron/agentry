package saml

import (
	"slices"
	"strings"
)

// mfaAuthnContexts are the AuthnContextClassRef values that say the IdP
// authenticated the person with more than one factor. An
// assertion naming one is second-factor evidence for the public-publish gate,
// the organization-SSO counterpart of a directory ID token whose `amr` names
// a factor. The list is deliberately short: a password class,
// however it travelled, is one factor. docs/self-hosting.md lists the same
// values for operators; change both together.
var mfaAuthnContexts = []string{
	"https://refeds.org/profile/mfa",                    // REFEDS MFA profile
	"http://schemas.microsoft.com/claims/multipleauthn", // AD FS, Entra ID
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
}

// EntraAuthnMethodsAttribute is the attribute Entra ID puts its
// authentication methods in; it names multipleauthn after an MFA sign-in even
// when the context class says only password. It counts because
// ParseAndValidate reads attributes only from the assertion crewjam has
// verified the signature of, as it does the context class.
const EntraAuthnMethodsAttribute = "http://schemas.microsoft.com/claims/authnmethodsreferences"

// MFAAsserted reports whether the validated assertion names a second factor.
// It reads only what ParseAndValidate took from the signed assertion.
func (r *Result) MFAAsserted() bool {
	for _, ref := range r.AuthnContextClassRefs {
		if isMFAContext(ref) {
			return true
		}
	}
	for _, v := range r.Attributes[EntraAuthnMethodsAttribute] {
		if isMFAContext(v) {
			return true
		}
	}
	return false
}

func isMFAContext(v string) bool {
	return slices.Contains(mfaAuthnContexts, strings.TrimSpace(v))
}
