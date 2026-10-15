package auth

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

// TOTPIssuer names the service in authenticator apps when the deployment
// has no name of its own (config brand.name / Config.DisplayName).
const TOTPIssuer = "Agentry"

// GenerateTOTP creates a new TOTP secret for enrollment. Returns the base32
// secret and the otpauth:// provisioning URL. issuer is what the
// authenticator app shows; empty means TOTPIssuer.
func GenerateTOTP(issuer, accountName string) (secret, url string, err error) {
	if issuer == "" {
		issuer = TOTPIssuer
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: accountName})
	if err != nil {
		return "", "", fmt.Errorf("auth: totp generate: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP checks a 6-digit code against the secret (±1 step skew is the
// library default).
func ValidateTOTP(code, secret string) bool {
	return totp.Validate(code, secret)
}

// TestTOTPCode computes the current code for a secret. Exported for tests
// that must complete an enrollment; never call it in serving paths.
func TestTOTPCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
