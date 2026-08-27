package auth

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

// TOTPIssuer names the service in authenticator apps. Placeholder per Q1.
const TOTPIssuer = "Agentry"

// GenerateTOTP creates a new TOTP secret for enrollment. Returns the base32
// secret and the otpauth:// provisioning URL.
func GenerateTOTP(accountName string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: TOTPIssuer, AccountName: accountName})
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
