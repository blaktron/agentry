package api

import (
	"math"
	"regexp"
	"strings"
)

// The directory's own ID-token claims, sent by its `agentry` scope: the
// registry reads them from the directory's token alone (the callers check
// the provider), and from the token's raw claims, since no other IdP sends
// them and the identity types name only what every IdP does.
const (
	claimRememberDevice = "agentry_remember_device"
	claimDirectoryID    = "agentry_directory_id"
	claimPromoCode      = "agentry_promo_code"
)

// directoryRememberDevice reads `agentry_remember_device`: the person ticked
// "Remember this device for 30 days" on the directory's code page, in the
// sign-in this token closes. Strictly the JSON true: the claim is half of
// what mints a credential, so nothing that merely looks like yes counts. It
// asks for a remembered browser and proves nothing about a factor, which is
// `amr`'s to say.
func directoryRememberDevice(claims map[string]any) bool {
	v, ok := claims[claimRememberDevice].(bool)
	return ok && v
}

// directoryAccountID reads `agentry_directory_id`, the directory's own id for
// the account signing in: a JSON number that is a positive whole number a
// float64 holds exactly. Anything else is 0, "not sent".
func directoryAccountID(claims map[string]any) int64 {
	f, ok := claims[claimDirectoryID].(float64)
	if !ok || f < 1 || f > 1<<53 || f != math.Trunc(f) {
		return 0
	}
	return int64(f)
}

// promoCodeRE is a promo code's grammar, the billing extension's own, in
// either case: an ASCII letter or digit, then three to thirty-one ASCII
// letters, digits or hyphens. Read before upper-casing, because
// strings.ToUpper maps ſ to S and ı to I.
var promoCodeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{3,31}$`)

// PromoCodeClaim reads an `agentry_promo_code` claim, the promo code typed on
// the directory's sign-up form: a string inside the grammar once trimmed and
// upper-cased, else "". What a code is worth is an extension's to decide,
// never the core's.
func PromoCodeClaim(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	code := strings.TrimSpace(s)
	if !promoCodeRE.MatchString(code) {
		return ""
	}
	return strings.ToUpper(code)
}
