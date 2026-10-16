package api

import (
	"strings"
	"testing"
)

// TestDirectoryRememberDeviceIsOnlyAJSONTrue: the directory's
// agentry_remember_device claim is half of what mints a credential, so only
// the JSON boolean its scope mapping emits counts. A string, a number or an
// absent claim is "not asked", never a guess.
func TestDirectoryRememberDeviceIsOnlyAJSONTrue(t *testing.T) {
	for name, tc := range map[string]struct {
		claims map[string]any
		want   bool
	}{
		"true":            {map[string]any{claimRememberDevice: true}, true},
		"false":           {map[string]any{claimRememberDevice: false}, false},
		"absent":          {map[string]any{}, false},
		"no claims":       {nil, false},
		"the string true": {map[string]any{claimRememberDevice: "true"}, false},
		"one":             {map[string]any{claimRememberDevice: float64(1)}, false},
	} {
		if got := directoryRememberDevice(tc.claims); got != tc.want {
			t.Errorf("%s: directoryRememberDevice = %v, want %v", name, got, tc.want)
		}
	}
}

// TestDirectoryAccountIDIsAPositiveWholeNumber: the directory's own id for
// an account is read only as the number its mapping sends.
func TestDirectoryAccountIDIsAPositiveWholeNumber(t *testing.T) {
	for name, tc := range map[string]struct {
		v    any
		want int64
	}{
		"a number":          {float64(42), 42},
		"zero":              {float64(0), 0},
		"negative":          {float64(-3), 0},
		"a fraction":        {4.5, 0},
		"past 2^53":         {float64(1<<53) * 2, 0},
		"a string":          {"42", 0},
		"absent":            {nil, 0},
		"the largest exact": {float64(1 << 53), 1 << 53},
	} {
		claims := map[string]any{}
		if tc.v != nil {
			claims[claimDirectoryID] = tc.v
		}
		if got := directoryAccountID(claims); got != tc.want {
			t.Errorf("%s: directoryAccountID = %d, want %d", name, got, tc.want)
		}
	}
}

// TestPromoCodeClaim: the directory's agentry_promo_code claim is read as a
// string inside the billing extension's grammar, upper-cased, and as nothing
// otherwise.
func TestPromoCodeClaim(t *testing.T) {
	for in, want := range map[any]string{
		"LAUNCH-2026":           "LAUNCH-2026",
		" launch-2026 ":         "LAUNCH-2026",
		"a1b2":                  "A1B2",
		strings.Repeat("a", 32): strings.Repeat("A", 32),
		"":                      "",
		"abc":                   "",
		"-abcd":                 "",
		"ab cd":                 "",
		"ab_cd":                 "",
		strings.Repeat("a", 33): "",
		"Ünicode":               "",
		"ſale":                  "",
		"ıdea":                  "",
		1234:                    "",
		true:                    "",
	} {
		if got := PromoCodeClaim(in); got != want {
			t.Errorf("PromoCodeClaim(%#v) = %q, want %q", in, got, want)
		}
	}
	if got := PromoCodeClaim(nil); got != "" {
		t.Errorf("PromoCodeClaim(nil) = %q", got)
	}
}
