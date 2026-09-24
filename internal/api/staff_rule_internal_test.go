package api

import (
	"testing"

	"github.com/blaktron/agentry/internal/auth/social"
)

// staffRule compares the asserted address's domain to the staff domain as
// plain ASCII (agentry#525): strings.ToLower folds the Kelvin sign (U+212A)
// to "k" and a dotted capital I (U+0130) to "i", so an internationalised
// look-alike of a staff domain holding a k or an i would otherwise match.
func TestStaffRuleComparesTheDomainAsASCII(t *testing.T) {
	for _, c := range []struct {
		email string
		want  staffGrant
	}{
		{"ops@kiln.example", staffByDomain},
		{"ops@KILN.Example", staffByDomain},
		{"ops@kiln.example.", staffByDomain},
		{"ops@Kiln.example", staffByNone},
		{"ops@kİln.example", staffByNone},
		{"ops@xn--iln-9wa.example", staffByNone},
		{"ops@sub.kiln.example", staffByNone},
		{"ops@kiln.example.evil", staffByNone},
		{"kiln.example", staffByNone},
		{"", staffByNone},
	} {
		id := &social.Identity{Email: c.email, EmailVerified: true}
		if got := staffRule("", "kiln.example", id); got != c.want {
			t.Errorf("%q: %q, want %q", c.email, got, c.want)
		}
	}
	unverified := &social.Identity{Email: "ops@kiln.example"}
	if got := staffRule("", "kiln.example", unverified); got != staffByNone {
		t.Errorf("an unverified assertion: %q", got)
	}
	both := &social.Identity{Email: "ops@kiln.example", EmailVerified: true, Groups: []string{"staff"}}
	if got := staffRule("staff", "kiln.example", both); got != staffByGroupDomain {
		t.Errorf("group and domain: %q", got)
	}
	if got := staffRule("", "", both); got != staffByNone {
		t.Errorf("nothing configured: %q", got)
	}
}
