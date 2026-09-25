package registry

import "testing"

// atStaffDomain compares the address's domain to the staff domain as plain
// ASCII (agentry#525, kept by agentry#556): strings.ToLower folds the Kelvin
// sign (U+212A) to "k" and a dotted capital I (U+0130) to "i", so an
// internationalised look-alike of a staff domain holding a k or an i would
// otherwise match. A subdomain, a suffix and an unverified address never do.
func TestAtStaffDomainComparesAsASCII(t *testing.T) {
	s := &Service{staffOrg: "agentry", staffDomain: "kiln.example"}
	for _, c := range []struct {
		email string
		want  bool
	}{
		{"ops@kiln.example", true},
		{"ops@KILN.Example", true},
		{"ops@kiln.example.", true},
		{"ops@\u212Ailn.example", false},
		{"ops@k\u0130ln.example", false},
		{"ops@xn--iln-9wa.example", false},
		{"ops@sub.kiln.example", false},
		{"ops@kiln.example.evil", false},
		{"ops@evilkiln.example", false},
		{"kiln.example", false},
		{"", false},
	} {
		if got := s.atStaffDomain(c.email, true); got != c.want {
			t.Errorf("%q: %v, want %v", c.email, got, c.want)
		}
	}
	if s.atStaffDomain("ops@kiln.example", false) {
		t.Error("an unverified address must never match")
	}
	if (&Service{}).atStaffDomain("ops@kiln.example", true) {
		t.Error("no staff domain configured must never match")
	}
}
