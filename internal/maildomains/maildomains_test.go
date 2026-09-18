package maildomains

import "testing"

// TestSharedNamesNobodyOwns: the consumer providers, the reserved names and
// their subdomains are shared; an ordinary company domain is not, and
// case, space and a trailing dot do not change the answer.
func TestSharedNamesNobodyOwns(t *testing.T) {
	for _, d := range []string{
		"gmail.com", "GMAIL.COM", " gmail.com. ", "googlemail.com", "outlook.com", "hotmail.co.uk",
		"icloud.com", "proton.me", "yahoo.co.jp", "qq.com", "mail.ru",
		"example.com", "docs.example.com", "acme.test", "anything.example", "x.invalid", "localhost",
		"",
	} {
		if !Shared(d) {
			t.Errorf("Shared(%q) = false, want true", d)
		}
	}
	for _, d := range []string{
		"acme.io", "acme.co.uk", "corp.acme.com", "secureagentry.net", "gmail.com.evil.io", "examplecorp.com",
	} {
		if Shared(d) {
			t.Errorf("Shared(%q) = true, want false", d)
		}
	}
}

// TestOfReadsTheDomain: the part after the last @, lower-cased; none for an
// address without one.
func TestOfReadsTheDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Alice@Acme.IO": "acme.io", "a@b@c.example": "c.example", "nobody": "", "x@acme.io.": "acme.io",
	} {
		if got := Of(in); got != want {
			t.Errorf("Of(%q) = %q, want %q", in, got, want)
		}
	}
}
