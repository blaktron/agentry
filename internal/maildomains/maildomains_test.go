package maildomains

import (
	"strings"
	"testing"
)

// TestSharedNamesNobodyOwns: the consumer providers, the reserved names and
// their subdomains are shared; an ordinary company domain is not, and
// case, space and a trailing dot do not change the answer.
func TestSharedNamesNobodyOwns(t *testing.T) {
	// Every domain on the list, spelled out: dropping one would let a person
	// at that provider claim it for an organization.
	for _, d := range []string{
		"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
		"hotmail.fr", "hotmail.de", "hotmail.it", "hotmail.es", "outlook.de", "outlook.fr", "live.co.uk",
		"live.fr", "live.de", "icloud.com", "me.com", "mac.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr",
		"yahoo.de", "yahoo.it", "yahoo.es", "yahoo.ca", "yahoo.com.au", "yahoo.co.jp", "yahoo.com.br", "ymail.com",
		"rocketmail.com", "aol.com", "aim.com", "protonmail.com", "proton.me", "pm.me", "protonmail.ch",
		"tutanota.com", "tutanota.de", "tuta.io", "tuta.com", "fastmail.com", "fastmail.fm", "hey.com", "duck.com",
		"mailbox.org", "posteo.de", "posteo.net", "runbox.com", "hushmail.com", "zoho.com", "zohomail.com",
		"mail.com", "email.com", "usa.com", "gmx.com", "gmx.de", "gmx.net", "gmx.at", "gmx.ch", "web.de",
		"t-online.de", "freenet.de", "yandex.com", "yandex.ru", "ya.ru", "mail.ru", "bk.ru", "inbox.ru", "list.ru",
		"rambler.ru", "qq.com", "foxmail.com", "163.com", "126.com", "yeah.net", "sina.com", "sina.cn", "sohu.com",
		"aliyun.com", "naver.com", "daum.net", "hanmail.net", "kakao.com", "orange.fr", "wanadoo.fr", "free.fr",
		"laposte.net", "sfr.fr", "libero.it", "virgilio.it", "tiscali.it", "alice.it", "seznam.cz", "centrum.cz",
		"wp.pl", "o2.pl", "onet.pl", "interia.pl", "btinternet.com", "sky.com", "virginmedia.com", "talktalk.net",
		"blueyonder.co.uk", "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "cox.net", "charter.net",
		"bellsouth.net", "earthlink.net", "optonline.net", "shaw.ca", "rogers.com", "sympatico.ca", "telus.net",
		"videotron.ca", "bigpond.com", "optusnet.com.au", "iinet.net.au", "xtra.co.nz", "uol.com.br", "bol.com.br",
		"terra.com.br", "example.com", "example.net", "example.org",
	} {
		if !Shared(d) {
			t.Errorf("Shared(%q) = false, want true: a mail provider or documentation name", d)
		}
		// A provider's subdomain is as shared as the provider.
		if !Shared("mail." + d) {
			t.Errorf("Shared(%q) = false, want true: a subdomain of a shared name", "mail."+d)
		}
	}
	// The top-level names reserved for testing and documentation, by
	// themselves and as the end of any name.
	for _, tld := range []string{
		"test", "example", "invalid", "localhost", "local",
	} {
		for _, d := range []string{tld, "acme." + tld, "corp.acme." + tld, "ACME." + strings.ToUpper(tld), "acme." + tld + "."} {
			if !Shared(d) {
				t.Errorf("Shared(%q) = false, want true: ends in the reserved name %q", d, tld)
			}
		}
	}

	for _, d := range []string{
		"gmail.com", "GMAIL.COM", " gmail.com. ", "googlemail.com", "outlook.com", "hotmail.co.uk",
		"icloud.com", "proton.me", "yahoo.co.jp", "qq.com", "mail.ru",
		"example.com", "docs.example.com", "acme.test", "anything.example", "x.invalid", "localhost",
		"",
		// White space and the dot of an absolute name, in any order and case.
		"   ", ".", "gmail.com .", " Gmail.Com. ", "\tgmail.com\n", "EXAMPLE.ORG",
		// Several levels below a shared name or a reserved top-level name.
		"a.b.gmail.com", "a.b.c.outlook.com", "regional.yahoo.co.uk", "one.two.acme.test", "a.b.localhost",
	} {
		if !Shared(d) {
			t.Errorf("Shared(%q) = false, want true", d)
		}
	}
	for _, d := range []string{
		"acme.io", "acme.co.uk", "corp.acme.com", "secureagentry.net", "gmail.com.evil.io", "examplecorp.com",
		// A shared name is matched by whole labels, never as a suffix of text
		// or as a label in the middle; a bare top-level name is nobody's.
		"notgmail.com", "xgmail.com", "gmail.co", "gmail.com.au", "gmail", "com", "co.uk", "io", "gmail.example.io",
		"testing.io", "example-corp.com", "acme.localhosting", "acme.locale", "acme.invalids",
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
		"x@ acme.io ": "acme.io", "x@\tACME.io.": "acme.io", "@acme.io": "acme.io", "": "", "x@": "", "x@.": "",
		"x@sub.acme.io": "sub.acme.io", "first@a.io@second@b.io": "b.io",
	} {
		if got := Of(in); got != want {
			t.Errorf("Of(%q) = %q, want %q", in, got, want)
		}
	}
}
