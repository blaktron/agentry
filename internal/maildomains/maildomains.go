// Package maildomains answers one question: is this mail domain one that
// no single organization owns? An organization is keyed on the domain of
// its creator's verified address, and a person at gmail.com must not be
// able to claim gmail.com for their organization — nor be told that
// "gmail.com is registered to Acme" — so an address at a shared domain
// records no domain at all.
//
// The list is maintained by hand and is deliberately conservative: the
// large consumer providers, their regional and legacy names, and the names
// the IETF reserves for documentation and testing (RFC 2606, RFC 6761),
// which nobody can own. A domain that is not listed is treated as an
// organization's own, which is the safe direction: the worst a missing
// entry does is let one person claim a provider's domain for their
// organization, which DNS verification will never confirm and platform
// staff can undo.
package maildomains

import "strings"

// shared is the set of exact domains no organization owns.
var shared = map[string]bool{
	// Google, Microsoft, Apple, Yahoo and their legacy names.
	"gmail.com": true, "googlemail.com": true,
	"outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true,
	"hotmail.co.uk": true, "hotmail.fr": true, "hotmail.de": true, "hotmail.it": true, "hotmail.es": true,
	"outlook.de": true, "outlook.fr": true, "live.co.uk": true, "live.fr": true, "live.de": true,
	"icloud.com": true, "me.com": true, "mac.com": true,
	"yahoo.com": true, "yahoo.co.uk": true, "yahoo.fr": true, "yahoo.de": true, "yahoo.it": true,
	"yahoo.es": true, "yahoo.ca": true, "yahoo.com.au": true, "yahoo.co.jp": true, "yahoo.com.br": true,
	"ymail.com": true, "rocketmail.com": true, "aol.com": true, "aim.com": true,
	// Privacy-minded and independent providers.
	"protonmail.com": true, "proton.me": true, "pm.me": true, "protonmail.ch": true,
	"tutanota.com": true, "tutanota.de": true, "tuta.io": true, "tuta.com": true,
	"fastmail.com": true, "fastmail.fm": true, "hey.com": true, "duck.com": true,
	"mailbox.org": true, "posteo.de": true, "posteo.net": true, "runbox.com": true, "hushmail.com": true,
	"zoho.com": true, "zohomail.com": true, "mail.com": true, "email.com": true, "usa.com": true,
	"gmx.com": true, "gmx.de": true, "gmx.net": true, "gmx.at": true, "gmx.ch": true,
	"web.de": true, "t-online.de": true, "freenet.de": true,
	"yandex.com": true, "yandex.ru": true, "ya.ru": true, "mail.ru": true, "bk.ru": true,
	"inbox.ru": true, "list.ru": true, "rambler.ru": true,
	"qq.com": true, "foxmail.com": true, "163.com": true, "126.com": true, "yeah.net": true,
	"sina.com": true, "sina.cn": true, "sohu.com": true, "aliyun.com": true,
	"naver.com": true, "daum.net": true, "hanmail.net": true, "kakao.com": true,
	"orange.fr": true, "wanadoo.fr": true, "free.fr": true, "laposte.net": true, "sfr.fr": true,
	"libero.it": true, "virgilio.it": true, "tiscali.it": true, "alice.it": true,
	"seznam.cz": true, "centrum.cz": true, "wp.pl": true, "o2.pl": true, "onet.pl": true, "interia.pl": true,
	"btinternet.com": true, "sky.com": true, "virginmedia.com": true, "talktalk.net": true, "blueyonder.co.uk": true,
	"comcast.net": true, "verizon.net": true, "att.net": true, "sbcglobal.net": true, "cox.net": true,
	"charter.net": true, "bellsouth.net": true, "earthlink.net": true, "optonline.net": true,
	"shaw.ca": true, "rogers.com": true, "sympatico.ca": true, "telus.net": true, "videotron.ca": true,
	"bigpond.com": true, "optusnet.com.au": true, "iinet.net.au": true, "xtra.co.nz": true,
	"uol.com.br": true, "bol.com.br": true, "terra.com.br": true,
	// Names nobody owns: the IETF's documentation domains.
	"example.com": true, "example.net": true, "example.org": true,
}

// reservedTLDs are the top-level names reserved for testing and
// documentation (RFC 2606 §2, RFC 6761): no organization has an address
// there, and a registry's own tests do.
var reservedTLDs = map[string]bool{
	"test": true, "example": true, "invalid": true, "localhost": true, "local": true,
}

// Shared reports whether domain is one no single organization owns: a
// public mail provider, an IETF-reserved name, or a subdomain of either.
// The comparison ignores case, surrounding space and a trailing dot.
func Shared(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	if d == "" {
		return true
	}
	labels := strings.Split(d, ".")
	if reservedTLDs[labels[len(labels)-1]] {
		return true
	}
	// The domain itself, then each parent: mail.example.com is as shared
	// as example.com, and a provider's regional subdomain as its parent.
	for i := range labels {
		if shared[strings.Join(labels[i:], ".")] {
			return true
		}
	}
	return false
}

// Of returns the domain of an email address, lower-cased, or "" when the
// address has none.
func Of(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(email[at+1:], ".")))
}
