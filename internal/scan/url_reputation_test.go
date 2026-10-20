package scan

import "testing"

// TestSuspiciousURLReadsTheHostAfterUserinfo pins that the host checked is
// the one a URL parser reads: after the last "@" of the authority, with the
// port, path, query and fragment cut off, and the scheme in any case.
func TestSuspiciousURLReadsTheHostAfterUserinfo(t *testing.T) {
	for _, c := range []struct {
		url, want string
	}{
		{"https://bit.ly/x", "URL shortener hides destination"},
		{"https://user@bit.ly/x", "URL shortener hides destination"},
		{"https://a:b@tinyurl.com/x", "URL shortener hides destination"},
		{"http://x@y@bit.ly/x", "URL shortener hides destination"},
		{"https://user@bit.ly:443/x?q=1#f", "URL shortener hides destination"},
		{"https://user@bit.ly", "URL shortener hides destination"},
		{"https://user@xn--pple-43d.com/", "punycode/homograph domain"},
		{"HTTPS://user@BIT.LY/x", "URL shortener hides destination"},
		{"https://bit.ly@example.com/x", ""},
		{"https://example.com/x?next=user@bit.ly", ""},
		{"https://example.com/#user@bit.ly", ""},
		{"https://user@example.com/x", ""},
	} {
		if got := suspiciousURL(c.url); got != c.want {
			t.Errorf("suspiciousURL(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

// TestS8URLReputationReadsUserinfoURLs pins the finding through the stage.
func TestS8URLReputationReadsUserinfoURLs(t *testing.T) {
	for _, line := range []string{
		"See https://user@bit.ly/x for setup.",
		"See https://a:b@tinyurl.com/x for setup.",
	} {
		got := scannerSet(S8Metadata{}.Run(testStageContext(t), &Input{Files: files("readme.md", "# Tool\n\n"+line+"\n")}).Findings)
		if _, ok := got["S8/url-reputation"]; !ok {
			t.Errorf("%s: no S8/url-reputation (got %v)", line, got)
		}
	}
}

// TestSuspiciousURLReadsTheHostABrowserReads pins the forms that reach the
// same host as the plain link they imitate: a backslash in the authority,
// which a browser reads as "/" in an http(s) URL, and a trailing dot, which
// names the same host; with a shortener and with a punycode host each, and
// the look-alikes that do not reach it. Where a browser and a parser that
// keeps the backslash read different hosts, either reading counts.
func TestSuspiciousURLReadsTheHostABrowserReads(t *testing.T) {
	const short, puny = "URL shortener hides destination", "punycode/homograph domain"
	for _, c := range []struct {
		url, want string
	}{
		{`https://bit.ly\@example.com/x`, short},
		{`https://bit.ly\x`, short},
		{`https://user@bit.ly\x`, short},
		{`https://xn--pple-43d.com\@example.com/x`, puny},
		{"https://bit.ly./x", short},
		{"https://bit.ly.", short},
		{"https://user@tinyurl.com.:443/x", short},
		{"https://xn--pple-43d.com./", puny},
		// A parser that keeps the backslash reads bit.ly here, where a
		// browser opens example.com: either reading counts.
		{`https://example.com\@bit.ly/x`, short},
		{`https://example.com\@xn--pple-43d.com/x`, puny},
		{"https://XN--PPLE-43D.COM./", puny},
		{"https://example.com./x", ""},
		{"https://bit.ly.example.com/x", ""},
	} {
		if got := suspiciousURL(c.url); got != c.want {
			t.Errorf("suspiciousURL(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

// TestSuspiciousURLMapsTheHostAsABrowserDoes pins that the host is compared
// after the mapping a browser applies to it: the full-width, half-width
// ideographic and ideographic full stops read as ".", full-width letters
// and hyphens as ASCII, and case is folded; and after trimming what no host
// name holds, such as a comma that ends the authority. Each form is tried
// with a shortener and with a punycode host.
func TestSuspiciousURLMapsTheHostAsABrowserDoes(t *testing.T) {
	const short, puny = "URL shortener hides destination", "punycode/homograph domain"
	for _, c := range []struct {
		url, want string
	}{
		{"https://bit\u3002ly/x", short},
		{"https://bit\uFF0Ely/x", short},
		{"https://bit\uFF61ly/x", short},
		{"https://\uFF42\uFF49\uFF54\uFF0E\uFF4C\uFF59/x", short},    // every character full-width
		{"https://\uFF22\uFF29\uFF34.\uFF2C\uFF39", short},           // full-width capitals
		{"https://\uFF58\uFF4E\uFF0D\uFF0Dpple-43d\u3002com/", puny}, // a full-width "xn--"
		{"https://user@\uFF58\uFF4E--pple-43d\uFF0Ecom:443/x", puny},
		{"https://bit.ly,/x", short},
		{"https://bit.ly,", short},
		{"https://tinyurl.com,.:443/x", short},
		{"https://xn--pple-43d.com,/", puny},
		{"https://example\u3002com/x", ""},
		{"https://bit\uFF0Ely\uFF0Eexample.com/x", ""},
		{"https://[::1]:8080/x", ""},
	} {
		if got := suspiciousURL(c.url); got != c.want {
			t.Errorf("suspiciousURL(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

// TestS8URLReputationReadsEveryHiddenForm pins the finding through the stage,
// where the URL is first found in the line: the scheme in any case, a
// backslash authority and a trailing dot, with a shortener and with a
// punycode host.
func TestS8URLReputationReadsEveryHiddenForm(t *testing.T) {
	for _, line := range []string{
		"See HTTPS://bit.ly/x for setup.",
		"See Https://xn--pple-43d.com/ for setup.",
		"See hTTp://tinyurl.com/x for setup.",
		`See https://bit.ly\@example.com/x for setup.`,
		`See https://xn--pple-43d.com\@example.com/x for setup.`,
		"See https://bit.ly./x for setup.",
		"See https://xn--pple-43d.com./ for setup.",
	} {
		got := scannerSet(S8Metadata{}.Run(testStageContext(t), &Input{Files: files("readme.md", "# Tool\n\n"+line+"\n")}).Findings)
		if _, ok := got["S8/url-reputation"]; !ok {
			t.Errorf("%s: no S8/url-reputation (got %v)", line, got)
		}
	}
}
