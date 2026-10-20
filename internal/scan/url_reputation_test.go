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
