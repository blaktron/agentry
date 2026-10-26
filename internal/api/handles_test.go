package api

import (
	"strings"
	"testing"
)

// The two reserved lists differ in exactly one cell: a first-party name is
// creatable as an org by platform staff, a root path by nobody.
func TestOrgHandleReserved(t *testing.T) {
	for _, tc := range []struct {
		handle string
		staff  bool
		want   bool
	}{
		{"ui", false, true},
		{"ui", true, true},
		// The site's own root paths: a person named `runs` would shadow the
		// runs pages.
		{"runs", false, true},
		{"runs", true, true},
		{"invitations", true, true},
		{"pricing", true, true},
		// The site's later roots: About us, the account-deleted page, the
		// Scheduled pages and the OAuth client metadata documents.
		{"aboutus", false, true},
		{"aboutus", true, true},
		{"account-deleted", true, true},
		{"scheduled", true, true},
		{"oauth", true, true},
		// The site's Report bug page.
		{"report-bug", false, true},
		{"report-bug", true, true},
		{"agentry", false, true},
		{"agentry", true, false},
		{"secureagentry", true, false},
		{"acme", false, false},
		{"acme", true, false},
	} {
		if got := orgHandleReserved(tc.handle, tc.staff); got != tc.want {
			t.Errorf("orgHandleReserved(%q, staff=%v) = %v, want %v", tc.handle, tc.staff, got, tc.want)
		}
	}
	for _, h := range []string{"ui", "runs", "invitations", "pricing", "aboutus", "account-deleted", "scheduled", "oauth", "report-bug", "agentry", "secureagentry"} {
		if !handleReserved(h) {
			t.Errorf("handleReserved(%q) = false; sign-up must refuse it", h)
		}
		if got := unreservedHandle(h); got != h+"-1" {
			t.Errorf("unreservedHandle(%q) = %q, want the suffixed form", h, got)
		}
	}
	if unreservedHandle("acme") != "acme" {
		t.Error("unreservedHandle must leave an unreserved handle alone")
	}
}

// TestHandleSeed: a JIT handle is seeded from the username the IdP asserts,
// falling back to the email's local part only when the username is absent
// or yields no valid handle.
func TestHandleSeed(t *testing.T) {
	cases := []struct{ username, email, subject, want string }{
		{"blaktron", "chris@example.test", "sub", "blaktron"},
		{"", "chris@example.test", "sub", "chris"},
		{"   ", "chris@example.test", "sub", "chris"},
		{"chris.young@contoso.test", "cy@contoso.test", "sub", "chris.young"}, // a UPN gives its local part
		{"___", "chris@example.test", "sub", "chris"},                         // no valid handle in it
		{"", "", "github-42", "github-42"},
		{"  blaktron ", "chris@example.test", "sub", "blaktron"}, // the name is trimmed
		{"@contoso.test", "chris@example.test", "sub", "chris"},  // an address with no local part
	}
	for _, c := range cases {
		if got := handleSeed(c.username, c.email, c.subject); got != c.want {
			t.Errorf("handleSeed(%q, %q, %q) = %q, want %q", c.username, c.email, c.subject, got, c.want)
		}
	}
	// The seed still goes through the grammar and the reserved list.
	if got := sanitizeHandle(handleSeed("Chris.Young", "x@y.test", "s")); got != "chris-young" {
		t.Errorf("sanitized seed = %q, want chris-young", got)
	}
	if got := sanitizeHandle(handleSeed("admin", "x@y.test", "s")); got != "admin-1" {
		t.Errorf("a reserved username = %q, want admin-1", got)
	}
	// A derived handle is lower case, letters, digits and hyphens only,
	// without edge hyphens, at most 39 characters, and never a reserved name.
	for _, tc := range []struct{ in, want string }{
		{"Chris.Young", "chris-young"},
		{"  Mixed Case  ", "mixed-case"},
		{"a_b.c", "a-b-c"},
		{"--a--", "a"},
		{"a..b", "a-b"},
		{"---", ""},
		{"", ""},
		{"ui", "ui-1"},
		{"agentry", "agentry-1"},
		{strings.Repeat("a", 39), strings.Repeat("a", 39)},
		{strings.Repeat("a", 40), strings.Repeat("a", 39)},
		{strings.Repeat("a", 50), strings.Repeat("a", 39)},
		// The cut lands on a hyphen: it does not end the handle.
		{strings.Repeat("a", 38) + "-b", strings.Repeat("a", 38)},
	} {
		if got := sanitizeHandle(tc.in); got != tc.want {
			t.Errorf("sanitizeHandle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := truncateHandle("abc-def", 4); got != "abc" {
		t.Errorf("truncateHandle(abc-def, 4) = %q, want abc", got)
	}
	if got := truncateHandle("abc", 4); got != "abc" {
		t.Errorf("truncateHandle(abc, 4) = %q, want abc", got)
	}
}

func TestHandleRequestedDetail(t *testing.T) {
	if d := handleRequestedDetail("blaktron", "blaktron"); d != nil {
		t.Errorf("agreeing handle recorded %v", d)
	}
	if d := handleRequestedDetail("", "chris"); d != nil {
		t.Errorf("no username recorded %v", d)
	}
	if d := handleRequestedDetail("blaktron", "blaktron-1a2b3c"); d["handleRequested"] != "blaktron" {
		t.Errorf("fallback not recorded: %v", d)
	}
	// Handles are case-insensitive, and the username is trimmed before it is
	// compared and before it is recorded.
	if d := handleRequestedDetail("Blaktron", "blaktron"); d != nil {
		t.Errorf("a handle differing only in case recorded %v", d)
	}
	if d := handleRequestedDetail("  blaktron ", "blaktron"); d != nil {
		t.Errorf("a padded username agreeing with the handle recorded %v", d)
	}
	if d := handleRequestedDetail("  blaktron ", "blaktron-1a2b3c"); d["handleRequested"] != "blaktron" {
		t.Errorf("padded fallback recorded %v, want the trimmed username", d)
	}
	if d := handleRequestedDetail("   ", "chris"); d != nil {
		t.Errorf("a blank username recorded %v", d)
	}
}
