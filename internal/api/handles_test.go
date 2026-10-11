package api

import "testing"

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
		// The site's own root paths (plan web-dashboard-shell §4, agentry#448):
		// a person named `runs` would shadow the runs pages.
		{"runs", false, true},
		{"runs", true, true},
		{"invitations", true, true},
		{"pricing", true, true},
		// The site's later roots: About us (agentry#1083, plan
		// web-landing-page.md M0), the account-deleted page (agentry-web#297),
		// the Scheduled pages (agentry-web#1346) and the OAuth client
		// metadata documents (agentry-web#1331) — agentry#506.
		{"aboutus", false, true},
		{"aboutus", true, true},
		{"account-deleted", true, true},
		{"scheduled", true, true},
		{"oauth", true, true},
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
	for _, h := range []string{"ui", "runs", "invitations", "pricing", "aboutus", "account-deleted", "scheduled", "oauth", "agentry", "secureagentry"} {
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
// or yields no valid handle (agentry#517).
func TestHandleSeed(t *testing.T) {
	cases := []struct{ username, email, subject, want string }{
		{"blaktron", "chris@example.test", "sub", "blaktron"},
		{"", "chris@example.test", "sub", "chris"},
		{"   ", "chris@example.test", "sub", "chris"},
		{"chris.young@contoso.test", "cy@contoso.test", "sub", "chris.young"}, // a UPN gives its local part
		{"___", "chris@example.test", "sub", "chris"},                         // no valid handle in it
		{"", "", "github-42", "github-42"},
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
}
