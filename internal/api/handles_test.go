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
	for _, h := range []string{"ui", "agentry", "secureagentry"} {
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
