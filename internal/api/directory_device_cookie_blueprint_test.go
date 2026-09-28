package api

import "testing"

// authentik's User Login stage writes its own "known device" cookie,
// `authentik_device`, whenever `remember_device` is at least a second, and
// the field defaults to 30 days. The cookie is a stateless JWT signed with a
// key derived from the installation's identifier and the stage's primary key:
// the directory keeps no record of it, so it cannot be listed or revoked, and
// rotating the secret key does not end it (agentry#460). The operator turned it off on 2026-09-25 ("do not
// create unrecoverable tokens"); the remembered browser (DEV-163) is the one
// device credential. Every login stage the directory ships or we add is
// therefore declared by name with the cookie off, not left to the default.
//
// `remember_me_offset` is pinned at its default of zero too. Above zero the
// stage shows authentik's own "Remember me" box beside ours and, because the
// stage then logs in with an explicit choice, it stops writing the device
// cookie at all whatever `remember_device` says: a setting that looks
// unrelated would silently change what this test protects.
func TestDirectoryIssuesNoDeviceCookie(t *testing.T) {
	loginStages := map[string]bool{
		// ours
		"agentry-enrollment-login": false,
		"agentry-recovery-login":   false,
		// authentik's default flows, which the directory creates on first boot
		"default-authentication-login":        false,
		"default-source-authentication-login": false,
		"default-source-enrollment-login":     false,
	}
	for _, e := range readAccountFlows(t) {
		if e.Model != "authentik_stages_user_login.userloginstage" {
			continue
		}
		name := scalar(e.Identifiers["name"])
		if _, known := loginStages[name]; !known {
			t.Errorf("login stage %q is not in this test's list: add it, with the device cookie off", name)
			continue
		}
		loginStages[name] = true
		if got := scalar(e.Attrs["remember_device"]); got != "seconds=0" {
			t.Errorf("login stage %q: remember_device = %q, want seconds=0 (authentik's default writes a 30-day authentik_device cookie)", name, got)
		}
		if got := scalar(e.Attrs["remember_me_offset"]); got != "seconds=0" {
			t.Errorf("login stage %q: remember_me_offset = %q, want seconds=0", name, got)
		}
	}
	for name, declared := range loginStages {
		if !declared {
			t.Errorf("login stage %q is not declared in the account-flows blueprint, so it keeps authentik's 30-day device cookie", name)
		}
	}
}
