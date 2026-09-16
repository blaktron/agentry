package auth

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("not PHC argon2id: %s", h)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("verify failed for correct password")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("verify passed for wrong password")
	}
	if VerifyPassword("anything", "$bcrypt$whatever") {
		t.Fatal("unknown format must verify false")
	}
}

func TestTokens(t *testing.T) {
	tok, err := NewToken(PATPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPAT(tok) {
		t.Fatalf("PAT prefix missing: %s", tok)
	}
	if len(tok) < 40 {
		t.Fatalf("token too short: %d", len(tok))
	}
	if DisplayPrefix(tok) != tok[:12] {
		t.Fatal("display prefix wrong")
	}
	tok2, _ := NewToken(PATPrefix)
	if tok == tok2 {
		t.Fatal("tokens must be unique")
	}
	if string(HashToken(tok)) == string(HashToken(tok2)) {
		t.Fatal("hashes must differ")
	}
}

func TestSealerRoundTrip(t *testing.T) {
	s, err := NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal([]byte("totp-secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.Open(ct)
	if err != nil || string(pt) != "totp-secret" {
		t.Fatalf("roundtrip failed: %v %q", err, pt)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := s.Open(ct); err == nil {
		t.Fatal("tampered ciphertext must not open")
	}
	if _, err := NewSealer("", false); err == nil {
		t.Fatal("empty key outside dev must fail")
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	secret, url, err := GenerateTOTP("", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || !strings.HasPrefix(url, "otpauth://") {
		t.Fatalf("bad enrollment: %q %q", secret, url)
	}
	if ValidateTOTP("000000", secret) && ValidateTOTP("111111", secret) {
		t.Fatal("both fixed codes valid — validation broken")
	}
}

// TestCheckTruthTable pins the §12.2 role thresholds explicitly, independent
// of the matrix test (which reuses Check to derive expectations).
func TestCheckTruthTable(t *testing.T) {
	orgID := uuid.New()
	otherOrg := uuid.New()
	principal := func(role OrgRole) *Principal {
		p := &Principal{UserID: uuid.New(), Via: "session", OrgRoles: map[uuid.UUID]OrgRole{}}
		if role != RoleNone {
			p.OrgRoles[orgID] = role
		}
		return p
	}

	cases := []struct {
		name  string
		p     *Principal
		act   Action
		org   uuid.UUID
		allow bool
	}{
		{"anon public", &Principal{Anonymous: true}, ActOrgRead, orgID, true},
		{"anon members read", &Principal{Anonymous: true}, ActOrgMembersRead, orgID, false},
		{"member reads members", principal(RoleMember), ActOrgMembersRead, orgID, true},
		{"member cannot update org", principal(RoleMember), ActOrgUpdate, orgID, false},
		{"security_reviewer cannot update org", principal(RoleSecurityReviewer), ActOrgUpdate, orgID, false},
		{"security_reviewer reads teams", principal(RoleSecurityReviewer), ActOrgTeamsRead, orgID, true},
		{"admin updates org", principal(RoleAdmin), ActOrgUpdate, orgID, true},
		{"admin cannot elevate", principal(RoleAdmin), ActOrgMembersElevate, orgID, false},
		{"owner elevates", principal(RoleOwner), ActOrgMembersElevate, orgID, true},
		{"admin manages members", principal(RoleAdmin), ActOrgMembersManage, orgID, true},
		{"member cannot manage members", principal(RoleMember), ActOrgMembersManage, orgID, false},
		{"admin reads audit", principal(RoleAdmin), ActOrgAuditRead, orgID, true},
		{"member cannot read audit", principal(RoleMember), ActOrgAuditRead, orgID, false},
		{"cross-org admin denied", principal(RoleAdmin), ActOrgUpdate, otherOrg, false},
		{"authed self read", principal(RoleNone), ActUserSelfRead, uuid.Nil, true},
		{"authed org create", principal(RoleNone), ActOrgCreate, uuid.Nil, true},
		{"owner settings", principal(RoleOwner), ActOrgSettingsManage, orgID, true},
		{"admin no settings", principal(RoleAdmin), ActOrgSettingsManage, orgID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.p, Resource{OrgID: tc.org}, tc.act)
			if tc.allow && err != nil {
				t.Fatalf("want allow, got %v", err)
			}
			if !tc.allow && err == nil {
				t.Fatal("want deny, got allow")
			}
		})
	}
}

// TestCheckPATScopes pins PAT scope gating (§12.3).
func TestCheckPATScopes(t *testing.T) {
	orgID := uuid.New()
	pat := func(role OrgRole, scopes ...string) *Principal {
		return &Principal{
			UserID: uuid.New(), Via: "pat", Scopes: scopes,
			OrgRoles: map[uuid.UUID]OrgRole{orgID: role},
		}
	}
	if err := Check(pat(RoleOwner, "org:admin"), Resource{OrgID: orgID}, ActOrgUpdate); err != nil {
		t.Fatalf("owner PAT with org:admin must update org: %v", err)
	}
	if err := Check(pat(RoleOwner, "user:profile"), Resource{OrgID: orgID}, ActOrgUpdate); err == nil {
		t.Fatal("wrong-scope PAT must be denied")
	}
	if err := Check(pat(RoleOwner, "org:admin", "audit:read"), Resource{}, ActUserTokensManage); err == nil {
		t.Fatal("session-only action must deny every PAT")
	}
	if err := Check(pat(RoleMember, "org:admin"), Resource{OrgID: orgID}, ActOrgUpdate); err == nil {
		t.Fatal("scope cannot exceed role")
	}
}

// The hosted-run scopes (agentry#348): valid, in the enumeration, flat, and
// mapped to no core action — a token carrying only them unlocks nothing
// in the core.
func TestRunScopesAreValidFlatAndUnlockNoCoreAction(t *testing.T) {
	for _, s := range []Scope{ScopeRunRead, ScopeRunWrite} {
		if !ValidScope(s) {
			t.Errorf("%s is not a valid scope", s)
		}
		found := false
		for _, v := range AllScopes() {
			found = found || v == s
		}
		if !found {
			t.Errorf("%s is not enumerated", s)
		}
	}
	if HasScope([]string{"run:read"}, ScopeRunWrite) || HasScope([]string{"run:write"}, ScopeRunRead) {
		t.Fatal("one run scope implied the other; the list is flat")
	}
	for act, sc := range scopeFor {
		if sc == ScopeRunRead || sc == ScopeRunWrite {
			t.Errorf("core action %v is unlocked by %s", act, sc)
		}
	}
}
