package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

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
	if PATDisplayPrefixLen != 12 {
		t.Fatalf("PATDisplayPrefixLen = %d, want 12 (stored as pats.token_prefix)", PATDisplayPrefixLen)
	}

	// Every credential kind has its own spelled-out prefix, and what follows it
	// is 32 random bytes in lower-case base32 without padding (52 characters):
	// the shape secret scanners and the lookup by prefix rely on.
	t.Run("format of every credential kind", func(t *testing.T) {
		for _, tc := range []struct{ name, prefix, want string }{
			{"PAT", PATPrefix, "agy_"},
			{"session", SessionPrefix, "agys_"},
			{"invitation", InvitePrefix, "agyi_"},
			{"verification", VerificationPrefix, "agyv_"},
			{"trusted device", TrustedDevicePrefix, "agyd_"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if tc.prefix != tc.want {
					t.Fatalf("prefix = %q, want %q", tc.prefix, tc.want)
				}
				tok, err := NewToken(tc.prefix)
				if err != nil {
					t.Fatal(err)
				}
				body, ok := strings.CutPrefix(tok, tc.want)
				if !ok || len(body) != 52 {
					t.Fatalf("token %q: want %q then 52 characters, got %d", tok, tc.want, len(body))
				}
				if strings.Trim(body, "abcdefghijklmnopqrstuvwxyz234567") != "" {
					t.Fatalf("token body %q is not lower-case base32 without padding", body)
				}
				// All 32 bytes are random: neither half of the decoded body is zero.
				raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(body))
				if err != nil || len(raw) != 32 {
					t.Fatalf("body decodes to %d bytes (%v), want 32", len(raw), err)
				}
				for _, half := range [][]byte{raw[:16], raw[16:]} {
					if string(half) == string(make([]byte, 16)) {
						t.Fatalf("half of the token's %d bytes is zero: %x", len(raw), raw)
					}
				}
			})
		}
	})

	// Only the PAT prefix makes a PAT: the other credentials share the "agy"
	// stem and are not PATs, and a PAT string embedded elsewhere is not one.
	t.Run("only the PAT prefix is a PAT", func(t *testing.T) {
		for in, want := range map[string]bool{
			"agy_abc":      true,
			"agy_":         true,
			"agys_abc":     false,
			"agyi_abc":     false,
			"agyv_abc":     false,
			"agyd_abc":     false,
			"agy":          false,
			"xagy_abc":     false,
			" agy_abc":     false,
			"token agy_ab": false,
			"AGY_abc":      false,
			"":             false,
		} {
			if got := IsPAT(in); got != want {
				t.Errorf("IsPAT(%q) = %v, want %v", in, got, want)
			}
		}
	})

	// What is stored for a token is the sha256 of the whole string, and the
	// display prefix is its first 12 characters, or all of a shorter string.
	t.Run("stored hash and display prefix", func(t *testing.T) {
		// The standard sha256 test vector for "abc".
		if got := hex.EncodeToString(HashToken("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
			t.Fatalf("HashToken(abc) = %s", got)
		}
		tok := "agy_abcdefghijklmnop"
		sum := sha256.Sum256([]byte(tok))
		if !slices.Equal(HashToken(tok), sum[:]) {
			t.Fatal("HashToken is not the sha256 of the full token")
		}
		if slices.Equal(HashToken(tok), HashToken(tok[:12])) {
			t.Fatal("HashToken hashed only the display prefix")
		}
		for in, want := range map[string]string{
			"":                 "",
			"agy_ab":           "agy_ab",
			"agy_abcdefg":      "agy_abcdefg",
			"agy_abcdefgh":     "agy_abcdefgh",
			"agy_abcdefghi":    "agy_abcdefgh",
			"agy_abcdefghijkl": "agy_abcdefgh",
		} {
			if got := DisplayPrefix(in); got != want {
				t.Errorf("DisplayPrefix(%q) = %q, want %q", in, got, want)
			}
		}
	})
}

func TestSealerRoundTrip(t *testing.T) {
	s, err := NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal([]byte("a webhook secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.Open(ct)
	if err != nil || string(pt) != "a webhook secret" {
		t.Fatalf("roundtrip failed: %v %q", err, pt)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := s.Open(ct); err == nil {
		t.Fatal("tampered ciphertext must not open")
	}
	if _, err := NewSealer("", false); err == nil {
		t.Fatal("empty key outside dev must fail")
	}

	// The blob is nonce || ciphertext || tag, and the nonce is random: the
	// same plaintext never seals to the same bytes twice.
	again, _ := s.Seal([]byte("a webhook secret"))
	if len(again) != 12+len("a webhook secret")+16 {
		t.Fatalf("sealed blob is %d bytes, want 12 (nonce) + plaintext + 16 (tag)", len(again))
	}
	first, _ := s.Seal([]byte("a webhook secret"))
	if string(first) == string(again) || string(first[:12]) == string(again[:12]) {
		t.Fatal("two seals of one plaintext share a nonce")
	}
	if string(first[:12]) == string(make([]byte, 12)) && string(again[:12]) == string(make([]byte, 12)) {
		t.Fatal("the nonce is all zero")
	}
	empty, _ := s.Seal(nil)
	if pt, err := s.Open(empty); err != nil || len(pt) != 0 {
		t.Fatalf("an empty secret did not round-trip: %q %v", pt, err)
	}
	// A flipped nonce bit is as fatal as a flipped ciphertext bit.
	again[0] ^= 0x01
	if _, err := s.Open(again); err == nil {
		t.Fatal("a ciphertext with a tampered nonce must not open")
	}
	// A blob shorter than the nonce is refused as such; one of exactly the
	// nonce's length is long enough to be read and fails authentication.
	for _, n := range []int{0, 1, 11} {
		if _, err := s.Open(make([]byte, n)); err == nil || !strings.Contains(err.Error(), "too short") {
			t.Errorf("Open of %d bytes: %v, want a too-short error", n, err)
		}
	}
	if _, err := s.Open(nil); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("Open(nil): %v, want a too-short error", err)
	}
	if _, err := s.Open(make([]byte, 12)); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Errorf("Open of exactly a nonce: %v, want an unseal error, not a too-short one", err)
	}
	if _, err := NewSealer("", false); err == nil || !strings.Contains(err.Error(), "sealing key required") {
		t.Errorf("empty key outside dev: %v, want the required-key error", err)
	}

	// The configured key is exactly 32 bytes of standard base64, and it is the
	// key used: not the dev key, with or without dev mode on.
	t.Run("configured key", func(t *testing.T) {
		// 0xfb 0xef 0xbe spells "++++" and 0xff 0xff spells "//8=": a key that
		// only the standard alphabet decodes.
		key := append([]byte(strings.Repeat("\xfb\xef\xbe", 10)), 0xff, 0xff)
		enc := base64.StdEncoding.EncodeToString(key)
		if !strings.ContainsAny(enc, "+/") {
			t.Fatalf("fixture %q should use '+' or '/'", enc)
		}
		a, err := NewSealer(enc, false)
		if err != nil {
			t.Fatalf("a 32-byte standard-base64 key was refused: %v", err)
		}
		b, err := NewSealer(enc, false)
		if err != nil {
			t.Fatal(err)
		}
		withDev, err := NewSealer(enc, true)
		if err != nil {
			t.Fatal(err)
		}
		dev, err := NewSealer("", true)
		if err != nil {
			t.Fatal(err)
		}
		sealed, _ := a.Seal([]byte("sign-in state"))
		for name, s := range map[string]*Sealer{"same key": b, "same key in dev mode": withDev} {
			if pt, err := s.Open(sealed); err != nil || string(pt) != "sign-in state" {
				t.Errorf("%s did not open what the key sealed: %q %v", name, pt, err)
			}
		}
		if _, err := dev.Open(sealed); err == nil {
			t.Error("the dev key opened a value sealed under the configured key")
		}
		devSealed, _ := dev.Seal([]byte("dev"))
		if _, err := a.Open(devSealed); err == nil {
			t.Error("the configured key opened a value sealed under the dev key")
		}
		again, _ := NewSealer("", true)
		if pt, err := again.Open(devSealed); err != nil || string(pt) != "dev" {
			t.Errorf("the dev key is not stable: %q %v", pt, err)
		}

		for name, raw := range map[string][]byte{
			"16 bytes": key[:16], "24 bytes": key[:24], "31 bytes": key[:31],
			"33 bytes": append(append([]byte(nil), key...), 1),
		} {
			_, err := NewSealer(base64.StdEncoding.EncodeToString(raw), true)
			if err == nil || !strings.Contains(err.Error(), "must be 32 bytes") {
				t.Errorf("%s: %v, want a must-be-32-bytes error", name, err)
			}
		}
		if _, err := NewSealer("not base64 !!", true); err == nil || !strings.Contains(err.Error(), "sealing key") {
			t.Errorf("undecodable key: %v, want a sealing-key error", err)
		}
		if _, err := NewSealer(base64.URLEncoding.EncodeToString(key), true); err == nil {
			t.Error("a URL-alphabet key was accepted; only standard base64 is")
		}
	})
}

// TestCheckTruthTable pins the role thresholds explicitly, independent
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
		{"admin elevates", principal(RoleAdmin), ActOrgMembersElevate, orgID, true},
		{"member cannot elevate", principal(RoleMember), ActOrgMembersElevate, orgID, false},
		{"security_reviewer cannot elevate", principal(RoleSecurityReviewer), ActOrgMembersElevate, orgID, false},
		{"admin manages members", principal(RoleAdmin), ActOrgMembersManage, orgID, true},
		{"member cannot manage members", principal(RoleMember), ActOrgMembersManage, orgID, false},
		{"admin reads audit", principal(RoleAdmin), ActOrgAuditRead, orgID, true},
		{"member cannot read audit", principal(RoleMember), ActOrgAuditRead, orgID, false},
		{"cross-org admin denied", principal(RoleAdmin), ActOrgUpdate, otherOrg, false},
		{"authed self read", principal(RoleNone), ActUserSelfRead, uuid.Nil, true},
		{"authed org create", principal(RoleNone), ActOrgCreate, uuid.Nil, true},
		{"admin settings", principal(RoleAdmin), ActOrgSettingsManage, orgID, true},
		{"member no settings", principal(RoleMember), ActOrgSettingsManage, orgID, false},
		{"security_reviewer no settings", principal(RoleSecurityReviewer), ActOrgSettingsManage, orgID, false},
		// The value "owner" is not a role and ranks as nobody: a stale row
		// or token that still carries it holds no role at all.
		{"retired owner is nobody", principal(OrgRole("owner")), ActOrgMembersRead, orgID, false},
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

	// The two refusals are different answers: no credential is 401, a
	// credential without the permission is 403.
	t.Run("anonymous and absent callers are unauthorized, not forbidden", func(t *testing.T) {
		for _, p := range []*Principal{nil, {Anonymous: true}} {
			for _, act := range []Action{ActOrgMembersRead, ActOrgUpdate, ActUserSelfRead, ActOrgCreate} {
				if err := Check(p, Resource{OrgID: orgID}, act); !errors.Is(err, ErrUnauthorized) {
					t.Errorf("%+v, %s: %v, want ErrUnauthorized", p, act, err)
				}
			}
			for _, act := range []Action{ActOrgRead, ActPublicRead} {
				if err := Check(p, Resource{OrgID: orgID}, act); err != nil {
					t.Errorf("%+v, %s is public but got %v", p, act, err)
				}
			}
		}
		if err := Check(principal(RoleMember), Resource{OrgID: orgID}, ActOrgUpdate); !errors.Is(err, ErrForbidden) {
			t.Errorf("a member updating the org: %v, want ErrForbidden", err)
		}
	})

	t.Run("an action the chokepoint does not declare is refused", func(t *testing.T) {
		for _, act := range []Action{"org.nonexistent", "", ActAgentRead, ActAgentPublish} {
			if err := Check(principal(RoleAdmin), Resource{OrgID: orgID}, act); !errors.Is(err, ErrForbidden) {
				t.Errorf("Check(admin, %q) = %v, want ErrForbidden", act, err)
			}
		}
	})

	// The role threshold of every org-scoped action, against every role,
	// written out here and not read back from the code.
	t.Run("role thresholds of every org-scoped action", func(t *testing.T) {
		adminOnly := []Action{
			ActOrgUpdate, ActOrgMembersManage, ActOrgMembersElevate, ActOrgTeamsManage, ActOrgAuditRead,
			ActOrgSettingsManage, ActOrgBrandingManage, ActOrgInvitationsManage, ActOrgDecommission,
			ActOrgKnowledgeWrite,
		}
		memberUp := []Action{ActOrgMembersRead, ActOrgTeamsRead, ActOrgLeave, ActOrgKnowledgeRead}
		for _, role := range []OrgRole{RoleNone, RoleMember, RoleSecurityReviewer, RoleAdmin, OrgRole("owner"), OrgRole("Admin")} {
			for _, act := range adminOnly {
				want := role == RoleAdmin
				if got := Check(principal(role), Resource{OrgID: orgID}, act) == nil; got != want {
					t.Errorf("role %q, %s: allowed=%v, want %v", role, act, got, want)
				}
				if Check(principal(role), Resource{OrgID: otherOrg}, act) == nil {
					t.Errorf("role %q in another org, %s: allowed", role, act)
				}
			}
			for _, act := range memberUp {
				want := role == RoleAdmin || role == RoleMember || role == RoleSecurityReviewer
				if got := Check(principal(role), Resource{OrgID: orgID}, act) == nil; got != want {
					t.Errorf("role %q, %s: allowed=%v, want %v", role, act, got, want)
				}
				if Check(principal(role), Resource{OrgID: otherOrg}, act) == nil {
					t.Errorf("role %q in another org, %s: allowed", role, act)
				}
			}
		}
	})

	t.Run("self-scoped actions need only a session", func(t *testing.T) {
		for _, act := range []Action{
			ActUserSelfRead, ActUserSelfUpdate, ActUserTokensRead, ActUserTokensManage, ActUserSecurityManage,
			ActUserOrgRequest, ActOrgCreate, ActAgentCreate, ActReviewAct, ActKnowledgeRead, ActKnowledgeWrite,
			ActVoiceRead, ActVoiceWrite,
		} {
			if err := Check(principal(RoleNone), Resource{}, act); err != nil {
				t.Errorf("a session with no organization, %s: %v", act, err)
			}
		}
	})

	t.Run("a nil principal holds no role", func(t *testing.T) {
		var nobody *Principal
		if got := nobody.Role(orgID); got != RoleNone {
			t.Errorf("nil principal's role = %q", got)
		}
		if got := (&Principal{}).Role(orgID); got != RoleNone {
			t.Errorf("a principal with no roles holds %q", got)
		}
		if got := principal(RoleAdmin).Role(orgID); got != RoleAdmin {
			t.Errorf("admin's role = %q", got)
		}
		if got := principal(RoleAdmin).Role(otherOrg); got != RoleNone {
			t.Errorf("role in another org = %q", got)
		}
	})
}

// TestCheckPATScopes pins PAT scope gating.
func TestCheckPATScopes(t *testing.T) {
	orgID := uuid.New()
	pat := func(role OrgRole, scopes ...string) *Principal {
		return &Principal{
			UserID: uuid.New(), Via: "pat", Scopes: scopes,
			OrgRoles: map[uuid.UUID]OrgRole{orgID: role},
		}
	}
	if err := Check(pat(RoleAdmin, "org:admin"), Resource{OrgID: orgID}, ActOrgUpdate); err != nil {
		t.Fatalf("admin PAT with org:admin must update org: %v", err)
	}
	if err := Check(pat(RoleAdmin, "user:profile"), Resource{OrgID: orgID}, ActOrgUpdate); err == nil {
		t.Fatal("wrong-scope PAT must be denied")
	}
	if err := Check(pat(RoleAdmin, "org:admin", "audit:read"), Resource{}, ActUserTokensManage); err == nil {
		t.Fatal("session-only action must deny every PAT")
	}
	if err := Check(pat(RoleMember, "org:admin"), Resource{OrgID: orgID}, ActOrgUpdate); err == nil {
		t.Fatal("scope cannot exceed role")
	}

	// The scope that unlocks each action, written out here: a token holding
	// exactly that scope passes (given the role), a token holding any other
	// valid scope does not, and neither does one holding no scope or an
	// empty-named one.
	unlocks := map[Action]Scope{
		ActOrgCreate: ScopeOrgAdmin, ActOrgMembersRead: ScopeOrgAdmin, ActOrgMembersManage: ScopeOrgAdmin,
		ActOrgMembersElevate: ScopeOrgAdmin, ActOrgInvitationsManage: ScopeOrgAdmin, ActOrgTeamsRead: ScopeOrgAdmin,
		ActOrgTeamsManage: ScopeOrgAdmin, ActOrgUpdate: ScopeOrgAdmin, ActOrgBrandingManage: ScopeOrgAdmin,
		ActOrgAuditRead: ScopeAuditRead, ActAgentCreate: ScopeAgentPublish,
		ActUserSelfRead: ScopeUserProfile, ActUserSelfUpdate: ScopeUserProfile, ActUserTokensRead: ScopeUserProfile,
		ActReviewAct: ScopeReviewAct, ActKnowledgeRead: ScopeKnowledgeRead, ActKnowledgeWrite: ScopeKnowledgeWrite,
		ActOrgKnowledgeRead: ScopeKnowledgeRead, ActOrgKnowledgeWrite: ScopeKnowledgeWrite,
		ActVoiceRead: ScopeVoiceRead, ActVoiceWrite: ScopeVoiceWrite,
	}
	for act, want := range unlocks {
		for _, have := range AllScopes() {
			err := Check(pat(RoleAdmin, string(have)), Resource{OrgID: orgID}, act)
			if have == want && err != nil {
				t.Errorf("%s with %s: %v, want allowed", act, have, err)
			}
			if have != want && !errors.Is(err, ErrForbidden) {
				t.Errorf("%s with %s: %v, want ErrForbidden (only %s unlocks it)", act, have, err, want)
			}
		}
		for _, none := range [][]string{nil, {}, {""}} {
			if err := Check(pat(RoleAdmin, none...), Resource{OrgID: orgID}, act); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s with scopes %q: %v, want ErrForbidden", act, none, err)
			}
		}
	}
	// A token that asks for a public read needs no scope at all.
	for _, act := range []Action{ActOrgRead, ActPublicRead} {
		if err := Check(pat(RoleNone), Resource{OrgID: orgID}, act); err != nil {
			t.Errorf("%s with no scope: %v", act, err)
		}
	}
	// Session-only actions refuse every token, whatever scopes it holds,
	// including a scope named like nothing.
	every := []string{""}
	for _, sc := range AllScopes() {
		every = append(every, string(sc))
	}
	for _, act := range []Action{
		ActOrgSettingsManage, ActOrgDecommission, ActOrgLeave, ActUserTokensManage, ActUserSecurityManage,
		ActUserOrgRequest, ActAgentRead, ActAgentPublish, ActAgentManage, "org.nonexistent",
	} {
		if err := Check(pat(RoleAdmin, every...), Resource{OrgID: orgID}, act); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s with every scope: %v, want ErrForbidden (session only)", act, err)
		}
	}

	// The scopes that admit each agent action: a token needs any one of them.
	agentUnlocks := map[Action][]Scope{
		ActAgentRead: {ScopeAgentRead}, ActAgentRepoRead: {ScopeRepoRead}, ActAgentRepoWrite: {ScopeRepoWrite},
		ActAgentMaintain: {ScopeOrgAdmin}, ActAgentPublish: {ScopeAgentPublish}, ActAgentAdminister: {ScopeOrgAdmin},
		ActAgentManage: {ScopeAgentManage, ScopeOrgAdmin},
	}
	owner := AgentResource{EffectiveRole: AgentRoleAdmin}
	for act, admit := range agentUnlocks {
		for _, have := range AllScopes() {
			err := CheckAgent(&Principal{UserID: uuid.New(), Via: "pat", Scopes: []string{string(have)}}, owner, act)
			if slices.Contains(admit, have) && err != nil {
				t.Errorf("%s with %s: %v, want allowed", act, have, err)
			}
			if !slices.Contains(admit, have) && !errors.Is(err, ErrForbidden) {
				t.Errorf("%s with %s: %v, want ErrForbidden", act, have, err)
			}
		}
		if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "pat", Scopes: []string{"", "nonsense"}}, owner, act); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s with no real scope: %v, want ErrForbidden", act, err)
		}
		if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, owner, act); err != nil {
			t.Errorf("%s by a session on an agent it administers: %v", act, err)
		}
	}
	// Creating an agent is gated by the namespace in the caller, never here.
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, owner, ActAgentCreate); !errors.Is(err, ErrForbidden) {
		t.Errorf("CheckAgent(agent.create) = %v, want ErrForbidden", err)
	}
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "pat", Scopes: []string{"agent:publish"}}, owner, ActAgentCreate); !errors.Is(err, ErrForbidden) {
		t.Errorf("CheckAgent(agent.create) with agent:publish = %v, want ErrForbidden", err)
	}
}

// A principal loaded for a user with no credential is asked
// of the agent seams on its role alone and authorizes no route: Check
// refuses it whatever the role, where the same user's session passes.
func TestCheckRefusesAPrincipalWithNoCredential(t *testing.T) {
	orgID := uuid.New()
	as := func(via string) *Principal {
		return &Principal{UserID: uuid.New(), Via: via, OrgRoles: map[uuid.UUID]OrgRole{orgID: RoleAdmin}}
	}
	for _, act := range []Action{ActOrgUpdate, ActUserTokensManage, ActUserSelfRead, ActAgentCreate} {
		if err := Check(as("session"), Resource{OrgID: orgID}, act); err != nil {
			t.Fatalf("the session of an admin, %s: %v", act, err)
		}
		if err := Check(as("user"), Resource{OrgID: orgID}, act); !errors.Is(err, ErrForbidden) {
			t.Errorf("a principal with no credential, %s: %v, want ErrForbidden", act, err)
		}
	}
	res := AgentResource{EffectiveRole: AgentRoleAdmin}
	for _, act := range []Action{ActAgentRead, ActAgentMaintain, ActAgentPublish} {
		if err := CheckAgent(as("user"), res, act); err != nil {
			t.Errorf("the agent seams answer a principal with no credential on its role, %s: %v", act, err)
		}
	}
}

// A schedule's credential is gated as a token minted with
// ScheduleScopes, on top of the role: an admin's schedule reads their
// private agent and does nothing an admin's session could, from managing
// the organization to minting a token.
func TestCheckScheduleCredential(t *testing.T) {
	orgID := uuid.New()
	sched := &Principal{
		UserID: uuid.New(), Via: "schedule", ScheduleID: uuid.New(), Scopes: ScheduleScopes(),
		OrgRoles: map[uuid.UUID]OrgRole{orgID: RoleAdmin},
	}
	if !sched.ScopeBound() || (&Principal{Via: "session"}).ScopeBound() || (&Principal{Via: "user"}).ScopeBound() {
		t.Fatal("ScopeBound must hold for a token and a schedule and for nothing else")
	}
	for _, act := range []Action{ActOrgUpdate, ActUserTokensManage, ActUserSelfUpdate, ActAgentCreate} {
		if err := Check(sched, Resource{OrgID: orgID}, act); !errors.Is(err, ErrForbidden) {
			t.Errorf("a schedule's credential, %s: %v, want ErrForbidden", act, err)
		}
	}
	res := AgentResource{EffectiveRole: AgentRoleAdmin}
	if err := CheckAgent(sched, res, ActAgentRead); err != nil {
		t.Errorf("a schedule's credential reads its owner's private agent: %v", err)
	}
	for _, act := range []Action{ActAgentMaintain, ActAgentPublish, ActAgentRepoRead, ActAgentRepoWrite, ActAgentManage} {
		if err := CheckAgent(sched, res, act); !errors.Is(err, ErrForbidden) {
			t.Errorf("a schedule's credential, %s on an agent it administers: %v, want ErrForbidden", act, err)
		}
	}
	// Scope cannot exceed role: a schedule of someone who cannot read the
	// agent does not read it.
	if err := CheckAgent(sched, AgentResource{}, ActAgentRead); err == nil {
		t.Error("a schedule's credential read an agent its owner has no role on")
	}
	// The set is the closed list's, and each call's is its own.
	got := ScheduleScopes()
	if want := []string{"agent:read", "run:read", "run:write", "knowledge:read", "voice:read"}; !slices.Equal(got, want) {
		t.Errorf("ScheduleScopes() = %v, want %v: no write to knowledge, voice or the vault, nothing administrative", got, want)
	}
	for _, s := range got {
		if !ValidScope(Scope(s)) {
			t.Errorf("schedule scope %s is not a valid scope", s)
		}
	}
	got[0] = string(ScopeOrgAdmin)
	if ScheduleScopes()[0] == string(ScopeOrgAdmin) {
		t.Fatal("ScheduleScopes hands out a shared slice; one caller widened the next")
	}
}

// The hosted-run scopes: valid, in the enumeration, flat, and
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

// The vault scope: valid, enumerated, flat, and mapped to no core action
// — only the hosted vault consumes it.
func TestSecretWriteIsValidFlatAndUnlocksNoCoreAction(t *testing.T) {
	if !ValidScope(ScopeSecretWrite) {
		t.Fatal("secret:write is not a valid scope")
	}
	found := false
	for _, v := range AllScopes() {
		found = found || v == ScopeSecretWrite
	}
	if !found {
		t.Fatal("secret:write is not enumerated")
	}
	if HasScope([]string{"secret:write"}, ScopeRunWrite) || HasScope([]string{"run:write", "knowledge:write"}, ScopeSecretWrite) {
		t.Fatal("secret:write implied or was implied by another scope; the list is flat")
	}
	for act, sc := range scopeFor {
		if sc == ScopeSecretWrite {
			t.Errorf("core action %v is unlocked by secret:write", act)
		}
	}
}

// TestNamespaceDerivedAgentRole pins what a membership confers on an org's
// agents before any grant: an admin administers them, an active member
// may release them, and everyone else holds nothing until a grant says
// otherwise. A pending member needs no row here: an inactive membership never reaches OrgRoles, so they
// arrive as RoleNone — the "outsider" case is theirs too.
func TestNamespaceDerivedAgentRole(t *testing.T) {
	orgID, userID := uuid.New(), uuid.New()
	p := &Principal{UserID: userID, Via: "session"}
	cases := []struct {
		name string
		kind string
		ns   uuid.UUID
		role OrgRole
		want AgentRole
	}{
		{"own namespace", "user", userID, RoleNone, AgentRoleAdmin},
		{"someone else's namespace", "user", uuid.New(), RoleNone, AgentRoleNone},
		{"org admin", "org", orgID, RoleAdmin, AgentRoleAdmin},
		{"org member", "org", orgID, RoleMember, AgentRolePublish},
		{"org security_reviewer", "org", orgID, RoleSecurityReviewer, AgentRoleNone},
		{"outsider", "org", orgID, RoleNone, AgentRoleNone},
		{"retired owner", "org", orgID, OrgRole("owner"), AgentRoleNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NamespaceDerivedAgentRole(p, tc.kind, tc.ns, tc.role); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := NamespaceDerivedAgentRole(&Principal{Anonymous: true}, "org", orgID, RoleAdmin); got != AgentRoleNone {
		t.Fatalf("anonymous derived %q, want none", got)
	}
	// An anonymous principal carries the nil user id, so a namespace with
	// the nil id must not read as its own.
	if got := NamespaceDerivedAgentRole(&Principal{Anonymous: true}, "user", uuid.Nil, RoleNone); got != AgentRoleNone {
		t.Fatalf("anonymous derived %q on the nil user namespace, want none", got)
	}
	if got := NamespaceDerivedAgentRole(nil, "org", orgID, RoleAdmin); got != AgentRoleNone {
		t.Fatalf("no principal derived %q, want none", got)
	}
	if got := NamespaceDerivedAgentRole(nil, "user", uuid.Nil, RoleNone); got != AgentRoleNone {
		t.Fatalf("no principal derived %q on a user namespace, want none", got)
	}
	// A user namespace is the user's alone: no organization role changes it.
	if got := NamespaceDerivedAgentRole(p, "user", uuid.New(), RoleAdmin); got != AgentRoleNone {
		t.Fatalf("an org admin derived %q on someone else's personal namespace, want none", got)
	}
}

// TestAgentRoleLadder pins the order the thresholds read, and that the top
// of it cannot be handed out: a grant must never be a way to acquire the
// acts that decide what an agent is.
func TestAgentRoleLadder(t *testing.T) {
	ascending := []AgentRole{AgentRoleNone, AgentRoleRead, AgentRoleWrite, AgentRoleMaintain, AgentRolePublish, AgentRoleAdmin}
	for i := 1; i < len(ascending); i++ {
		if agentRoleRank(ascending[i]) <= agentRoleRank(ascending[i-1]) {
			t.Fatalf("%q does not outrank %q", ascending[i], ascending[i-1])
		}
		if MaxAgentRole(ascending[i-1], ascending[i]) != ascending[i] {
			t.Fatalf("MaxAgentRole(%q, %q) is not %q", ascending[i-1], ascending[i], ascending[i])
		}
	}
	if ValidAgentRole(AgentRoleAdmin) {
		t.Fatal("AgentRoleAdmin is grantable: a grant on one agent would hand out the organization's own authority")
	}
	// The one that matters: publish does not reach the acts that
	// decide what the agent is, so an organization's members do not.
	publisher := AgentResource{EffectiveRole: AgentRolePublish}
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, publisher, ActAgentPublish); err != nil {
		t.Fatalf("a publisher cannot publish: %v", err)
	}
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, publisher, ActAgentAdminister); err == nil {
		t.Fatal("a publisher may administer the agent: visibility, deletion and grants would fall to every member")
	}

	// Which role each action needs, against every role of the ladder; the
	// threshold is the position in the ascending list, written out here.
	needs := map[Action]AgentRole{
		ActAgentRead: AgentRoleRead, ActAgentRepoRead: AgentRoleRead, ActAgentRepoWrite: AgentRoleWrite,
		ActAgentMaintain: AgentRoleMaintain, ActAgentPublish: AgentRolePublish,
		ActAgentAdminister: AgentRoleAdmin, ActAgentManage: AgentRoleAdmin,
	}
	for act, need := range needs {
		for i, role := range ascending {
			err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, AgentResource{EffectiveRole: role}, act)
			wantAllowed := i >= slices.Index(ascending, need)
			if wantAllowed && err != nil {
				t.Errorf("%s with role %q: %v, want allowed", act, role, err)
			}
			if !wantAllowed && !errors.Is(err, ErrForbidden) {
				t.Errorf("%s with role %q: %v, want ErrForbidden", act, role, err)
			}
		}
	}
	// Public agents are readable by anyone, anonymous included, for the two
	// reads and nothing else; a private one needs a credential and a role.
	public, private := AgentResource{Public: true}, AgentResource{}
	for _, p := range []*Principal{nil, {Anonymous: true}} {
		for _, act := range []Action{ActAgentRead, ActAgentRepoRead} {
			if err := CheckAgent(p, public, act); err != nil {
				t.Errorf("%+v reading a public agent with %s: %v", p, act, err)
			}
			if err := CheckAgent(p, private, act); !errors.Is(err, ErrUnauthorized) {
				t.Errorf("%+v reading a private agent with %s: %v, want ErrUnauthorized", p, act, err)
			}
		}
		for _, act := range []Action{ActAgentRepoWrite, ActAgentMaintain, ActAgentPublish, ActAgentAdminister, ActAgentManage} {
			if err := CheckAgent(p, public, act); !errors.Is(err, ErrUnauthorized) {
				t.Errorf("%+v with %s on a public agent: %v, want ErrUnauthorized", p, act, err)
			}
		}
	}
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, private, ActAgentRead); !errors.Is(err, ErrForbidden) {
		t.Errorf("a signed-in stranger reading a private agent: %v, want ErrForbidden", err)
	}
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, public, ActAgentRepoWrite); !errors.Is(err, ErrForbidden) {
		t.Errorf("a signed-in stranger pushing to a public agent: %v, want ErrForbidden", err)
	}
	// Only the four content levels are grantable, and the empty role is none.
	for _, r := range []AgentRole{AgentRoleRead, AgentRoleWrite, AgentRoleMaintain, AgentRolePublish} {
		if !ValidAgentRole(r) {
			t.Errorf("%q is not a grantable role", r)
		}
	}
	for _, r := range []AgentRole{AgentRoleNone, AgentRoleAdmin, "owner", "Read"} {
		if ValidAgentRole(r) {
			t.Errorf("%q is a grantable role", r)
		}
	}
	for i := 1; i < len(ascending); i++ {
		if MaxAgentRole(ascending[i], ascending[i-1]) != ascending[i] {
			t.Errorf("MaxAgentRole(%q, %q) is not %q", ascending[i], ascending[i-1], ascending[i])
		}
	}
	if agentRoleRank("owner") != agentRoleRank(AgentRoleNone) {
		t.Error("a role that is not on the ladder ranks above none")
	}
}

// TestHoldPermits pins what an organization in its decommission hold still
// permits: the reads, and a member leaving. The list is kept by hand
// beside minRole, so a change to it is a deliberate one.
func TestHoldPermits(t *testing.T) {
	permitted := map[Action]bool{
		ActOrgRead: true, ActOrgMembersRead: true, ActOrgTeamsRead: true, ActOrgAuditRead: true,
		ActPublicRead: true, ActUserSelfRead: true, ActUserTokensRead: true,
		ActAgentRead: true, ActAgentRepoRead: true, ActOrgLeave: true, ActKnowledgeRead: true,
		ActOrgKnowledgeRead: true,
	}
	all := []Action{
		ActOrgRead, ActOrgUpdate, ActOrgMembersRead, ActOrgMembersManage, ActOrgMembersElevate,
		ActOrgTeamsRead, ActOrgTeamsManage, ActOrgAuditRead, ActOrgSettingsManage, ActOrgInvitationsManage,
		ActOrgDecommission, ActOrgLeave, ActUserSelfRead, ActUserSelfUpdate, ActUserTokensRead,
		ActUserTokensManage, ActUserSecurityManage, ActUserOrgRequest, ActOrgCreate, ActPublicRead, ActReviewAct,
		ActAgentCreate, ActAgentRead, ActAgentRepoRead, ActAgentRepoWrite, ActAgentMaintain, ActAgentPublish, ActAgentAdminister,
		ActAgentManage, ActKnowledgeRead, ActKnowledgeWrite, ActOrgKnowledgeRead, ActOrgKnowledgeWrite,
		ActOrgBrandingManage, ActVoiceRead, ActVoiceWrite,
	}
	for _, act := range all {
		if got := HoldPermits(act); got != permitted[act] {
			t.Errorf("HoldPermits(%s) = %v, want %v", act, got, permitted[act])
		}
		if act != ActOrgLeave && ReadOnly(act) != permitted[act] {
			t.Errorf("ReadOnly(%s) = %v, want %v", act, ReadOnly(act), permitted[act])
		}
	}
}

// TestAgentManageScope: agent:manage admits the owner
// actions and nothing else of org:admin's, org:admin still admits them,
// and neither lowers the administrators' rung.
func TestAgentManageScope(t *testing.T) {
	admin := AgentResource{Public: true, EffectiveRole: AgentRoleAdmin}
	publisher := AgentResource{Public: true, EffectiveRole: AgentRolePublish}
	pat := func(scopes ...string) *Principal {
		return &Principal{UserID: uuid.New(), Via: "pat", Scopes: scopes}
	}
	signIn := pat(SignInGrantScopes()...)
	wantGrant := []string{
		"agent:read", "agent:publish", "agent:manage", "repo:read", "repo:write", "user:profile",
		"run:read", "run:write", "knowledge:read", "knowledge:write", "secret:write", "voice:read", "voice:write",
	}
	if got := SignInGrantScopes(); !slices.Equal(got, wantGrant) {
		t.Fatalf("SignInGrantScopes() = %v, want %v (no review:act, no org scopes)", got, wantGrant)
	}
	if err := CheckAgent(signIn, admin, ActAgentManage); err != nil {
		t.Fatalf("the sign-in grant cannot take the owner actions: %v", err)
	}
	if err := CheckAgent(pat("org:admin"), admin, ActAgentManage); err != nil {
		t.Fatalf("org:admin no longer takes the owner actions: %v", err)
	}
	for _, act := range []Action{ActAgentMaintain, ActAgentAdminister} {
		if err := CheckAgent(signIn, admin, act); err == nil {
			t.Fatalf("the sign-in grant reaches %s", act)
		}
	}
	if err := CheckAgent(pat("agent:read", "agent:publish"), admin, ActAgentManage); err == nil {
		t.Fatal("a token without agent:manage or org:admin takes the owner actions")
	}
	if err := CheckAgent(signIn, publisher, ActAgentManage); err == nil {
		t.Fatal("agent:manage lowers the rung: a publisher takes the owner actions")
	}
	if err := CheckAgent(&Principal{UserID: uuid.New(), Via: "session"}, publisher, ActAgentManage); err == nil {
		t.Fatal("a publisher's session takes the owner actions")
	}
	if !ValidScope(ScopeAgentManage) {
		t.Fatal("agent:manage is not a valid scope")
	}
}

// The closed list of scopes: each is spelled as tokens carry it, nothing else
// is a scope (not a near miss, not another case), and a scope is held only
// when it is in the set exactly.
func TestScopeListIsClosed(t *testing.T) {
	want := []string{
		"repo:read", "repo:write", "agent:publish", "agent:read", "agent:manage", "org:admin", "review:act",
		"audit:read", "user:profile", "run:read", "run:write", "knowledge:read", "knowledge:write",
		"secret:write", "voice:read", "voice:write",
	}
	var got []string
	for _, sc := range AllScopes() {
		got = append(got, string(sc))
		if !ValidScope(sc) {
			t.Errorf("%s is enumerated but not valid", sc)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("AllScopes() = %v, want %v", got, want)
	}
	for _, bad := range []string{"", "org:owner", "ORG:ADMIN", "org:admin ", "org:", "repo", "repo:read:extra", "admin", "*", "agent:delete"} {
		if ValidScope(Scope(bad)) {
			t.Errorf("ValidScope(%q) = true", bad)
		}
	}
	for _, near := range []string{"org:admin-extra", "xorg:admin", "org:adm", "ORG:ADMIN", "org:admin "} {
		if HasScope([]string{near}, ScopeOrgAdmin) {
			t.Errorf("HasScope(%q, org:admin) = true", near)
		}
	}
	if HasScope(nil, ScopeOrgAdmin) || HasScope([]string{}, ScopeOrgAdmin) {
		t.Error("an empty scope set holds a scope")
	}
	if !HasScope([]string{"repo:read", "org:admin"}, ScopeOrgAdmin) || !HasScope([]string{"org:admin"}, ScopeOrgAdmin) {
		t.Error("a scope in the set is not held")
	}
}

// Whether a credential satisfies an organization's enforced SSO: a PAT bound
// to that organization, or a session whose SSO assertion for it is recent
// enough; nothing else, and no other organization's assertion.
func TestSSOSatisfied(t *testing.T) {
	orgID, other := uuid.New(), uuid.New()
	var nobody *Principal
	if nobody.SSOSatisfied(orgID, time.Hour) {
		t.Error("no principal satisfies SSO")
	}
	for _, tc := range []struct {
		name string
		p    *Principal
		want bool
	}{
		{"PAT bound to the organization", &Principal{Via: "pat", PATOrgID: orgID}, true},
		{"PAT bound to another organization", &Principal{Via: "pat", PATOrgID: other}, false},
		{"personal PAT", &Principal{Via: "pat"}, false},
		{"session with a fresh assertion", &Principal{Via: "session", SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now().Add(-time.Minute)}}, true},
		{"session with a stale assertion", &Principal{Via: "session", SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now().Add(-2 * time.Hour)}}, false},
		{"session asserted for another organization", &Principal{Via: "session", SSOFresh: map[uuid.UUID]time.Time{other: time.Now()}}, false},
		{"session with no assertion", &Principal{Via: "session"}, false},
		{"session with a PAT binding", &Principal{Via: "session", PATOrgID: orgID}, false},
		{"PAT with a session assertion", &Principal{Via: "pat", SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now()}}, false},
		{"ssh key", &Principal{Via: "ssh", PATOrgID: orgID, SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now()}}, false},
		{"loaded user", &Principal{Via: "user", PATOrgID: orgID, SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now()}}, false},
		{"schedule", &Principal{Via: "schedule", PATOrgID: orgID, SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now()}}, false},
		{"no credential kind", &Principal{PATOrgID: orgID, SSOFresh: map[uuid.UUID]time.Time{orgID: time.Now()}}, false},
	} {
		if got := tc.p.SSOSatisfied(orgID, time.Hour); got != tc.want {
			t.Errorf("%s: SSOSatisfied = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An account is unactivated when its address is unconfirmed and a mail can
// reach it; the placeholder an address-less social sign-in is given is never
// a mailbox, whatever its case.
func TestUnactivatedAndSyntheticAddress(t *testing.T) {
	if SyntheticAddressSuffix != ".social.local" {
		t.Fatalf("SyntheticAddressSuffix = %q", SyntheticAddressSuffix)
	}
	for addr, want := range map[string]bool{
		"abc@github.social.local":    true,
		"ABC@GITHUB.SOCIAL.LOCAL":    true,
		"abc@x.social.local":         true,
		"abc@social.local":           false,
		"abc@xsocial.local":          false,
		"abc@github.social.local.io": false,
		"abc@social.local.example":   false,
		"ada@acme.io":                false,
		"":                           false,
	} {
		if got := SyntheticAddress(addr); got != want {
			t.Errorf("SyntheticAddress(%q) = %v, want %v", addr, got, want)
		}
	}
	at := time.Now()
	for _, tc := range []struct {
		name     string
		verified *time.Time
		email    string
		want     bool
	}{
		{"unconfirmed real address", nil, "ada@acme.io", true},
		{"confirmed real address", &at, "ada@acme.io", false},
		{"unconfirmed placeholder", nil, "abc@github.social.local", false},
		{"confirmed placeholder", &at, "abc@github.social.local", false},
		{"unconfirmed placeholder in capitals", nil, "ABC@GITHUB.SOCIAL.LOCAL", false},
	} {
		if got := Unactivated(tc.verified, tc.email); got != tc.want {
			t.Errorf("%s: Unactivated = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The caller's resolved address rides the context and nothing else does.
func TestClientIPRidesTheContext(t *testing.T) {
	ctx := context.Background()
	if got := ClientIPFrom(ctx); got != "" {
		t.Fatalf("ClientIPFrom of a bare context = %q", got)
	}
	withIP := WithClientIP(ctx, "203.0.113.9")
	if got := ClientIPFrom(withIP); got != "203.0.113.9" {
		t.Fatalf("ClientIPFrom = %q, want the recorded address", got)
	}
	if got := ClientIPFrom(ctx); got != "" {
		t.Fatalf("recording an address changed its parent context: %q", got)
	}
	if got := ClientIPFrom(WithClientIP(withIP, "198.51.100.1")); got != "198.51.100.1" {
		t.Fatalf("the innermost address should win, got %q", got)
	}
	type foreignKey struct{}
	if got := ClientIPFrom(context.WithValue(ctx, foreignKey{}, "198.51.100.2")); got != "" {
		t.Fatalf("a foreign context value was read as the client address: %q", got)
	}
}
