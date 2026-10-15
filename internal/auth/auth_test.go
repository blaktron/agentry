package auth

import (
	"errors"
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
