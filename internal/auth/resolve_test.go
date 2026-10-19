package auth

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// fakeStore answers the store queries ResolvePAT and ResolveSSHKey make from
// values the test sets, and records which queries were asked and with what.
// It stands in for the database: the resolvers' decisions (which account
// states sign in, what the principal carries) are all in the Go code.
type fakeStore struct {
	pat     storegen.Pat
	patErr  error
	key     storegen.UserSshKey
	keyErr  error
	user    storegen.GetUserByIDRow
	userErr error
	members []storegen.ListUserMembershipsRow
	memErr  error
	execErr error

	asked []string // query names, in order
	args  map[string][]any
}

func (f *fakeStore) name(sql string) string {
	_, rest, _ := strings.Cut(sql, "-- name: ")
	n, _, _ := strings.Cut(rest, " ")
	if f.args == nil {
		f.args = map[string][]any{}
	}
	f.asked = append(f.asked, n)
	return n
}

func (f *fakeStore) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	n := f.name(sql)
	f.args[n] = args
	return pgconn.CommandTag{}, f.execErr
}

func (f *fakeStore) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	n := f.name(sql)
	f.args[n] = args
	switch n {
	case "GetPATByHash":
		return fakeRow{v: f.pat, err: f.patErr}
	case "GetSSHKeyByFingerprint":
		return fakeRow{v: f.key, err: f.keyErr}
	case "GetUserByID":
		return fakeRow{v: f.user, err: f.userErr}
	}
	return fakeRow{err: errors.New("unexpected query " + n)}
}

func (f *fakeStore) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	n := f.name(sql)
	f.args[n] = args
	if n != "ListUserMemberships" {
		return nil, errors.New("unexpected query " + n)
	}
	if f.memErr != nil {
		return nil, f.memErr
	}
	return &fakeRows{rows: f.members, at: -1}, nil
}

// fakeRow scans a struct's fields, in order, into the destinations.
type fakeRow struct {
	v   any
	err error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	rv := reflect.ValueOf(r.v)
	for i, d := range dest {
		reflect.ValueOf(d).Elem().Set(rv.Field(i))
	}
	return nil
}

type fakeRows struct {
	rows []storegen.ListUserMembershipsRow
	at   int
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }
func (r *fakeRows) TypeMap() *pgtype.Map                         { return nil }
func (r *fakeRows) Next() bool                                   { r.at++; return r.at < len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	*(dest[0].(*uuid.UUID)) = r.rows[r.at].OrgID
	*(dest[1].(*string)) = r.rows[r.at].Role
	return nil
}

// An account the resolvers accept: active, address confirmed, in two
// organizations.
func activeStore() (*fakeStore, uuid.UUID, uuid.UUID, uuid.UUID) {
	userID, adminOrg, memberOrg := uuid.New(), uuid.New(), uuid.New()
	verified := time.Now().Add(-time.Hour)
	return &fakeStore{
		pat: storegen.Pat{ID: uuid.New(), UserID: userID, Scopes: []string{"repo:read", "agent:read"}},
		key: storegen.UserSshKey{ID: uuid.New(), UserID: userID},
		user: storegen.GetUserByIDRow{
			ID: userID, Email: "ada@acme.io", EmailVerifiedAt: &verified, State: "active",
			PlatformStaff: true, Handle: "ada",
		},
		members: []storegen.ListUserMembershipsRow{{OrgID: adminOrg, Role: "admin"}, {OrgID: memberOrg, Role: "member"}},
	}, userID, adminOrg, memberOrg
}

// ResolvePAT turns a presented PAT into the principal of its owner, and only
// when the PAT is known and its owner is an active account.
func TestResolvePAT(t *testing.T) {
	t.Run("builds the principal of an active account", func(t *testing.T) {
		st, userID, adminOrg, memberOrg := activeStore()
		token := PATPrefix + "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"
		p, err := ResolvePAT(context.Background(), storegen.New(st), token)
		if err != nil {
			t.Fatalf("ResolvePAT: %v", err)
		}
		if p.Via != "pat" || p.Anonymous || !p.ScopeBound() {
			t.Errorf("principal is not a scope-bound token: via=%q anonymous=%v", p.Via, p.Anonymous)
		}
		if p.UserID != userID || p.Handle != "ada" || p.PATID != st.pat.ID {
			t.Errorf("identity wrong: %+v", p)
		}
		if !slices.Equal(p.Scopes, []string{"repo:read", "agent:read"}) {
			t.Errorf("Scopes = %v, want the PAT's own", p.Scopes)
		}
		if want := (map[uuid.UUID]OrgRole{adminOrg: RoleAdmin, memberOrg: RoleMember}); !reflect.DeepEqual(p.OrgRoles, want) {
			t.Errorf("OrgRoles = %v, want %v", p.OrgRoles, want)
		}
		if !p.EmailVerified || p.Unactivated || !p.PlatformStaff {
			t.Errorf("account flags wrong: verified=%v unactivated=%v staff=%v", p.EmailVerified, p.Unactivated, p.PlatformStaff)
		}
		if p.PATOrgID != uuid.Nil {
			t.Errorf("a personal PAT is bound to org %v", p.PATOrgID)
		}
		// The store is asked for the hash of the whole token, never the token.
		if got, ok := st.args["GetPATByHash"][0].([]byte); !ok || !slices.Equal(got, HashToken(token)) {
			t.Errorf("GetPATByHash asked for %v, want the sha256 of the full token", st.args["GetPATByHash"])
		}
		if got := st.args["GetUserByID"][0]; got != userID {
			t.Errorf("GetUserByID asked for %v, want the PAT's user %v", got, userID)
		}
		if got := st.args["ListUserMemberships"][0]; got != userID {
			t.Errorf("ListUserMemberships asked for %v, want %v", got, userID)
		}
		if got := st.args["TouchPAT"]; len(got) != 1 || got[0] != st.pat.ID {
			t.Errorf("last use recorded for %v, want the PAT %v", got, st.pat.ID)
		}
	})

	t.Run("binds an organization PAT to its organization", func(t *testing.T) {
		st, _, adminOrg, _ := activeStore()
		st.pat.OrgID = &adminOrg
		p, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x")
		if err != nil {
			t.Fatal(err)
		}
		if p.PATOrgID != adminOrg {
			t.Errorf("PATOrgID = %v, want %v", p.PATOrgID, adminOrg)
		}
		if !p.SSOSatisfied(adminOrg, time.Hour) || p.SSOSatisfied(uuid.New(), time.Hour) {
			t.Error("an org-bound PAT must satisfy enforced SSO for its own organization and no other")
		}
	})

	t.Run("reads the account activation", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			verified     bool
			email        string
			wantVerified bool
			wantUnact    bool
		}{
			{"unconfirmed real address", false, "ada@acme.io", false, true},
			{"unconfirmed placeholder address", false, "abc@github.social.local", false, false},
			{"confirmed address", true, "ada@acme.io", true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				st, _, _, _ := activeStore()
				st.user.Email = tc.email
				if !tc.verified {
					st.user.EmailVerifiedAt = nil
				}
				p, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x")
				if err != nil {
					t.Fatal(err)
				}
				if p.EmailVerified != tc.wantVerified || p.Unactivated != tc.wantUnact {
					t.Errorf("verified=%v unactivated=%v, want %v and %v", p.EmailVerified, p.Unactivated, tc.wantVerified, tc.wantUnact)
				}
			})
		}
	})

	t.Run("refuses what is not an active account's PAT", func(t *testing.T) {
		t.Run("unknown or revoked PAT", func(t *testing.T) {
			st, _, _, _ := activeStore()
			st.patErr = pgx.ErrNoRows
			p, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x")
			if !errors.Is(err, ErrUnauthorized) || p != nil {
				t.Fatalf("got %v, %v; want ErrUnauthorized and no principal", p, err)
			}
			if slices.Contains(st.asked, "GetUserByID") || slices.Contains(st.asked, "TouchPAT") {
				t.Errorf("an unknown PAT went on to %v", st.asked)
			}
		})
		t.Run("store failure on the PAT lookup", func(t *testing.T) {
			st, _, _, _ := activeStore()
			st.patErr = errors.New("connection reset")
			if _, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x"); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("got %v, want ErrUnauthorized (the caller must not see the store's error)", err)
			}
		})
		t.Run("owner lookup fails", func(t *testing.T) {
			st, _, _, _ := activeStore()
			st.userErr = pgx.ErrNoRows
			if p, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x"); !errors.Is(err, ErrUnauthorized) || p != nil {
				t.Fatalf("got %v, %v; want ErrUnauthorized", p, err)
			}
		})
		for _, state := range []string{"suspended", "deleted", "pending", "Active", ""} {
			t.Run("owner state "+state, func(t *testing.T) {
				st, _, _, _ := activeStore()
				st.user.State = state
				p, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x")
				if !errors.Is(err, ErrUnauthorized) || p != nil {
					t.Fatalf("got %v, %v; want ErrUnauthorized for an account in state %q", p, err, state)
				}
				if slices.Contains(st.asked, "TouchPAT") || slices.Contains(st.asked, "ListUserMemberships") {
					t.Errorf("a refused account went on to %v", st.asked)
				}
			})
		}
	})

	t.Run("reports a membership failure as itself", func(t *testing.T) {
		st, _, _, _ := activeStore()
		boom := errors.New("memberships unavailable")
		st.memErr = boom
		p, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x")
		if p != nil || !errors.Is(err, boom) || errors.Is(err, ErrUnauthorized) {
			t.Fatalf("got %v, %v; want the store's own error and no principal (a roleless principal must not be handed out)", p, err)
		}
	})

	t.Run("outlives a failed last-use update", func(t *testing.T) {
		st, _, _, _ := activeStore()
		st.execErr = errors.New("read-only transaction")
		if _, err := ResolvePAT(context.Background(), storegen.New(st), "agy_x"); err != nil {
			t.Fatalf("a failed last-use update refused the PAT: %v", err)
		}
	})
}

// ResolveSSHKey turns a presented key fingerprint into an ssh principal of the
// key's owner, and only when the key is known and its owner is active.
func TestResolveSSHKey(t *testing.T) {
	t.Run("builds an ssh principal of an active account", func(t *testing.T) {
		st, userID, adminOrg, memberOrg := activeStore()
		p, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc")
		if err != nil {
			t.Fatalf("ResolveSSHKey: %v", err)
		}
		if p.Via != "ssh" || p.Anonymous || p.ScopeBound() {
			t.Errorf("principal is not an ssh credential: via=%q", p.Via)
		}
		if p.UserID != userID || p.Handle != "ada" || p.SSHKeyID != st.key.ID || p.PATID != uuid.Nil {
			t.Errorf("identity wrong: %+v", p)
		}
		if want := (map[uuid.UUID]OrgRole{adminOrg: RoleAdmin, memberOrg: RoleMember}); !reflect.DeepEqual(p.OrgRoles, want) {
			t.Errorf("OrgRoles = %v, want %v", p.OrgRoles, want)
		}
		if !p.EmailVerified || p.Unactivated || !p.PlatformStaff {
			t.Errorf("account flags wrong: verified=%v unactivated=%v staff=%v", p.EmailVerified, p.Unactivated, p.PlatformStaff)
		}
		if got := st.args["GetSSHKeyByFingerprint"]; len(got) != 1 || got[0] != "SHA256:abc" {
			t.Errorf("key looked up by %v, want the presented fingerprint", got)
		}
		if got := st.args["TouchSSHKey"]; len(got) != 1 || got[0] != st.key.ID {
			t.Errorf("last use recorded for %v, want the key %v", got, st.key.ID)
		}
		// An ssh key is worth the repository transport and the release tag, and
		// a caller cannot widen the package's list through its principal.
		if !slices.Equal(p.Scopes, []string{"repo:read", "repo:write", "agent:publish"}) {
			t.Errorf("Scopes = %v", p.Scopes)
		}
		p.Scopes[0] = string(ScopeOrgAdmin)
		if SSHKeyScopes[0] != string(ScopeRepoRead) {
			t.Fatal("the principal's scopes alias SSHKeyScopes; one caller widened every key")
		}
		if p.PATOrgID != uuid.Nil || p.SSOSatisfied(adminOrg, time.Hour) {
			t.Error("an ssh key is never org-bound and never satisfies enforced SSO")
		}
	})

	t.Run("reads the account activation", func(t *testing.T) {
		st, _, _, _ := activeStore()
		st.user.EmailVerifiedAt = nil
		p, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc")
		if err != nil {
			t.Fatal(err)
		}
		if p.EmailVerified || !p.Unactivated {
			t.Errorf("verified=%v unactivated=%v for an unconfirmed real address", p.EmailVerified, p.Unactivated)
		}
	})

	t.Run("refuses what is not an active account's key", func(t *testing.T) {
		t.Run("unknown or revoked key", func(t *testing.T) {
			st, _, _, _ := activeStore()
			st.keyErr = pgx.ErrNoRows
			if p, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc"); !errors.Is(err, ErrUnauthorized) || p != nil {
				t.Fatalf("got %v, %v; want ErrUnauthorized", p, err)
			}
			if slices.Contains(st.asked, "GetUserByID") {
				t.Errorf("an unknown key went on to %v", st.asked)
			}
		})
		t.Run("owner lookup fails", func(t *testing.T) {
			st, _, _, _ := activeStore()
			st.userErr = pgx.ErrNoRows
			if p, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc"); !errors.Is(err, ErrUnauthorized) || p != nil {
				t.Fatalf("got %v, %v; want ErrUnauthorized", p, err)
			}
		})
		for _, state := range []string{"suspended", "deleted", ""} {
			t.Run("owner state "+state, func(t *testing.T) {
				st, _, _, _ := activeStore()
				st.user.State = state
				p, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc")
				if !errors.Is(err, ErrUnauthorized) || p != nil {
					t.Fatalf("got %v, %v; want ErrUnauthorized for an account in state %q", p, err, state)
				}
				if slices.Contains(st.asked, "TouchSSHKey") {
					t.Errorf("a refused account's key was recorded as used: %v", st.asked)
				}
			})
		}
		t.Run("membership failure", func(t *testing.T) {
			st, _, _, _ := activeStore()
			boom := errors.New("memberships unavailable")
			st.memErr = boom
			p, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc")
			if p != nil || !errors.Is(err, boom) || errors.Is(err, ErrUnauthorized) {
				t.Fatalf("got %v, %v; want the store's own error and no principal", p, err)
			}
		})
		t.Run("failed last-use update", func(t *testing.T) {
			st, _, _, _ := activeStore()
			st.execErr = errors.New("read-only transaction")
			if _, err := ResolveSSHKey(context.Background(), storegen.New(st), "SHA256:abc"); err != nil {
				t.Fatalf("a failed last-use update refused the key: %v", err)
			}
		})
	})
}

// An authorized_keys line is reduced to its type, the canonical "type
// base64" form without the comment, and the SHA256 fingerprint; anything
// that is not one key is refused.
func TestParseSSHPublicKey(t *testing.T) {
	const canonical = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs"
	const fingerprint = "SHA256:z/fSv0Z0RZS+Lccbc6ZoOWwt/fbj1VFJGSBKQbo4icE"
	for name, line := range map[string]string{
		"bare":                     canonical,
		"with a comment":           canonical + " ada@laptop",
		"padded with white space":  "  \t" + canonical + " ada@laptop \n",
		"trailing newline":         canonical + "\n",
		"with a comment of spaces": canonical + " my work laptop 2026",
	} {
		t.Run(name, func(t *testing.T) {
			typ, canon, fp, err := ParseSSHPublicKey(line)
			if err != nil {
				t.Fatal(err)
			}
			if typ != "ssh-ed25519" || canon != canonical || fp != fingerprint {
				t.Fatalf("got (%q, %q, %q), want (ssh-ed25519, the canonical line, %s)", typ, canon, fp, fingerprint)
			}
		})
	}
	for name, line := range map[string]string{
		"empty":              "",
		"only white space":   "  \n",
		"not a key":          "hello world",
		"truncated key":      canonical[:len(canonical)-12],
		"unknown key type":   "ssh-nothing AAAAC3NzaC1lZDI1NTE5AAAAIOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs",
		"type and body swap": "AAAAC3NzaC1lZDI1NTE5AAAAIOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs ssh-ed25519",
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			typ, canon, fp, err := ParseSSHPublicKey(line)
			if err == nil {
				t.Fatalf("accepted %q as (%q, %q, %q)", line, typ, canon, fp)
			}
			if typ != "" || canon != "" || fp != "" {
				t.Fatalf("a refused line still returned (%q, %q, %q)", typ, canon, fp)
			}
		})
	}
}
