package api

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestDirectorySignInFactsAgainstALiveDirectory checks SignInFacts against a
// real authentik carrying the account-flows blueprint (agentry#706), the way
// TestAuthentikGroupsAgainstALiveDirectory checks the staff mirror. An
// account the API creates has run no flow, so nothing is recorded for it
// and it has no connection: the shapes parse and both answers are absent.
// The recorded answers exist only after real flows, which the API cannot
// run, so those cases take accounts a real sign-in made:
//
//	AGENTRY_TEST_AUTHENTIK_PASSWORD_EMAIL, _PASSWORD_UID: an account that has
//	signed in with a password (want hasPassword true);
//	AGENTRY_TEST_AUTHENTIK_CONNECTED_EMAIL, _CONNECTED_UID, _CONNECTED_SOURCE:
//	an account a social provider created (want that provider first, and
//	hasPassword false).
//
// CI skips it; the workstation runs it against a throwaway directory.
func TestDirectorySignInFactsAgainstALiveDirectory(t *testing.T) {
	base, token := os.Getenv("AGENTRY_TEST_AUTHENTIK_URL"), os.Getenv("AGENTRY_TEST_AUTHENTIK_TOKEN")
	if base == "" || token == "" {
		t.Skip("AGENTRY_TEST_AUTHENTIK_URL / AGENTRY_TEST_AUTHENTIK_TOKEN not set")
	}
	ctx := context.Background()
	a := newAuthentikEraser(base, token)
	tag := fmt.Sprintf("%06x", rand.Int63n(1<<24)) //nolint:gosec // test names
	email := "live-facts-" + tag + "@example.test"
	var u struct {
		PK int `json:"pk"`
	}
	if err := a.doJSON(ctx, http.MethodPost, "/api/v3/core/users/", map[string]any{
		"username": "live-facts-" + tag, "name": "live facts", "email": email, "is_active": true, "path": "users",
	}, &u); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/api/v3/core/users/%d/", u.PK), nil, nil) })
	accounts, err := a.AccountsByEmail(ctx, email)
	if err != nil || len(accounts) != 1 || accounts[0].UID == "" {
		t.Fatalf("lookup: %+v %v", accounts, err)
	}
	f, err := a.SignInFacts(ctx, directoryLink{UID: accounts[0].UID, Email: email})
	if err != nil || f.FirstSource != nil || f.HasPassword != nil {
		t.Fatalf("an account no flow has touched: %+v %v, want nothing", f, err)
	}

	// agentry#727: by the directory's id, the account is found although the
	// registry's address is another (the DEV-061 placeholder), and the uid
	// still has to agree.
	elsewhere := "live-facts-" + tag + "@authentik.social.local"
	byID := directoryLink{AccountID: int64(u.PK), UID: accounts[0].UID, Email: elsewhere}
	if got, how, err := a.findAccount(ctx, byID); err != nil || got == nil || got.PK != u.PK || how != dirLookupByID {
		t.Fatalf("by id with another registry address: %+v %s %v, want account %d", got, how, err, u.PK)
	}
	if got, _, err := a.findAccount(ctx, directoryLink{UID: accounts[0].UID, Email: elsewhere}); err != nil || got != nil {
		t.Fatalf("by uid at the registry's other address: %+v %v, want none (why the id is needed)", got, err)
	}
	if got, _, err := a.findAccount(ctx, directoryLink{AccountID: int64(u.PK), UID: "not-" + accounts[0].UID, Email: email}); err != nil || got != nil {
		t.Fatalf("by id with another uid: %+v %v, want none", got, err)
	}
	if devs, err := a.Devices(ctx, byID); err != nil || len(devs) != 0 {
		t.Fatalf("devices by id: %+v %v, want an empty list", devs, err)
	}
	// agentry#617: the address with other capitals than the directory's.
	if got, how, err := a.findAccount(ctx, directoryLink{Email: strings.ToUpper(email)}); err != nil || got == nil || got.PK != u.PK || how != dirLookupByAddress {
		t.Fatalf("by the address in capitals: %+v %s %v, want account %d", got, how, err, u.PK)
	}

	ran := 0
	if pe, pu := os.Getenv("AGENTRY_TEST_AUTHENTIK_PASSWORD_EMAIL"), os.Getenv("AGENTRY_TEST_AUTHENTIK_PASSWORD_UID"); pe != "" {
		ran++
		f, err := a.SignInFacts(ctx, directoryLink{UID: pu, Email: pe})
		if err != nil || f.HasPassword == nil || !*f.HasPassword {
			t.Errorf("the account that signed in with a password (%s): %+v %v, want hasPassword true", pe, f, err)
		}
	}
	if ce, cu, cs := os.Getenv("AGENTRY_TEST_AUTHENTIK_CONNECTED_EMAIL"), os.Getenv("AGENTRY_TEST_AUTHENTIK_CONNECTED_UID"), os.Getenv("AGENTRY_TEST_AUTHENTIK_CONNECTED_SOURCE"); ce != "" {
		ran++
		f, err := a.SignInFacts(ctx, directoryLink{UID: cu, Email: ce})
		if err != nil || f.FirstSource == nil || f.FirstSource.Slug != cs || f.HasPassword == nil || *f.HasPassword {
			t.Errorf("the socially created account (%s): %+v %v, want first source %q and hasPassword false", ce, f, err, cs)
		} else {
			t.Logf("socially created account: first source %s (%s), hasPassword false", f.FirstSource.Slug, f.FirstSource.Name)
		}
	}
	t.Logf("%d of the 2 flow-made cases ran", ran)
}
