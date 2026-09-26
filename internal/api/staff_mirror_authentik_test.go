package api

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"testing"
)

// TestAuthentikGroupsAgainstALiveDirectory runs the mirror's directory
// calls against a real authentik (agentry#598), which the fake in
// staff_mirror_test.go only imitates: the group lookup and its creation,
// the member listing by group name, the exact address match over
// authentik's substring filter, add_user and remove_user. It needs a
// throwaway directory and an admin token, and is skipped without them:
//
//	AGENTRY_TEST_AUTHENTIK_URL=http://127.0.0.1:9000 AGENTRY_TEST_AUTHENTIK_TOKEN=… go test ./internal/api -run LiveDirectory
func TestAuthentikGroupsAgainstALiveDirectory(t *testing.T) {
	base, token := os.Getenv("AGENTRY_TEST_AUTHENTIK_URL"), os.Getenv("AGENTRY_TEST_AUTHENTIK_TOKEN")
	if base == "" || token == "" {
		t.Skip("AGENTRY_TEST_AUTHENTIK_URL / AGENTRY_TEST_AUTHENTIK_TOKEN not set")
	}
	ctx := context.Background()
	a := newAuthentikEraser(base, token)
	tag := fmt.Sprintf("%06x", rand.Int63n(1<<24)) //nolint:gosec // test names
	group := "agentry-mirror-live-" + tag
	mkUser := func(name, email string) int {
		var u struct {
			PK int `json:"pk"`
		}
		if err := a.doJSON(ctx, http.MethodPost, "/api/v3/core/users/", map[string]any{
			"username": name + tag, "name": name, "email": email, "is_active": true, "path": "users",
		}, &u); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/api/v3/core/users/%d/", u.PK), nil, nil) })
		return u.PK
	}
	staff := mkUser("live-staff", "live-"+tag+"@example.test")
	_ = mkUser("live-lookalike", "xlive-"+tag+"@example.test") // a substring match authentik returns

	gid, members, err := a.GroupMembers(ctx, group)
	if err != nil || gid == "" || len(members) != 0 {
		t.Fatalf("a new group: %q %v %v", gid, members, err)
	}
	t.Cleanup(func() { _ = a.doJSON(ctx, http.MethodDelete, "/api/v3/core/groups/"+gid+"/", nil, nil) })
	got, err := a.AccountsByEmail(ctx, "LIVE-"+tag+"@example.test")
	if err != nil || len(got) != 1 || got[0].PK != staff || got[0].UID == "" {
		t.Fatalf("the exact, case-blind match, with its uid: %+v %v", got, err)
	}
	if err := a.SetMember(ctx, gid, staff, true); err != nil {
		t.Fatal(err)
	}
	gid2, members, err := a.GroupMembers(ctx, group)
	if err != nil || gid2 != gid || len(members) != 1 || members[0].PK != staff || members[0].UID != got[0].UID {
		t.Fatalf("after add_user: %q %+v %v", gid2, members, err)
	}
	if err := a.SetMember(ctx, gid, staff, false); err != nil {
		t.Fatal(err)
	}
	if _, members, err := a.GroupMembers(ctx, group); err != nil || len(members) != 0 {
		t.Fatalf("after remove_user: %+v %v", members, err)
	}
}
