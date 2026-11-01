package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Which advisories name a version, and the first published version that
// fixes each: the range decides, a later version the range leaves out is
// the fix, and a version that is not published, or on another channel, is
// not one.
func TestAdvisoriesNamingAVersionAndTheirFix(t *testing.T) {
	ver := func(v, status, channel string) storegen.AgentVersion {
		return storegen.AgentVersion{Version: v, Status: status, Channel: channel}
	}
	now := time.Now()
	adv := func(affected string, published bool) storegen.Advisory {
		a := storegen.Advisory{ID: uuid.New(), AffectedVersions: affected, Severity: "high", Summary: affected}
		if published {
			a.PublishedAt = &now
		}
		return a
	}
	versions := []storegen.AgentVersion{
		ver("1.0.0", "published", "stable"),
		ver("1.1.0", "yanked", "stable"),
		ver("1.2.0", "needs_review", "stable"),
		ver("1.3.0", "published", "beta"),
		ver("1.4.0", "published", "stable"),
		ver("1.5.0", "yanked", "stable"),
		ver("1.6.0", "published", "beta"),
		ver("2.0.0", "published", "stable"),
	}
	advisories := []storegen.Advisory{
		adv("<1.4.0", true),         // names 1.0.0; 1.1–1.3 do not fix it (yanked, in review, another channel); 1.4.0 does
		adv(">=1.0.0 <2.0.0", true), // names 1.0.0; fixed in 2.0.0
		adv(">=5.0.0", true),        // does not name 1.0.0
		adv("<1.5.0", true),         // names 1.0.0; not fixed by 1.5.0 (yanked) or 1.6.0 (beta), so 2.0.0
		adv("<9.0.0", true),         // names 1.0.0; no fix published
		adv("every version", true),  // unreadable: named, no fix
		adv("<1.4.0", false),        // not published: never counted
	}
	got := advisoriesNaming(ver("1.0.0", "published", "stable"), versions, advisories)
	want := []struct {
		affected, fixedIn string
		unreadable        bool
	}{{"<1.4.0", "1.4.0", false}, {">=1.0.0 <2.0.0", "2.0.0", false}, {"<1.5.0", "2.0.0", false}, {"<9.0.0", "", false}, {"every version", "", true}}
	if len(got) != len(want) {
		t.Fatalf("got %d advisories, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.AffectedVersions != w.affected || g.FixedIn != w.fixedIn || g.RangeUnreadable != w.unreadable {
			t.Errorf("advisory %d: got %q fixed in %q unreadable %v, want %q fixed in %q unreadable %v",
				i, g.AffectedVersions, g.FixedIn, g.RangeUnreadable, w.affected, w.fixedIn, w.unreadable)
		}
	}

	// A version on the beta channel is fixed only by a published beta.
	beta := advisoriesNaming(ver("1.3.0", "published", "beta"), versions, []storegen.Advisory{adv("<1.4.0", true)})
	if len(beta) != 1 || beta[0].FixedIn != "1.6.0" {
		t.Errorf("a beta version: got %+v, want one advisory fixed in the later beta 1.6.0, not the stable 1.4.0", beta)
	}
}
