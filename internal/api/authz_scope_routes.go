package api

// PAT scope gates for route families whose authorization the generic §12.2
// chokepoint cannot express.
//
// Most routes declare one (resource, action) pair and auth.Check maps that
// action to the PAT scope that unlocks it. The review surface cannot: its
// authorization is "platform staff, or an org security_reviewer who is not
// the version's author", a judgement the chokepoint deliberately leaves to
// the handler (RouteDecl.SelfAuthorized). That left §12.3's `review:act`
// scope defined but unenforced — a PAT with `user:profile` alone could drive
// the review queue and record decisions, because the handler only ever
// checked the caller's ROLE.
//
// The gate below closes that hole in the auth layer rather than in each
// handler, so a new review route inherits it. Sessions are unaffected:
// §12.3 gives sessions the user's full authority and gates them with CSRF —
// scopes are a PAT-only least-privilege mechanism.

import (
	"net/http"
	"strings"

	"github.com/blaktron/agentry/internal/auth"
)

// scopedPathPrefixes maps an /api/v1 path prefix to the action whose scope a
// PAT must carry to touch it. Prefix matching (not exact) so sub-resources
// are covered by construction.
var scopedPathPrefixes = []struct {
	prefix string
	action auth.Action
}{
	{"/api/v1/review-queue", auth.ActReviewAct},
	{"/api/v1/review-items", auth.ActReviewAct},
	{"/api/v1/findings/", auth.ActReviewAct},
}

// checkPathScope enforces scopedPathPrefixes for PAT principals, writing the
// problem response and returning false on refusal.
func (s *Server) checkPathScope(w http.ResponseWriter, r *http.Request, p *auth.Principal) bool {
	if p == nil || p.Anonymous || p.Via != "pat" {
		return true
	}
	for _, sp := range scopedPathPrefixes {
		if !strings.HasPrefix(r.URL.Path, sp.prefix) {
			continue
		}
		if err := auth.Check(p, auth.Resource{}, sp.action); err != nil {
			problemForbidden(w, r, "this token is missing the "+string(auth.ScopeReviewAct)+" scope (§12.3)")
			return false
		}
	}
	return true
}
