package auth

import (
	"context"

	"github.com/google/uuid"

	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// ResolvePAT authenticates a presented PAT string against the store and
// builds the Principal (shared by the API middleware and the git layer).
func ResolvePAT(ctx context.Context, q *storegen.Queries, token string) (*Principal, error) {
	pat, err := q.GetPATByHash(ctx, HashToken(token))
	if err != nil {
		return nil, ErrUnauthorized
	}
	u, err := q.GetUserByID(ctx, pat.UserID)
	if err != nil || u.State != "active" {
		return nil, ErrUnauthorized
	}
	_ = q.TouchPAT(ctx, pat.ID) // best-effort last_used tracking

	rows, err := q.ListUserMemberships(ctx, pat.UserID)
	if err != nil {
		return nil, err
	}
	orgRoles := make(map[uuid.UUID]OrgRole, len(rows))
	for _, m := range rows {
		orgRoles[m.OrgID] = OrgRole(m.Role)
	}
	return &Principal{
		UserID:        pat.UserID,
		Handle:        u.Handle,
		Via:           "pat",
		Scopes:        pat.Scopes,
		OrgRoles:      orgRoles,
		EmailVerified: u.EmailVerifiedAt != nil,
		PATID:         pat.ID,
	}, nil
}
