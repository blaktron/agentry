package auth

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ParseSSHPublicKey validates an authorized_keys-style line and returns the
// key type, the canonical "type base64" form and the SHA256 fingerprint.
func ParseSSHPublicKey(line string) (keyType, canonical, fingerprint string, err error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return "", "", "", err
	}
	canonical = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	return pub.Type(), canonical, ssh.FingerprintSHA256(pub), nil
}

// SSHKeyScopes is what an SSH key is worth: the repository transport and
// the release tag it may create when the role allows (§6.4); never the API.
var SSHKeyScopes = []string{string(ScopeRepoRead), string(ScopeRepoWrite), string(ScopeAgentPublish)}

// ResolveSSHKey builds the Principal for a presented SSH public key by its
// fingerprint (§6.1 Q7, agentry#70). Via is "ssh": an SSH key is never
// org-bound, so SSOSatisfied is false and an enforced-SSO org's push stays
// HTTPS-with-org-bound-PAT only, exactly as §6.4's table reads.
func ResolveSSHKey(ctx context.Context, q *storegen.Queries, fingerprint string) (*Principal, error) {
	key, err := q.GetSSHKeyByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, ErrUnauthorized
	}
	u, err := q.GetUserByID(ctx, key.UserID)
	if err != nil || u.State != "active" {
		return nil, ErrUnauthorized
	}
	_ = q.TouchSSHKey(ctx, key.ID)
	rows, err := q.ListUserMemberships(ctx, key.UserID)
	if err != nil {
		return nil, err
	}
	orgRoles := make(map[uuid.UUID]OrgRole, len(rows))
	for _, m := range rows {
		orgRoles[m.OrgID] = OrgRole(m.Role)
	}
	return &Principal{
		UserID:        key.UserID,
		Handle:        u.Handle,
		Via:           "ssh",
		Scopes:        append([]string(nil), SSHKeyScopes...),
		OrgRoles:      orgRoles,
		EmailVerified: u.EmailVerifiedAt != nil,
		Unactivated:   Unactivated(u.EmailVerifiedAt, u.Email),
		PlatformStaff: u.PlatformStaff,
		SSHKeyID:      key.ID,
	}, nil
}
