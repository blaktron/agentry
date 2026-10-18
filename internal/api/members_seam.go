package api

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/registry"
)

// ProvisionedMember is a person an organization's identity provider
// provisioned, as a directory extension names them to the core: the
// address they are known at, the name the provider calls them by (a seed
// for a new account's handle) and a display name.
type ProvisionedMember struct {
	Email       string
	UserName    string
	DisplayName string
}

// ErrOrgNotProvisionable is Provision's refusal of an organization that is
// unknown, suspended or being decommissioned: its membership is frozen.
var ErrOrgNotProvisionable = errors.New("api: the organization is not active, so nobody is provisioned into it")

// ProvisionMember makes the person a pending member of orgID on a
// directory extension's word (pkg/extension.Deps.Members): the account at
// their address, or a new one with the address taken as verified. A pending
// membership holds no seat and confers nothing until an admin approves it,
// and an existing membership, pending or active, is left as it is. The
// staff organization admits only its own domain. The extension decides
// whom to provision; the core decides what provisioning is.
func (s *Server) ProvisionMember(ctx context.Context, ext string, orgID uuid.UUID, p ProvisionedMember) (uuid.UUID, error) {
	if s.st == nil {
		return uuid.Nil, errors.New("api: no database to provision members in")
	}
	email := strings.ToLower(strings.TrimSpace(p.Email))
	if strings.Count(email, "@") != 1 || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return uuid.Nil, errors.New("api: a provisioned member needs an address")
	}
	org, err := s.q().GetOrgByID(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrOrgNotProvisionable
	}
	if err != nil {
		return uuid.Nil, err
	}
	if org.State != registry.OrgStateActive || org.DecommissionAt != nil {
		return uuid.Nil, ErrOrgNotProvisionable
	}
	if err := s.staffOrgAddressIn(ctx, s.q(), orgID, email); err != nil {
		return uuid.Nil, err
	}
	userID, err := s.provisionPending(ctx, orgID, email, p.UserName, p.DisplayName, ext)
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.auditW.Write(ctx, s.q(), s.extensionMemberEvent(ext, orgID, audit.ActionSCIMUserProvision, userID)); err != nil {
		s.log.ErrorContext(ctx, "audit an extension's provisioning", "extension", ext, "err", err)
	}
	return userID, nil
}

// DeprovisionMember takes userID's membership of orgID away on a directory
// extension's word and revokes their org-bound tokens for orgID, every
// session and every remembered browser (pkg/extension.Deps.Members). The
// organization's last admin keeps the membership, so the organization keeps
// someone who can act, and loses every credential all the same; kept
// reports it. Calling it again does nothing more. It runs in any state of
// the organization: taking access away is never frozen.
func (s *Server) DeprovisionMember(ctx context.Context, ext string, orgID, userID uuid.UUID) (kept bool, err error) {
	if s.st == nil {
		return false, errors.New("api: no database to deprovision members in")
	}
	return s.deprovisionMember(ctx, orgID, userID, true, s.extensionMemberEvent(ext, orgID, audit.ActionSCIMUserDeactivate, userID))
}

// extensionMemberEvent is the audit row of an extension's provisioning
// act: the system as the actor, the extension named, as its other acts
// through the core are.
func (s *Server) extensionMemberEvent(ext string, orgID uuid.UUID, action audit.Action, userID uuid.UUID) audit.Event {
	return audit.Event{
		Action: action, ActorKind: audit.ActorSystem, OrgID: orgID,
		TargetKind: "user", TargetID: userID,
		Detail: map[string]any{"via": "extension", "extension": ext},
	}
}
