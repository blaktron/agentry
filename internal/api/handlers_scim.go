package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/httpmux"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// SCIM 2.0 data plane. Mounted at /scim/v2 outside the generated
// OpenAPI handler; authenticated by a SCIM bearer token (scim_tokens), which
// identifies the tenant org. Media type is application/scim+json.
//
// Subset implemented: Users (create, get, list w/ `userName eq` filter, PATCH
// active=false / DELETE ⇒ deactivate membership + revoke org-bound PATs + kill
// sessions) and Groups→teams (create, get, list, membership replace/patch).

const (
	scimUserSchema    = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema   = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimMediaType     = "application/scim+json"
)

type scimCtx struct {
	orgID     uuid.UUID
	orgHandle string
}

type scimHandler func(w http.ResponseWriter, r *http.Request, sc scimCtx)

// mountSCIM registers the SCIM routes on the mux.
func (s *Server) mountSCIM(mux httpmux.Mux) {
	MountFunc(mux, "POST /scim/v2/Users", s.scimAuth(s.scimCreateUser))
	MountFunc(mux, "GET /scim/v2/Users", s.scimAuth(s.scimListUsers))
	MountFunc(mux, "GET /scim/v2/Users/{id}", s.scimAuth(s.scimGetUser))
	MountFunc(mux, "PATCH /scim/v2/Users/{id}", s.scimAuth(s.scimPatchUser))
	MountFunc(mux, "PUT /scim/v2/Users/{id}", s.scimAuth(s.scimPutUser))
	MountFunc(mux, "DELETE /scim/v2/Users/{id}", s.scimAuth(s.scimDeleteUser))

	MountFunc(mux, "POST /scim/v2/Groups", s.scimAuth(s.scimCreateGroup))
	MountFunc(mux, "GET /scim/v2/Groups", s.scimAuth(s.scimListGroups))
	MountFunc(mux, "GET /scim/v2/Groups/{id}", s.scimAuth(s.scimGetGroup))
	MountFunc(mux, "PATCH /scim/v2/Groups/{id}", s.scimAuth(s.scimPatchGroup))
	MountFunc(mux, "DELETE /scim/v2/Groups/{id}", s.scimAuth(s.scimDeleteGroup))
}

// scimAuth resolves the SCIM bearer token to an org and invokes next.
func (s *Server) scimAuth(next scimHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.st == nil {
			scimError(w, http.StatusServiceUnavailable, "database not configured")
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			scimError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		row, err := s.q().GetSCIMTokenByHash(r.Context(), auth.HashToken(token))
		if err != nil {
			scimError(w, http.StatusUnauthorized, "invalid or expired SCIM token")
			return
		}
		// The `scim` rate class, one bucket per organization: a
		// directory syncs from one place, and every token is the
		// organization's, so a second token buys no second budget. Spent
		// once the token is known and before anything else is read. The
		// RateLimit-* trio goes on every answer, as elsewhere, so an IdP can
		// pace itself before it is refused; the refusal carries Retry-After.
		res := s.limits.Allow("scim", row.OrgID.String(), s.classes.scim, s.classes.scimBurst)
		writeRateLimitHeaders(w, res)
		if !res.OK {
			s.rateLimited(r, "scim")
			scimError(w, http.StatusTooManyRequests, "too many SCIM requests for this organization; retry after the Retry-After interval")
			return
		}
		org, err := s.q().GetOrgByID(r.Context(), row.OrgID)
		if err != nil {
			scimError(w, http.StatusUnauthorized, "org not found")
			return
		}
		// The IdP provisions nothing into an organization that is
		// suspended or being decommissioned: every SCIM
		// call changes or reads membership, which the hold has frozen.
		if org.State != registry.OrgStateActive {
			scimError(w, http.StatusForbidden, "this organization is "+org.State)
			return
		}
		// The data plane closes with the entitlement, not only the door
		// that mints tokens: a token issued while the tier included
		// SCIM must stop provisioning when it no longer does. The token's
		// row survives, so the directory works again the moment the
		// subscription does — nothing has to be re-issued. Unknown
		// refuses, like every other entitlement gate.
		f, ferr := s.orgFeatures(r.Context(), row.OrgID)
		if ferr != nil {
			s.log.ErrorContext(r.Context(), "scim entitlements", "org", row.OrgID, "err", ferr)
			scimError(w, http.StatusForbidden, "directory provisioning is unavailable for this organization")
			return
		}
		if !f.SCIM {
			scimError(w, http.StatusForbidden, "directory provisioning is not included in this organization's subscription")
			return
		}
		next(w, r, scimCtx{orgID: row.OrgID, orgHandle: org.Handle})
	}
}

// ---- SCIM wire types ----

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id,omitempty"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       *scimName   `json:"name,omitempty"`
	Emails     []scimEmail `json:"emails,omitempty"`
	Active     bool        `json:"active"`
	Meta       *scimMeta   `json:"meta,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

type scimPatchOp struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

func scimError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", scimMediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{scimErrorSchema}, "detail": detail, "status": itoa(status),
	})
}

func scimWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimMediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// itoa renders a status as SCIM's error schema wants it, a string. Every
// status renders, including 403 (a suspended organization or a missing
// entitlement) and 429.
func itoa(n int) string { return strconv.Itoa(n) }

func userToSCIM(id uuid.UUID, email, displayName string, active bool) scimUser {
	return scimUser{
		Schemas: []string{scimUserSchema}, ID: id.String(), UserName: email,
		Name: &scimName{Formatted: displayName}, Emails: []scimEmail{{Value: email, Primary: true}},
		Active: active, Meta: &scimMeta{ResourceType: "User"},
	}
}

// ---- Users ----

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	var in scimUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM user")
		return
	}
	email := scimPrimaryEmail(in)
	if email == "" {
		scimError(w, http.StatusBadRequest, "userName/email required")
		return
	}
	// Duplicate within the org → 409 (SCIM create semantics).
	if existing, err := s.q().FindOrgMemberByEmail(r.Context(), storegen.FindOrgMemberByEmailParams{OrgID: sc.orgID, Email: email}); err == nil {
		scimWrite(w, http.StatusConflict, map[string]any{
			"schemas": []string{scimErrorSchema}, "detail": "user already a member", "status": "409",
			"id": existing.ID.String(),
		})
		return
	}
	// The staff organization provisions only its own domain,
	// before any account is made for the address.
	if err := s.staffOrgAddressIn(r.Context(), s.q(), sc.orgID, email); err != nil {
		scimStaffOrgRefusal(w, r, s, err)
		return
	}
	displayName := ""
	if in.Name != nil {
		displayName = in.Name.Formatted
	}
	userID, err := s.provisionPending(r.Context(), sc.orgID, email, in.UserName, displayName, "scim")
	if err != nil {
		s.log.ErrorContext(r.Context(), "scim create user", "err", err)
		scimError(w, http.StatusInternalServerError, "provisioning failed")
		return
	}
	_ = s.auditW.Write(r.Context(), s.q(), s.scimEvent(sc.orgID, audit.ActionSCIMUserProvision, "user", userID))
	scimWrite(w, http.StatusCreated, userToSCIM(userID, email, orDefault(displayName, email), true))
}

// provisionPending links an existing global user by email or JIT-creates
// one, then adds a **pending** org membership marked via_scim: the IdP says
// who exists, an admin says who is a member. A pending membership holds no
// seat and confers nothing, so a provisioning door still succeeds however
// many seats the organization has left; the wall is at the approval. A new
// account's handle is seeded from the IdP's userName (its local part when
// the userName is the address), the name the directory knows the person
// by, and its address is taken as verified, because the organization's
// identity provider vouches for it. An existing membership, pending or
// active, is left as it is. Every door that creates an account fires
// user.registered, with via naming the door.
func (s *Server) provisionPending(ctx context.Context, orgID uuid.UUID, email, userName, displayName, via string) (uuid.UUID, error) {
	if u, err := s.q().GetUserByEmail(ctx, email); err == nil {
		if err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
			_, err := q.UpsertPendingMembership(ctx, storegen.UpsertPendingMembershipParams{
				OrgID: orgID, UserID: u.ID, Role: string(auth.RoleMember), ViaScim: true,
			})
			return err
		}); err != nil {
			return uuid.Nil, err
		}
		return u.ID, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	userID := newUUID()
	handle, err := s.allocateHandle(ctx, userName, email, email)
	if err != nil {
		return uuid.Nil, err
	}
	dn := orDefault(displayName, handle)
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := q.CreateHandle(ctx, storegen.CreateHandleParams{ID: userID, Handle: handle, Kind: "user"}); err != nil {
			return err
		}
		if _, err := q.CreateUser(ctx, storegen.CreateUserParams{ID: userID, Email: email, DisplayName: dn}); err != nil {
			return err
		}
		// IdP-provisioned via a token an org admin minted: treat as verified.
		if err := q.MarkEmailVerified(ctx, userID); err != nil {
			return err
		}
		_, err := q.UpsertPendingMembership(ctx, storegen.UpsertPendingMembershipParams{
			OrgID: orgID, UserID: userID, Role: string(auth.RoleMember), ViaScim: true,
		})
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	s.fireEvent(ctx, Event{Kind: "user.registered", UserID: userID, OrgID: orgID, Payload: map[string]any{
		"handle": handle, "email": email, "emailVerified": true, "via": via,
	}})
	return userID, nil
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	filter := r.URL.Query().Get("filter")
	resources := []any{}
	if email, ok := parseUserNameEqFilter(filter); ok {
		if u, err := s.q().FindOrgMemberByEmail(r.Context(), storegen.FindOrgMemberByEmailParams{OrgID: sc.orgID, Email: email}); err == nil {
			resources = append(resources, userToSCIM(u.ID, u.Email, orDefault(u.DisplayName, u.Email), u.State == "active"))
		}
	} else {
		rows, err := s.q().ListScimUsers(r.Context(), sc.orgID)
		if err != nil {
			scimError(w, http.StatusInternalServerError, "list failed")
			return
		}
		for _, u := range rows {
			resources = append(resources, userToSCIM(u.ID, u.Email, orDefault(u.DisplayName, u.Email), u.State == "active"))
		}
	}
	scimWrite(w, http.StatusOK, scimListResponse{
		Schemas: []string{scimListSchema}, TotalResults: len(resources),
		StartIndex: 1, ItemsPerPage: len(resources), Resources: resources,
	})
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	u, err := s.q().GetScimUser(r.Context(), storegen.GetScimUserParams{OrgID: sc.orgID, ID: id})
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	scimWrite(w, http.StatusOK, userToSCIM(u.ID, u.Email, orDefault(u.DisplayName, u.Email), u.State == "active"))
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	u, err := s.q().GetScimUser(r.Context(), storegen.GetScimUserParams{OrgID: sc.orgID, ID: id})
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	var patch scimPatchOp
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&patch); err != nil {
		scimError(w, http.StatusBadRequest, "invalid PatchOp")
		return
	}
	setActive, active := patchActiveValue(patch)
	if setActive && !active {
		if err := s.scimDeactivate(r.Context(), sc.orgID, id); err != nil {
			if scimLastAdmin(w, err) {
				return
			}
			s.log.ErrorContext(r.Context(), "scim deactivate", "err", err)
			scimError(w, http.StatusInternalServerError, "deactivate failed")
			return
		}
		scimWrite(w, http.StatusOK, userToSCIM(id, u.Email, orDefault(u.DisplayName, u.Email), false))
		return
	}
	// No-op / reactivation not modeled beyond membership presence.
	scimWrite(w, http.StatusOK, userToSCIM(id, u.Email, orDefault(u.DisplayName, u.Email), u.State == "active"))
}

// scimPutUser implements the spec-conformant full-resource replace (RFC 7644
// §3.5.1). Okta's deactivation is a PUT of the whole user with
// "active": false, so it is not decoded as PatchOp operations, which would
// yield zero operations and a 200 with nothing done. An IdP that believes it
// has offboarded someone, on a registry where their sessions still work, is
// the worst possible failure mode for SCIM provisioning.
func (s *Server) scimPutUser(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	u, err := s.q().GetScimUser(r.Context(), storegen.GetScimUserParams{OrgID: sc.orgID, ID: id})
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	var in scimUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM user")
		return
	}

	// active=false is the deactivation path: identical to PATCH active=false
	// and DELETE — drop the membership, revoke org-bound PATs, kill sessions.
	if !in.Active {
		if err := s.scimDeactivate(r.Context(), sc.orgID, id); err != nil {
			if scimLastAdmin(w, err) {
				return
			}
			s.log.ErrorContext(r.Context(), "scim put deactivate", "err", err)
			scimError(w, http.StatusInternalServerError, "deactivate failed")
			return
		}
		scimWrite(w, http.StatusOK, userToSCIM(id, u.Email, orDefault(u.DisplayName, u.Email), false))
		return
	}

	// userName is the account's email here, and email changes are an identity
	// change, not an attribute update: refuse rather than silently ignore, so
	// an IdP that renames a user finds out instead of drifting.
	if email := scimPrimaryEmail(in); email != "" && !strings.EqualFold(email, u.Email) {
		scimError(w, http.StatusBadRequest, "userName/email is immutable; deactivate and re-provision instead")
		return
	}

	// Reinstating provisions again, so the staff organization's door applies.
	if err := s.staffOrgAddressIn(r.Context(), s.q(), sc.orgID, u.Email); err != nil {
		scimStaffOrgRefusal(w, r, s, err)
		return
	}
	displayName := u.DisplayName
	if in.Name != nil && strings.TrimSpace(in.Name.Formatted) != "" {
		displayName = in.Name.Formatted
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if displayName != u.DisplayName {
			if _, err := q.UpdateUserDisplayName(r.Context(), storegen.UpdateUserDisplayNameParams{
				ID: id, DisplayName: displayName,
			}); err != nil {
				return err
			}
		}
		// Re-assert the membership: a PUT with active=true on someone
		// previously deactivated is how an IdP reinstates them — as a
		// PENDING member. Deactivating removed the row,
		// so this is a fresh provisioning, and SCIM provisions; an admin
		// approves. Someone who is still an active member is untouched.
		if _, err := q.UpsertPendingMembership(r.Context(), storegen.UpsertPendingMembershipParams{
			OrgID: sc.orgID, UserID: id, Role: orDefault(u.Role, string(auth.RoleMember)), ViaScim: true,
		}); err != nil {
			return err
		}
		return s.auditW.Write(r.Context(), q, s.scimEvent(sc.orgID, audit.ActionSCIMUserProvision, "user", id))
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "scim put user", "err", err)
		scimError(w, http.StatusInternalServerError, "update failed")
		return
	}
	scimWrite(w, http.StatusOK, userToSCIM(id, u.Email, orDefault(displayName, u.Email), true))
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	if _, err := s.q().GetScimUser(r.Context(), storegen.GetScimUserParams{OrgID: sc.orgID, ID: id}); err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.scimDeactivate(r.Context(), sc.orgID, id); err != nil {
		if scimLastAdmin(w, err) {
			return
		}
		scimError(w, http.StatusInternalServerError, "deactivate failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scimLastAdmin answers a deactivation refused for being the last admin's,
// and reports whether it did.
func scimLastAdmin(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, errLastAdmin) {
		return false
	}
	scimError(w, http.StatusConflict, "this user is the organization's last admin; make another member an admin before deactivating them")
	return true
}

// scimDeactivate is the deactivation: drop the membership, revoke the
// user's org-bound PATs, and kill the user's sessions — all in one request so
// access is revoked well within the 60s acceptance bound. SCIM never
// hard-deletes the global user (they may exist outside the org). The
// organization's last admin is the one person it cannot deprovision:
// the IdP is answered errLastAdmin and the org keeps
// someone who can act until another admin is made.
func (s *Server) scimDeactivate(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := s.deprovisionMember(ctx, orgID, userID, false, s.scimEvent(orgID, audit.ActionSCIMUserDeactivate, "user", userID))
	return err
}

// deprovisionMember takes userID's membership of orgID away and revokes
// their org-bound PATs for orgID, every session and every remembered
// browser, in one transaction, audited with ev. The last admin's
// membership is the one thing it cannot take: with keepLastAdmin false the
// whole call is refused with errLastAdmin; with it true the membership
// stays (the organization keeps someone who can act), the credentials are
// revoked, and kept reports it. A person who is not a member loses their
// sessions and remembered browsers all the same.
func (s *Server) deprovisionMember(ctx context.Context, orgID, userID uuid.UUID, keepLastAdmin bool, ev audit.Event) (kept bool, err error) {
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		kept = false
		if err := guardLastAdmin(ctx, q, orgID, userID); err != nil {
			if !keepLastAdmin || !errors.Is(err, errLastAdmin) {
				return err
			}
			kept = true
		}
		if !kept {
			if _, err := q.DeleteMembership(ctx, storegen.DeleteMembershipParams{OrgID: orgID, UserID: userID}); err != nil {
				return err
			}
		}
		if _, err := q.RevokeOrgBoundPATsForUser(ctx, storegen.RevokeOrgBoundPATsForUserParams{UserID: userID, OrgID: &orgID}); err != nil {
			return err
		}
		if _, err := q.RevokeUserSessions(ctx, userID); err != nil {
			return err
		}
		// A remembered browser is a way back in that outlives the sessions
		// killed just above, and deactivation leaves the account's password and
		// state untouched on purpose — the person may exist outside the
		// organization. Without this the deprovisioned user could sign in again
		// and be asked for *less* than before, the second factor skipped, which
		// is the opposite of what this function promises.
		if _, err := q.RevokeTrustedDevicesForUser(ctx, userID); err != nil {
			return err
		}
		row := ev
		if kept {
			row.Detail = map[string]any{"lastAdminKept": true}
			for k, v := range ev.Detail {
				row.Detail[k] = v
			}
		}
		if err := s.auditW.Write(ctx, q, row); err != nil {
			return err
		}
		// Deprovisioned from the staff organization is no longer staff;
		// whoever deprovisioned is the actor.
		actor := ev
		actor.Action = audit.ActionUserStaffSync
		return s.syncStaffIn(ctx, q, userID, registry.StaffSyncMembership, actor)
	})
	return kept, err
}

// scimStaffOrgRefusal answers the IdP when the staff organization's door
// refuses an address (409, the SCIM shape), or a 500 for any other error.
func scimStaffOrgRefusal(w http.ResponseWriter, r *http.Request, s *Server, err error) {
	if errors.Is(err, registry.ErrStaffOrgDomain) {
		scimError(w, http.StatusConflict, "this organization is the deployment's staff organization and admits only addresses at "+s.cfg.Auth.StaffDomain)
		return
	}
	s.log.ErrorContext(r.Context(), "scim staff organization door", "err", err)
	scimError(w, http.StatusInternalServerError, "provisioning failed")
}

// ---- Groups (teams) ----

type scimGroupMember struct {
	Value string `json:"value"` // SCIM user id (our user uuid)
}

type scimGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id,omitempty"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members,omitempty"`
	Meta        *scimMeta         `json:"meta,omitempty"`
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	var in scimGroup
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		scimError(w, http.StatusBadRequest, "invalid group")
		return
	}
	slug := sanitizeHandle(in.DisplayName)
	if slug == "" {
		scimError(w, http.StatusBadRequest, "displayName required")
		return
	}
	teamID := newUUID()
	groupKey := in.ExternalID
	if groupKey == "" {
		groupKey = teamID.String()
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.CreateTeamWithScim(r.Context(), storegen.CreateTeamWithScimParams{
			ID: teamID, OrgID: sc.orgID, Slug: slug, ScimGroupID: &groupKey,
		}); err != nil {
			return err
		}
		return s.auditW.Write(r.Context(), q, s.scimEvent(sc.orgID, audit.ActionSCIMGroupSync, "team", teamID))
	})
	if err != nil {
		if isUniqueViolation(err) {
			scimError(w, http.StatusConflict, "group already exists")
			return
		}
		scimError(w, http.StatusInternalServerError, "create failed")
		return
	}
	// A membership write that fails must be reported: SCIM clients retry on
	// 5xx, and silently discarding the error would leave the IdP believing a group
	// had been synced when the team was empty.
	if len(in.Members) > 0 {
		if err := s.scimReplaceMembers(r.Context(), sc.orgID, teamID, in.Members); err != nil {
			s.log.ErrorContext(r.Context(), "scim group create: member sync", "err", err, "team", teamID)
			scimError(w, http.StatusInternalServerError, "group created but member sync failed; retry")
			return
		}
	}
	scimWrite(w, http.StatusCreated, scimGroup{
		Schemas: []string{scimGroupSchema}, ID: teamID.String(), DisplayName: slug,
		ExternalID: in.ExternalID, Meta: &scimMeta{ResourceType: "Group"},
	})
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	t, err := s.q().GetTeamByID(r.Context(), storegen.GetTeamByIDParams{ID: id, OrgID: sc.orgID})
	if err != nil {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	memberIDs, _ := s.q().ListTeamMemberIDs(r.Context(), t.ID)
	members := make([]scimGroupMember, 0, len(memberIDs))
	for _, m := range memberIDs {
		members = append(members, scimGroupMember{Value: m.String()})
	}
	scimWrite(w, http.StatusOK, scimGroup{
		Schemas: []string{scimGroupSchema}, ID: t.ID.String(), DisplayName: t.Slug,
		Members: members, Meta: &scimMeta{ResourceType: "Group"},
	})
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	rows, err := s.q().ListTeams(r.Context(), sc.orgID)
	if err != nil {
		scimError(w, http.StatusInternalServerError, "list failed")
		return
	}
	resources := []any{}
	for _, t := range rows {
		resources = append(resources, scimGroup{
			Schemas: []string{scimGroupSchema}, ID: t.ID.String(), DisplayName: t.Slug,
			Meta: &scimMeta{ResourceType: "Group"},
		})
	}
	scimWrite(w, http.StatusOK, scimListResponse{
		Schemas: []string{scimListSchema}, TotalResults: len(resources),
		StartIndex: 1, ItemsPerPage: len(resources), Resources: resources,
	})
}

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	t, err := s.q().GetTeamByID(r.Context(), storegen.GetTeamByIDParams{ID: id, OrgID: sc.orgID})
	if err != nil {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	var patch scimPatchOp
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&patch); err != nil {
		scimError(w, http.StatusBadRequest, "invalid PatchOp")
		return
	}
	// Membership writes are the point of a group PATCH: a failure has to
	// reach the IdP as a 5xx so it retries. Only "this user is not an org
	// member" is tolerated — that is a legitimate no-op, not a lost write.
	for _, op := range patch.Operations {
		members := parseMembersValue(op.Value)
		var err error
		switch strings.ToLower(op.Op) {
		case "replace":
			if strings.EqualFold(op.Path, "members") || op.Path == "" {
				err = s.scimReplaceMembers(r.Context(), sc.orgID, t.ID, members)
			}
		case "add":
			for _, m := range members {
				uid, perr := uuid.Parse(m.Value)
				if perr != nil {
					continue
				}
				if aerr := s.addTeamMemberIfOrgMember(r.Context(), sc.orgID, t.ID, uid); aerr != nil &&
					!errors.Is(aerr, errNotOrgMember) {
					err = aerr
					break
				}
			}
		case "remove":
			for _, m := range members {
				uid, perr := uuid.Parse(m.Value)
				if perr != nil {
					continue
				}
				if _, rerr := s.q().RemoveTeamMember(r.Context(), storegen.RemoveTeamMemberParams{
					TeamID: t.ID, UserID: uid,
				}); rerr != nil {
					err = rerr
					break
				}
			}
		}
		if err != nil {
			s.log.ErrorContext(r.Context(), "scim group patch: member sync", "err", err, "team", t.ID, "op", op.Op)
			scimError(w, http.StatusInternalServerError, "group membership sync failed; retry")
			return
		}
	}
	if err := s.auditW.Write(r.Context(), s.q(), s.scimEvent(sc.orgID, audit.ActionSCIMGroupSync, "team", t.ID)); err != nil {
		s.log.ErrorContext(r.Context(), "scim group patch: audit", "err", err, "team", t.ID)
		scimError(w, http.StatusInternalServerError, "group synced but not audited; retry")
		return
	}
	s.scimGetGroup(w, r, sc)
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request, sc scimCtx) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	t, err := s.q().GetTeamByID(r.Context(), storegen.GetTeamByIDParams{ID: id, OrgID: sc.orgID})
	if err != nil {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	if _, err := s.q().DeleteTeam(r.Context(), storegen.DeleteTeamParams{OrgID: sc.orgID, Slug: t.Slug}); err != nil {
		scimError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scimReplaceMembers sets a team's membership to exactly the given SCIM members
// (that are org members).
func (s *Server) scimReplaceMembers(ctx context.Context, orgID, teamID uuid.UUID, members []scimGroupMember) error {
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := q.ClearTeamMembers(ctx, teamID); err != nil {
			return err
		}
		for _, m := range members {
			uid, err := uuid.Parse(m.Value)
			if err != nil {
				continue
			}
			if _, err := q.GetMembership(ctx, storegen.GetMembershipParams{OrgID: orgID, UserID: uid}); err != nil {
				continue // only org members can join teams
			}
			if err := q.AddTeamMember(ctx, storegen.AddTeamMemberParams{TeamID: teamID, UserID: uid}); err != nil {
				return err
			}
		}
		return nil
	})
}

// errNotOrgMember distinguishes "this user does not belong to the org" — a
// no-op the IdP need not retry — from a genuine write failure.
var errNotOrgMember = errors.New("scim: not an org member")

func (s *Server) addTeamMemberIfOrgMember(ctx context.Context, orgID, teamID, userID uuid.UUID) error {
	if _, err := s.q().GetMembership(ctx, storegen.GetMembershipParams{OrgID: orgID, UserID: userID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotOrgMember
		}
		return err
	}
	return s.q().AddTeamMember(ctx, storegen.AddTeamMemberParams{TeamID: teamID, UserID: userID})
}

// ---- helpers ----

func (s *Server) scimEvent(orgID uuid.UUID, action audit.Action, targetKind string, targetID uuid.UUID) audit.Event {
	return audit.Event{
		Action: action, ActorKind: audit.ActorSCIM, OrgID: orgID,
		TargetKind: targetKind, TargetID: targetID,
	}
}

func scimPrimaryEmail(u scimUser) string {
	for _, e := range u.Emails {
		if e.Primary && e.Value != "" {
			return strings.ToLower(e.Value)
		}
	}
	if len(u.Emails) > 0 && u.Emails[0].Value != "" {
		return strings.ToLower(u.Emails[0].Value)
	}
	if strings.Contains(u.UserName, "@") {
		return strings.ToLower(u.UserName)
	}
	return ""
}

// parseUserNameEqFilter parses SCIM `userName eq "x"` (the only filter
// requires).
func parseUserNameEqFilter(filter string) (string, bool) {
	f := strings.TrimSpace(filter)
	if f == "" {
		return "", false
	}
	low := strings.ToLower(f)
	if !strings.HasPrefix(low, "username eq ") {
		return "", false
	}
	val := strings.TrimSpace(f[len("userName eq "):])
	val = strings.Trim(val, "\"")
	return strings.ToLower(val), val != ""
}

// patchActiveValue extracts an `active` replace from a PatchOp, tolerating both
// `{"path":"active","value":false}` and `{"value":{"active":false}}` shapes.
func patchActiveValue(p scimPatchOp) (set bool, active bool) {
	for _, op := range p.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		if strings.EqualFold(op.Path, "active") {
			var b bool
			if json.Unmarshal(op.Value, &b) == nil {
				return true, b
			}
		}
		var obj struct {
			Active *bool `json:"active"`
		}
		if json.Unmarshal(op.Value, &obj) == nil && obj.Active != nil {
			return true, *obj.Active
		}
	}
	return false, false
}

func parseMembersValue(raw json.RawMessage) []scimGroupMember {
	if len(raw) == 0 {
		return nil
	}
	var members []scimGroupMember
	if json.Unmarshal(raw, &members) == nil && len(members) > 0 {
		return members
	}
	var wrap struct {
		Members []scimGroupMember `json:"members"`
	}
	if json.Unmarshal(raw, &wrap) == nil {
		return wrap.Members
	}
	return nil
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
