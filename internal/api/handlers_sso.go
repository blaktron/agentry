package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	oidcrp "github.com/blaktron/agentry/internal/auth/oidc"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// ssoURLs returns the SP metadata/ACS and OIDC redirect URLs for an org,
// preferring the configured public origin and falling back to the request's
// own scheme+host (so tests and self-host deployments work without BaseURL).
func (s *Server) ssoURLs(r *http.Request, handle string) (metadataURL, acsURL, oidcRedirect string) {
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	if base == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	prefix := base + "/api/v1/orgs/" + handle + "/sso"
	return prefix + "/saml/metadata", prefix + "/saml/acs", prefix + "/oidc/callback"
}

// samlSloURL is the SP's Single Logout endpoint for an org (§12.4, agentry#62).
func (s *Server) samlSloURL(r *http.Request, handle string) string {
	metadataURL, _, _ := s.ssoURLs(r, handle)
	return strings.TrimSuffix(metadataURL, "/metadata") + "/slo"
}

// ---- SSO connection config CRUD (admin only, §12.4) ----

// ListSsoConnections implements GET /orgs/{org}/sso/connections.
func (s *Server) ListSsoConnections(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	rows, err := s.q().ListSSOConnections(r.Context(), orgRow.ID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	out := make([]SsoConnection, 0, len(rows))
	for _, c := range rows {
		out = append(out, ssoConnToAPI(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// PutSsoConnection implements PUT /orgs/{org}/sso/connections/{kind}.
func (s *Server) PutSsoConnection(w http.ResponseWriter, r *http.Request, org OrgHandle, kind PutSsoConnectionParamsKind) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	k := string(kind)
	if k != "saml" && k != "oidc" {
		problemValidation(w, r, "The connection kind must be saml or oidc.")
		return
	}
	var req SsoConnectionInput
	if !readJSON(w, r, &req) {
		return
	}
	// The stored row, when there is one, so a save that omits the client
	// secret keeps the sealed one (agentry#272): the upsert replaces the whole
	// config, and before this an edit to any other field dropped the secret.
	var prev []byte
	if row, err := s.q().GetSSOConnection(r.Context(), storegen.GetSSOConnectionParams{OrgID: orgRow.ID, Kind: k}); err == nil {
		prev = row.Config
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.ErrorContext(r.Context(), "put sso connection: read current", "err", err)
		problemInternal(w, r)
		return
	}
	stored, verr := s.buildStoredSSOConfig(r, orgRow.Handle, k, req.Config, prev)
	if verr != nil {
		problemValidation(w, r, sentence(verr.Error()))
		return
	}
	cfgJSON, err := json.Marshal(stored)
	if err != nil {
		problemInternal(w, r)
		return
	}
	var conn storegen.SsoConnection
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		c, err := q.UpsertSSOConnection(r.Context(), storegen.UpsertSSOConnectionParams{
			ID: newUUID(), OrgID: orgRow.ID, Kind: k, Config: cfgJSON, Enabled: req.Enabled,
		})
		if err != nil {
			return err
		}
		conn = c
		e := auditEvent(r, audit.ActionSSOConnectionSet)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "sso_connection", c.ID
		e.Detail = map[string]any{"kind": k, "enabled": req.Enabled}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "put sso connection", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, ssoConnToAPI(conn))
}

// DeleteSsoConnection implements DELETE /orgs/{org}/sso/connections/{kind}.
func (s *Server) DeleteSsoConnection(w http.ResponseWriter, r *http.Request, org OrgHandle, kind DeleteSsoConnectionParamsKind) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.DeleteSSOConnection(r.Context(), storegen.DeleteSSOConnectionParams{OrgID: orgRow.ID, Kind: string(kind)}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionSSOConnectionDelete)
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "sso_connection", orgRow.ID
		e.Detail = map[string]any{"kind": string(kind)}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// storedOIDCConfig is the persisted OIDC config: the client secret is AES-GCM
// sealed (base64) so it never sits in the jsonb as plaintext.
type storedOIDCConfig struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"clientId"`
	ClientSecretEnc string   `json:"clientSecretEnc,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
}

// buildStoredSSOConfig validates the input config for a kind and returns the
// JSON-serializable form to persist (OIDC secrets sealed; SAML validated by
// constructing the SP).
// prev is the connection's current stored config, nil when there is none;
// an OIDC save without a clientSecret carries the sealed one forward from it.
func (s *Server) buildStoredSSOConfig(r *http.Request, handle, kind string, in map[string]interface{}, prev []byte) (any, error) {
	switch kind {
	case "saml":
		var c samlsp.Config
		raw, _ := json.Marshal(in)
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("the saml config could not be read: %w", err)
		}
		metadataURL, acsURL, _ := s.ssoURLs(r, handle)
		if _, err := samlsp.New(c, metadataURL, acsURL, s.samlReplay); err != nil {
			return nil, err
		}
		return c, nil
	case "oidc":
		issuer, _ := in["issuer"].(string)
		clientID, _ := in["clientId"].(string)
		if issuer == "" || clientID == "" {
			return nil, errors.New("an oidc connection needs an issuer and a clientId")
		}
		out := storedOIDCConfig{Issuer: issuer, ClientID: clientID}
		if secret, _ := in["clientSecret"].(string); secret != "" {
			sealed, err := s.sealer.Seal([]byte(secret))
			if err != nil {
				return nil, errors.New("the server could not encrypt the client secret, and nothing was stored")
			}
			out.ClientSecretEnc = base64.StdEncoding.EncodeToString(sealed)
		} else if prev != nil {
			var cur storedOIDCConfig
			if json.Unmarshal(prev, &cur) == nil {
				out.ClientSecretEnc = cur.ClientSecretEnc
			}
		}
		if scopes, ok := in["scopes"].([]interface{}); ok {
			for _, v := range scopes {
				if str, ok := v.(string); ok {
					out.Scopes = append(out.Scopes, str)
				}
			}
		}
		return out, nil
	}
	return nil, errors.New("unknown kind")
}

// ssoConnToAPI redacts secrets before returning a connection.
func ssoConnToAPI(c storegen.SsoConnection) SsoConnection {
	out := SsoConnection{Kind: SsoConnectionKind(c.Kind), Enabled: c.Enabled}
	var cfg map[string]interface{}
	if json.Unmarshal(c.Config, &cfg) == nil {
		delete(cfg, "clientSecretEnc")
		delete(cfg, "clientSecret")
		out.Config = &cfg
	}
	return out
}

// samlSPForOrg builds the SAML SP for an org's enabled connection, returning
// the connection id (for identity linking).
func (s *Server) samlSPForOrg(r *http.Request, orgRow storegen.GetOrgByHandleRow) (*samlsp.SP, uuid.UUID, error) {
	conn, err := s.q().GetEnabledSSOConnection(r.Context(), storegen.GetEnabledSSOConnectionParams{OrgID: orgRow.ID, Kind: "saml"})
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("no enabled saml connection")
	}
	sp, err := s.samlSPFromConfig(r, orgRow.Handle, conn.Config)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return sp, conn.ID, nil
}

// samlSPFromConfig builds the SP for an org handle from a stored connection
// config (the ACS/metadata path and the SLO path share it).
func (s *Server) samlSPFromConfig(r *http.Request, orgHandle string, raw []byte) (*samlsp.SP, error) {
	var c samlsp.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	metadataURL, acsURL, _ := s.ssoURLs(r, orgHandle)
	sp, err := samlsp.New(c, metadataURL, acsURL, s.samlReplay)
	if err != nil {
		return nil, err
	}
	return sp.WithRequestTracker(samlRequests).WithSLO(s.samlSloURL(r, orgHandle)), nil
}

// oidcRPForOrg builds the OIDC RP for an org's enabled connection. ctx should
// carry a custom HTTP client for a private/test IdP (coreoidc.ClientContext).
func (s *Server) oidcRPForOrg(ctx context.Context, r *http.Request, orgRow storegen.GetOrgByHandleRow) (*oidcrp.RP, uuid.UUID, error) {
	conn, err := s.q().GetEnabledSSOConnection(ctx, storegen.GetEnabledSSOConnectionParams{OrgID: orgRow.ID, Kind: "oidc"})
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("no enabled oidc connection")
	}
	var st storedOIDCConfig
	if err := json.Unmarshal(conn.Config, &st); err != nil {
		return nil, uuid.Nil, err
	}
	cfg := oidcrp.Config{Issuer: st.Issuer, ClientID: st.ClientID, Scopes: st.Scopes}
	if st.ClientSecretEnc != "" {
		sealed, err := base64.StdEncoding.DecodeString(st.ClientSecretEnc)
		if err != nil {
			return nil, uuid.Nil, err
		}
		secret, err := s.sealer.Open(sealed)
		if err != nil {
			return nil, uuid.Nil, err
		}
		cfg.ClientSecret = string(secret)
	}
	_, _, redirect := s.ssoURLs(r, orgRow.Handle)
	rp, err := oidcrp.New(ctx, cfg, redirect)
	return rp, conn.ID, err
}

// establishSSOSession is the shared JIT + session step for SAML and OIDC
// (§12.4). It links or creates the user, ensures org membership, opens an
// SSO-tagged session, and writes the LoginResult.
// samlSessionLink is what a SAML-established session remembers for Single
// Logout (§12.4, agentry#62): the asserted NameID and the IdP's
// SessionIndex, keyed by the connection.
type samlSessionLink struct {
	NameID       string
	SessionIndex string
}

func (s *Server) establishSSOSession(w http.ResponseWriter, r *http.Request, orgRow storegen.GetOrgByHandleRow, connID uuid.UUID, providerKind, subject, email string, samlLink *samlSessionLink) {
	ctx := r.Context()
	q := s.q()

	userID, err := s.resolveSSOUser(ctx, orgRow, connID, providerKind, subject, email)
	if err != nil {
		if errors.Is(err, errNotAMember) {
			// A plain notice, and the same one whether the person has no
			// account, has one that is not a member, or is a member
			// waiting for approval: the organization's SSO is not a place
			// to learn who is in it.
			writeProblem(w, r, http.StatusForbidden, "not-a-member",
				"Not a member of this organization",
				"This organization signs in its members only. Ask an administrator of "+orgRow.Handle+" to invite you; you will be able to sign in here once you have accepted.")
			return
		}
		s.log.ErrorContext(r.Context(), "sso sign-in", "err", err)
		problemInternal(w, r)
		return
	}

	sessToken, err := auth.NewToken(auth.SessionPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	csrfToken, err := auth.NewToken("csrf_")
	if err != nil {
		problemInternal(w, r)
		return
	}
	var ipPtr *netip.Addr
	if ip, perr := netip.ParseAddr(clientIP(r)); perr == nil {
		ipPtr = &ip
	}
	ua := r.UserAgent()
	sessID := newUUID()
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if samlLink != nil && samlLink.NameID != "" {
			var idx *string
			if samlLink.SessionIndex != "" {
				idx = &samlLink.SessionIndex
			}
			cid := connID
			if _, err := q.CreateSAMLSession(ctx, storegen.CreateSAMLSessionParams{
				ID: sessID, TokenSha256: auth.HashToken(sessToken), UserID: userID,
				CsrfToken: csrfToken, Ip: ipPtr, UserAgent: &ua,
				ExpiresAt:       time.Now().Add(s.cfg.Auth.SessionTTL),
				SsoConnectionID: &cid, SamlNameID: &samlLink.NameID, SamlSessionIndex: idx,
			}); err != nil {
				return err
			}
		} else if _, err := q.CreateSession(ctx, storegen.CreateSessionParams{
			ID: sessID, TokenSha256: auth.HashToken(sessToken), UserID: userID,
			CsrfToken: csrfToken, Ip: ipPtr, UserAgent: &ua,
			ExpiresAt: time.Now().Add(s.cfg.Auth.SessionTTL),
		}); err != nil {
			return err
		}
		// Tag the session SSO-fresh for this org (§12.4 enforced SSO).
		if err := q.TagSessionSSO(ctx, storegen.TagSessionSSOParams{
			ID: sessID, Column2: orgRow.ID.String(), Column3: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionSSOLogin)
		e.Actor, e.ActorKind = userID, audit.ActorUser
		e.OrgID = orgRow.ID
		e.TargetKind, e.TargetID = "user", userID
		e.Detail = map[string]any{"provider": providerKind}
		return s.auditW.Write(ctx, q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "sso session", "err", err)
		problemInternal(w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: sessToken, Path: "/", HttpOnly: true,
		Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(s.cfg.Auth.SessionTTL.Seconds()),
	})
	u, err := q.GetUserByID(ctx, userID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, LoginResult{
		CsrfToken: csrfToken,
		User: User{
			Id: u.ID, Handle: u.Handle, Email: u.Email, DisplayName: u.DisplayName,
			EmailVerified: u.EmailVerifiedAt != nil, TotpEnabled: u.TotpEnabled, CreatedAt: u.CreatedAt,
		},
	})
}

// errExplicitLinkRequired signals the T-12 guard: an existing account matches
// the email but the domain is not org-verified, so auto-link is refused.
var errExplicitLinkRequired = errors.New("explicit link confirmation required")

// (The org-SSO path no longer raises it: since agentry#361 an organization's
// SSO recognises members and admits nobody, so there is no account for it to
// link without confirmation. The social sign-in path still does.)

// errNotAMember reports that the person the IdP authenticated is not an
// active member of the organization.
var errNotAMember = errors.New("not an active member of this organization")

// resolveSSOUser answers who the IdP just authenticated, and refuses
// anyone the organization has not already admitted (agentry#361, D7, D11).
// It used to be a door: it linked accounts by verified domain and
// JIT-created an account and a membership for whoever the IdP asserted,
// which meant the IdP decided who belonged. Now the organization decides —
// an admin invites, or approves someone the IdP provisioned over SCIM —
// and this path only recognises them. Nothing is created here: no account,
// no identity for an unknown person, no membership.
//
// An active member signing in for the first time through a connection has
// their identity linked, which is recognition, not admission: they are
// already a member, and the link is what makes the next sign-in direct.
func (s *Server) resolveSSOUser(ctx context.Context, orgRow storegen.GetOrgByHandleRow, connID uuid.UUID, providerKind, subject, email string) (uuid.UUID, error) {
	q := s.q()
	// 1. Known identity for this connection: the usual case.
	if id, err := q.GetIdentityBySubject(ctx, storegen.GetIdentityBySubjectParams{
		SsoConnectionID: &connID, Subject: subject,
	}); err == nil {
		if !s.isActiveMember(ctx, orgRow.ID, id.UserID) {
			return uuid.Nil, errNotAMember
		}
		return id.UserID, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	// 2. No identity yet: only an account that is already an active member
	// may be recognised, and only when the IdP asserted the address it
	// holds — the address is what ties the assertion to the member.
	if email == "" {
		return uuid.Nil, errNotAMember
	}
	u, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, errNotAMember
		}
		return uuid.Nil, err
	}
	if !s.isActiveMember(ctx, orgRow.ID, u.ID) {
		return uuid.Nil, errNotAMember
	}
	if err := s.linkIdentity(ctx, u.ID, providerKind, connID, subject); err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

// isActiveMember reports whether the user is an active member of the org.
// A pending member — provisioned by SCIM, or folded in from the domain —
// is not: they are waiting for an admin, and signing them in would be the
// organization admitting them without deciding to.
func (s *Server) isActiveMember(ctx context.Context, orgID, userID uuid.UUID) bool {
	m, err := s.q().GetMembership(ctx, storegen.GetMembershipParams{OrgID: orgID, UserID: userID})
	return err == nil && m.State == "active"
}

func (s *Server) linkIdentity(ctx context.Context, userID uuid.UUID, providerKind string, connID uuid.UUID, subject string) error {
	_, err := s.q().CreateIdentity(ctx, storegen.CreateIdentityParams{
		ID: newUUID(), UserID: userID, ProviderKind: providerKind,
		SsoConnectionID: &connID, Subject: subject,
	})
	return err
}

var reHandleChars = regexp.MustCompile(`[^a-z0-9-]+`)

// allocateHandle derives a unique, grammar-valid handle for a JIT user.
func (s *Server) allocateHandle(ctx context.Context, email, subject string) (string, error) {
	seed := emailLocalPart(email)
	if seed == "" {
		seed = subject
	}
	base := sanitizeHandle(seed)
	if base == "" {
		base = "sso-user"
	}
	for i := 0; i < 6; i++ {
		cand := base
		if i > 0 {
			suffix, _ := auth.NewToken("")
			cand = truncateHandle(base, 30) + "-" + strings.ToLower(suffix)[:6]
		}
		if _, err := s.q().GetHandle(ctx, cand); errors.Is(err, pgx.ErrNoRows) {
			return cand, nil
		}
	}
	return "", errors.New("could not allocate a unique handle")
}

func sanitizeHandle(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = reHandleChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	s = truncateHandle(s, 39)
	if len(s) < 1 {
		return ""
	}
	return unreservedHandle(s) // root paths are not handles (DEV-091)
}

func truncateHandle(s string, n int) string {
	if len(s) > n {
		return strings.Trim(s[:n], "-")
	}
	return s
}

func emailLocalPart(email string) string {
	if i := strings.Index(email, "@"); i >= 0 {
		return email[:i]
	}
	return ""
}
