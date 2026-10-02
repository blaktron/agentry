package api

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Handle/name grammar shared with the DDL (§4.2).
var reHandle = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$`)

const emailVerificationTTL = 48 * time.Hour

// newUUID returns a UUIDv7 (D-10); generation failure is unrecoverable.
func newUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id
}

// isUniqueViolation reports a Postgres 23505 error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// uniqueViolationOn reports whether err is a unique violation of the named
// constraint or index, for a handler whose insert can collide on more than
// one.
func uniqueViolationOn(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// auditEvent builds the base event for this request's principal.
func auditEvent(r *http.Request, action audit.Action) audit.Event {
	p := principalFrom(r.Context())
	e := audit.Event{Action: action, ActorKind: audit.ActorSystem, UserAgent: r.UserAgent()}
	if !p.Anonymous {
		e.Actor = p.UserID
		if p.Via == "pat" {
			e.ActorKind = audit.ActorPAT
		} else {
			e.ActorKind = audit.ActorUser
		}
	}
	if ip, err := netip.ParseAddr(clientIP(r)); err == nil {
		e.IP = ip
	}
	return e
}

// requestFacts are the two things a credential row records about the request
// that presented it: the address it came from and the user agent it claimed.
// Both are display facts for the pages that list credentials — a session, a
// trusted device — and neither takes part in any decision, so a value the
// client can choose never influences what the server trusts. agentry#429 is
// about that address being choosable; keeping it out of every decision is what
// makes it harmless here. Both are best-effort: an address that does not parse
// is left nil rather than refused.
func requestFacts(r *http.Request) (ip *netip.Addr, ua string) {
	if a, err := netip.ParseAddr(clientIP(r)); err == nil {
		ip = &a
	}
	return ip, r.UserAgent()
}

// Register implements POST /auth/register (§12.1).
// nativeCredsGone enforces auth.externalOnly (DEV-057): with an external
// directory service owning credentials, the native register / password /
// email-verify / TOTP endpoints answer 410 Gone. The handlers below stay
// intact — clearing the flag restores them — and social/SSO sign-in plus
// sessions, PATs, and RBAC are untouched.
func (s *Server) nativeCredsGone(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.Auth.ExternalOnly {
		return false
	}
	problemGone(w, r, "This deployment's directory service manages credentials. Sign in at "+s.paths.login("")+".")
	return true
}

func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	if s.nativeCredsGone(w, r) {
		return
	}
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req RegisterRequest
	if !readJSON(w, r, &req) {
		return
	}

	var fields []FieldError
	if !reHandle.MatchString(req.Handle) {
		fields = append(fields, FieldError{Field: "handle", Message: "Must be 1-39 lowercase letters, digits and hyphens, starting and ending with a letter or digit."})
	} else if handleReserved(req.Handle) {
		fields = append(fields, FieldError{Field: "handle", Message: "This handle is reserved."})
	}
	email := strings.TrimSpace(string(req.Email))
	if !strings.Contains(email, "@") || len(email) > 254 {
		fields = append(fields, FieldError{Field: "email", Message: "Must contain @ and be 254 characters or fewer."})
	}
	if len(req.Password) < 10 || len(req.Password) > 256 {
		fields = append(fields, FieldError{Field: "password", Message: "Must be 10-256 characters."})
	}
	if len(fields) > 0 {
		problemValidation(w, r, "The registry rejected the registration. Each field error says what to fix.", fields...)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.log.ErrorContext(r.Context(), "register: hash", "err", err)
		problemInternal(w, r)
		return
	}

	displayName := req.Handle
	if req.DisplayName != nil && strings.TrimSpace(*req.DisplayName) != "" {
		displayName = strings.TrimSpace(*req.DisplayName)
	}

	userID := newUUID()
	verifyToken, err := auth.NewToken(auth.VerificationPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}

	var created storegen.User
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.CreateHandle(r.Context(), storegen.CreateHandleParams{ID: userID, Handle: req.Handle, Kind: "user"}); err != nil {
			return err
		}
		u, err := q.CreateUser(r.Context(), storegen.CreateUserParams{
			ID: userID, Email: email, DisplayName: displayName, PasswordHash: &hash,
		})
		if err != nil {
			return err
		}
		created = u
		if err := q.CreateEmailVerification(r.Context(), storegen.CreateEmailVerificationParams{
			TokenSha256: auth.HashToken(verifyToken),
			UserID:      userID,
			ExpiresAt:   time.Now().Add(emailVerificationTTL),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserRegister)
		e.Actor, e.ActorKind = userID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", userID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if isUniqueViolation(err) {
			problemConflict(w, r, "That handle or email address is already in use. Choose another.")
			return
		}
		s.log.ErrorContext(r.Context(), "register", "err", err)
		problemInternal(w, r)
		return
	}

	if err := s.notifier.EmailVerification(r.Context(), email, req.Handle, verifyToken); err != nil {
		s.log.WarnContext(r.Context(), "register: verification email", "err", err)
	}

	s.fireEvent(r.Context(), Event{Kind: "user.registered", UserID: created.ID, Payload: map[string]any{
		"handle": req.Handle, "email": email, "emailVerified": false, "via": "native",
	}})
	writeJSON(w, http.StatusCreated, User{
		Id: created.ID, Handle: req.Handle, Email: created.Email,
		DisplayName: created.DisplayName, EmailVerified: false,
		TotpEnabled: false, CreatedAt: created.CreatedAt,
	})
}

// VerifyEmail implements POST /auth/verify-email. It is the activation
// link's target for every account (agentry#861), so unlike the rest of the
// native credential endpoints it stays open under externalOnly: a directory
// account follows the link the registry mailed it. Where the account signed
// in through the directory, the confirmation is written there too, before
// the registry's transaction commits: a directory that cannot be reached
// rolls the registry back and leaves the link unused, to be followed again,
// rather than an account confirmed here and still unconfirmed in the token
// the directory issues. (The other way round, a commit that fails after the
// directory write, leaves the link unused too, and following it again
// finishes the registry's half; the directory write is idempotent.)
func (s *Server) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var verified uuid.UUID
	var dirErr error
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		userID, err := q.ConsumeEmailVerification(r.Context(), auth.HashToken(req.Token))
		if err != nil {
			return err
		}
		u, err := q.GetUserByID(r.Context(), userID)
		if err != nil {
			return err
		}
		if u.State != "active" {
			// An erased or deactivated account's link activates nothing.
			return pgx.ErrNoRows
		}
		if err := q.MarkEmailVerified(r.Context(), userID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserEmailVerified)
		e.Actor, e.ActorKind = userID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", userID
		if err := s.auditW.Write(r.Context(), q, e); err != nil {
			return err
		}
		if u.EmailVerifiedAt == nil {
			if err := s.confirmInDirectory(r.Context(), userID, u.Email); err != nil {
				dirErr = err
				return err
			}
			verified = userID
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemValidation(w, r, "This verification link is invalid or expired.")
			return
		}
		if dirErr != nil {
			s.log.ErrorContext(r.Context(), "verify-email: directory", "err", dirErr)
			problemUnavailable(w, r, "The account could not be activated just now. Follow the link again in a minute; it still works.")
			return
		}
		s.log.ErrorContext(r.Context(), "verify-email", "err", err)
		problemInternal(w, r)
		return
	}
	// Extensions hear the address confirmed (agentry#861): a sign-up's
	// allowance and promo code wait for it (plan unactivated-accounts.md D9).
	if verified != uuid.Nil {
		s.fireEvent(r.Context(), Event{Kind: "user.email_verified", UserID: verified})
	}
	w.WriteHeader(http.StatusNoContent)
}

// Login implements POST /auth/login: password + optional TOTP → session.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	if s.nativeCredsGone(w, r) {
		return
	}
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req LoginRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	q := s.q()

	deny := func(userID uuid.UUID) {
		// Named for the log contract; the address and agent are on the
		// access line under the same request id. The login as typed is on
		// the audit row, not here (docs/logging.md: no addresses of people
		// in a line the contract adds).
		s.log.InfoContext(ctx, "login failed", logevent.AuthLoginFailed.Attr(), "user", userID)
		e := auditEvent(r, audit.ActionUserLoginFailed)
		e.Detail = map[string]any{"login": req.Login}
		if userID != uuid.Nil {
			e.Actor, e.ActorKind = userID, audit.ActorUser
		}
		if err := s.auditW.Write(ctx, q, e); err != nil {
			s.log.WarnContext(r.Context(), "audit login_failed", "err", err)
		}
		problemUnauthorized(w, r, "These credentials do not match an active account.")
	}

	var (
		row storegen.GetUserByEmailRow
		err error
	)
	if strings.Contains(req.Login, "@") {
		row, err = q.GetUserByEmail(ctx, strings.TrimSpace(req.Login))
	} else {
		var hrow storegen.GetUserByHandleRow
		hrow, err = q.GetUserByHandle(ctx, req.Login)
		row = storegen.GetUserByEmailRow(hrow)
	}
	if err != nil || row.State != "active" || row.PasswordHash == nil {
		// The miss pays the same comparison as a wrong password, so the
		// refusal's timing does not say whether the account exists, is
		// active, or signs in another way (agentry#413).
		auth.SpendPasswordCheck(req.Password)
		deny(uuid.Nil)
		return
	}
	if !auth.VerifyPassword(req.Password, *row.PasswordHash) {
		deny(row.ID)
		return
	}

	// A trusted device skips the second factor; answering the factor earns
	// one. The two are kept apart here because the difference is the whole
	// security model: a skip never mints, which is what makes the credential's
	// lifetime absolute rather than sliding (plan trusted-devices.md D9). The
	// password above has already been verified, so the cookie is never itself
	// an authentication — it only stands in for the code.
	var totpAnswered, totpSkipped bool
	if row.TotpEnabled {
		switch {
		case s.trustedDeviceSkip(ctx, r, row.ID):
			totpSkipped = true
		case req.TotpCode == nil || *req.TotpCode == "":
			writeProblem(w, r, http.StatusUnauthorized, "totp-required", "TOTP code required", "Send totpCode with the current code from the authenticator app.")
			return
		default:
			secret, err := s.sealer.Open(row.TotpSecretEnc)
			if err != nil {
				s.log.ErrorContext(r.Context(), "login: unseal totp", "err", err)
				problemInternal(w, r)
				return
			}
			if !auth.ValidateTOTP(*req.TotpCode, string(secret)) {
				deny(row.ID)
				return
			}
			totpAnswered = true
		}
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

	ipPtr, ua := requestFacts(r)
	var deviceToken string
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		_, err := q.CreateSession(ctx, storegen.CreateSessionParams{
			ID:          newUUID(),
			TokenSha256: auth.HashToken(sessToken),
			UserID:      row.ID,
			CsrfToken:   csrfToken,
			Ip:          ipPtr,
			UserAgent:   &ua,
			ExpiresAt:   time.Now().Add(s.cfg.Auth.SessionTTL),
		})
		if err != nil {
			return err
		}
		// Platform staff is recomputed at every sign-in (agentry#556).
		staffActor := auditEvent(r, audit.ActionUserStaffSync)
		staffActor.Actor, staffActor.ActorKind = row.ID, audit.ActorUser
		if err := s.syncStaffIn(ctx, q, row.ID, registry.StaffSyncSignIn, staffActor); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserLogin)
		e.Actor, e.ActorKind = row.ID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", row.ID
		if totpSkipped {
			// The sign-in row names that the second factor was not asked for
			// and what stood in for it, so "signed in" and "signed in without
			// the code" stay distinguishable in the audit trail.
			e.Detail = map[string]any{"totp": "skipped_trusted_device"}
		}
		if err := s.auditW.Write(ctx, q, e); err != nil {
			return err
		}
		// Trust is earned only by answering the factor, and only when asked
		// for; the opt-in defaults to false. Both are inside this transaction
		// so a sign-in that earns trust records the session, the device and
		// the audit rows together, or none of them.
		if totpAnswered && req.RememberDevice != nil && *req.RememberDevice {
			tok, err := s.createTrustedDevice(ctx, q, r, row.ID, nil)
			if err != nil {
				return err
			}
			deviceToken = tok
		}
		return nil
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "login: session", "err", err)
		problemInternal(w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.Auth.SessionTTL.Seconds()),
	})
	if deviceToken != "" {
		setTrustedDeviceCookie(w, deviceToken, s.cfg.Auth.TrustedDeviceTTL, s.cfg.Auth.CookieSecure)
	}
	writeJSON(w, http.StatusOK, LoginResult{
		CsrfToken: csrfToken,
		User: User{
			Id: row.ID, Handle: row.Handle, Email: row.Email,
			DisplayName: row.DisplayName, EmailVerified: row.EmailVerifiedAt != nil,
			TotpEnabled: row.TotpEnabled, CreatedAt: row.CreatedAt,
		},
	})
}

// Logout implements POST /auth/logout (session-only).
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	if p.Via != "session" {
		problemForbidden(w, r, "Signing out requires a session, not a token.")
		return
	}
	// SP-initiated SAML Single Logout (§12.4, agentry#62): resolved before
	// the revoke, which is what makes the session unreadable.
	idpLogout := s.samlLogoutURLForSession(r, p.SessionID)
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.RevokeSession(r.Context(), p.SessionID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserLogout)
		e.TargetKind, e.TargetID = "user", p.UserID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "logout", "err", err)
		problemInternal(w, r)
		return
	}
	clearCookie(w, sessionCookieName, s.cfg.Auth.CookieSecure)
	if idpLogout != "" {
		writeJSON(w, http.StatusOK, LogoutResult{IdpLogoutUrl: idpLogout})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TotpSetup implements POST /auth/2fa/totp/setup (session-only).
func (s *Server) TotpSetup(w http.ResponseWriter, r *http.Request) {
	if s.nativeCredsGone(w, r) {
		return
	}
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	secret, url, err := auth.GenerateTOTP(s.cfg.DisplayName(), p.Handle)
	if err != nil {
		s.log.ErrorContext(r.Context(), "totp setup", "err", err)
		problemInternal(w, r)
		return
	}
	sealed, err := s.sealer.Seal([]byte(secret))
	if err != nil {
		s.log.ErrorContext(r.Context(), "totp seal", "err", err)
		problemInternal(w, r)
		return
	}
	if err := s.q().SetUserTOTPSecret(r.Context(), storegen.SetUserTOTPSecretParams{ID: p.UserID, TotpSecretEnc: sealed}); err != nil {
		s.log.ErrorContext(r.Context(), "totp store", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, TotpSetupResult{Secret: secret, OtpauthUrl: url})
}

// TotpVerify implements POST /auth/2fa/totp/verify (session-only).
func (s *Server) TotpVerify(w http.ResponseWriter, r *http.Request) {
	if s.nativeCredsGone(w, r) {
		return
	}
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil || len(row.TotpSecretEnc) == 0 {
		problemValidation(w, r, "No TOTP enrollment is in progress. Run the setup step first.")
		return
	}
	secret, err := s.sealer.Open(row.TotpSecretEnc)
	if err != nil {
		s.log.ErrorContext(r.Context(), "totp verify unseal", "err", err)
		problemInternal(w, r)
		return
	}
	if !auth.ValidateTOTP(req.Code, string(secret)) {
		problemValidation(w, r, "That code did not match. Try the current code from the authenticator app.")
		return
	}
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if err := q.EnableUserTOTP(r.Context(), p.UserID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserTOTPEnabled)
		e.TargetKind, e.TargetID = "user", p.UserID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "totp enable", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
