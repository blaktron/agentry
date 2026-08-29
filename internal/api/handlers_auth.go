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

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
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

// Register implements POST /auth/register (§12.1).
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
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
		fields = append(fields, FieldError{Field: "handle", Message: "must match ^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$"})
	}
	email := strings.TrimSpace(string(req.Email))
	if !strings.Contains(email, "@") || len(email) > 254 {
		fields = append(fields, FieldError{Field: "email", Message: "invalid email"})
	}
	if len(req.Password) < 10 || len(req.Password) > 256 {
		fields = append(fields, FieldError{Field: "password", Message: "must be 10-256 characters"})
	}
	if len(fields) > 0 {
		problemValidation(w, r, "registration rejected", fields...)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.log.Error("register: hash", "err", err)
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
			problemConflict(w, r, "handle or email already in use")
			return
		}
		s.log.Error("register", "err", err)
		problemInternal(w, r)
		return
	}

	if err := s.notifier.EmailVerification(r.Context(), email, verifyToken); err != nil {
		s.log.Warn("register: verification email", "err", err)
	}

	writeJSON(w, http.StatusCreated, User{
		Id: created.ID, Handle: req.Handle, Email: created.Email,
		DisplayName: created.DisplayName, EmailVerified: false,
		TotpEnabled: false, CreatedAt: created.CreatedAt,
	})
}

// VerifyEmail implements POST /auth/verify-email.
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
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		userID, err := q.ConsumeEmailVerification(r.Context(), auth.HashToken(req.Token))
		if err != nil {
			return err
		}
		if err := q.MarkEmailVerified(r.Context(), userID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserEmailVerified)
		e.Actor, e.ActorKind = userID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", userID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			problemValidation(w, r, "invalid or expired verification token")
			return
		}
		s.log.Error("verify-email", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Login implements POST /auth/login: password + optional TOTP → session.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
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
		e := auditEvent(r, audit.ActionUserLoginFailed)
		e.Detail = map[string]any{"login": req.Login}
		if userID != uuid.Nil {
			e.Actor, e.ActorKind = userID, audit.ActorUser
		}
		if err := s.auditW.Write(ctx, q, e); err != nil {
			s.log.Warn("audit login_failed", "err", err)
		}
		problemUnauthorized(w, r, "invalid credentials")
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
		deny(uuid.Nil)
		return
	}
	if !auth.VerifyPassword(req.Password, *row.PasswordHash) {
		deny(row.ID)
		return
	}

	if row.TotpEnabled {
		if req.TotpCode == nil || *req.TotpCode == "" {
			writeProblem(w, r, http.StatusUnauthorized, "totp-required", "TOTP code required", "supply totpCode")
			return
		}
		secret, err := s.sealer.Open(row.TotpSecretEnc)
		if err != nil {
			s.log.Error("login: unseal totp", "err", err)
			problemInternal(w, r)
			return
		}
		if !auth.ValidateTOTP(*req.TotpCode, string(secret)) {
			deny(row.ID)
			return
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

	var ipPtr *netip.Addr
	if ip, err := netip.ParseAddr(clientIP(r)); err == nil {
		ipPtr = &ip
	}
	ua := r.UserAgent()
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
		e := auditEvent(r, audit.ActionUserLogin)
		e.Actor, e.ActorKind = row.ID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", row.ID
		return s.auditW.Write(ctx, q, e)
	})
	if err != nil {
		s.log.Error("login: session", "err", err)
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
		problemForbidden(w, r, "logout requires a session")
		return
	}
	err := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		if _, err := q.RevokeSession(r.Context(), p.SessionID); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserLogout)
		e.TargetKind, e.TargetID = "user", p.UserID
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.Error("logout", "err", err)
		problemInternal(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// TotpSetup implements POST /auth/2fa/totp/setup (session-only).
func (s *Server) TotpSetup(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSecurityManage, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	p := principalFrom(r.Context())
	secret, url, err := auth.GenerateTOTP(p.Handle)
	if err != nil {
		s.log.Error("totp setup", "err", err)
		problemInternal(w, r)
		return
	}
	sealed, err := s.sealer.Seal([]byte(secret))
	if err != nil {
		s.log.Error("totp seal", "err", err)
		problemInternal(w, r)
		return
	}
	if err := s.q().SetUserTOTPSecret(r.Context(), storegen.SetUserTOTPSecretParams{ID: p.UserID, TotpSecretEnc: sealed}); err != nil {
		s.log.Error("totp store", "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, TotpSetupResult{Secret: secret, OtpauthUrl: url})
}

// TotpVerify implements POST /auth/2fa/totp/verify (session-only).
func (s *Server) TotpVerify(w http.ResponseWriter, r *http.Request) {
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
		problemValidation(w, r, "no TOTP enrollment in progress")
		return
	}
	secret, err := s.sealer.Open(row.TotpSecretEnc)
	if err != nil {
		s.log.Error("totp verify unseal", "err", err)
		problemInternal(w, r)
		return
	}
	if !auth.ValidateTOTP(req.Code, string(secret)) {
		problemValidation(w, r, "invalid code")
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
		s.log.Error("totp enable", "err", err)
		problemInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
