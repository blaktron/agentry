package api

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
)

// issuerOriginRe lifts the directory's origin out of the authentik issuer
// (https://auth.example/application/o/<slug>/ → https://auth.example).
var issuerOriginRe = regexp.MustCompile(`^(https?://[^/]+)/application/o/[^/]+/?$`)

// userDirectoryDevice mirrors the generated anonymous item type.
type userDirectoryDevice = struct {
	CreatedAt *time.Time `json:"createdAt,omitempty"`
	Id        *string    `json:"id,omitempty"`
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
}

// GetUserDirectory implements GET /user/directory (agentry#113): where the
// caller changes password, enrols MFA or edits profile when the directory
// service owns the account, plus the authenticators it has enrolled.
func (s *Server) GetUserDirectory(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	issuer := strings.TrimSpace(s.cfg.Social.Authentik.Issuer)
	out := UserDirectory{Managed: s.cfg.Auth.ExternalOnly && issuer != ""}
	if !out.Managed {
		writeJSON(w, http.StatusOK, out)
		return
	}
	origin := strings.TrimRight(issuer, "/")
	if m := issuerOriginRe.FindStringSubmatch(issuer); m != nil {
		origin = m[1]
	}
	str := func(v string) *string { return &v }
	// authentik's default flow slugs (2026.x); the user interface path is
	// stable across releases.
	// The Agentry flows (compose blueprint agentry-account-flows.yaml,
	// agentry#164): each ends with a redirect back to the account settings
	// (the site's, or the server's own /ui/ page — DEV-091), and no
	// link ever points at the directory's own panel.
	out.PasswordChangeUrl = str(origin + "/if/flow/agentry-password-change/")
	out.TotpSetupUrl = str(origin + "/if/flow/agentry-totp-setup/")
	out.WebauthnSetupUrl = str(origin + "/if/flow/agentry-webauthn-setup/")

	if lister, ok := s.dirEraser.(directoryDevices); ok {
		p := principalFrom(r.Context())
		row, err := s.q().GetUserByID(r.Context(), p.UserID)
		if err != nil {
			problemInternal(w, r)
			return
		}
		devs, err := lister.DevicesByEmail(r.Context(), row.Email)
		if err != nil {
			s.log.WarnContext(r.Context(), "user directory: devices", "err", err)
			out.DevicesError = str("The directory did not answer, so the authenticator list is missing. The links still work.")
		} else {
			list := make([]userDirectoryDevice, 0, len(devs))
			for _, d := range devs {
				item := userDirectoryDevice{CreatedAt: d.CreatedAt, Kind: d.Kind, Name: d.Name}
				if d.ID != "" {
					item.Id = str(d.ID)
				}
				list = append(list, item)
			}
			out.Devices = &list
		}
		s.addSignInFacts(r, row.Email, &out)
	}
	writeJSON(w, http.StatusOK, out)
}

// addSignInFacts adds the directory's first social connection and password
// answer (agentry#706) for the account the caller's directory sign-in is
// linked to. Anything the directory does not answer is left out: the page
// shows nothing rather than a guess.
func (s *Server) addSignInFacts(r *http.Request, email string, out *UserDirectory) {
	facts, ok := s.dirEraser.(directorySignIns)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	uid, err := s.q().GetUserDirectorySubject(r.Context(), p.UserID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.WarnContext(r.Context(), "user directory: linked subject", "err", err)
		}
		return
	}
	f, err := facts.SignInFacts(r.Context(), email, uid)
	if err != nil {
		s.log.WarnContext(r.Context(), "user directory: sign-in facts", "err", err)
		return
	}
	if f.FirstSource != nil {
		out.FirstSocialProvider = &struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		}{Id: f.FirstSource.Slug, Name: f.FirstSource.Name}
	}
	out.HasPassword = f.HasPassword
}

// DeleteUserDirectoryDevice implements DELETE /user/directory/devices/{kind}/{deviceId}
// (agentry#164): the caller removes one of their own authenticators from the
// directory without ever seeing the directory's settings panel. The
// directory admin access does the work; ownership is checked against the
// account's own device list, so an id that is not the caller's answers 404
// exactly like a missing one.
func (s *Server) DeleteUserDirectoryDevice(w http.ResponseWriter, r *http.Request, kindParam DeleteUserDirectoryDeviceParamsKind, deviceId string) {
	kind := string(kindParam)
	if !s.authorize(w, r, auth.ActUserSelfUpdate, uuid.Nil) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	lister, ok := s.dirEraser.(directoryDevices)
	if !ok || !s.cfg.Auth.ExternalOnly {
		writeProblem(w, r, http.StatusNotFound, "not-found", "Not found", "This server has no directory admin access, so it cannot remove authenticators.")
		return
	}
	p := principalFrom(r.Context())
	row, err := s.q().GetUserByID(r.Context(), p.UserID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	deleted, err := lister.DeleteDevice(r.Context(), row.Email, kind, deviceId)
	if err != nil {
		s.log.WarnContext(r.Context(), "user directory: delete device", "err", err)
		writeProblem(w, r, http.StatusBadGateway, "directory-unavailable", "Directory unavailable", "The directory did not answer. Try again.")
		return
	}
	if !deleted {
		writeProblem(w, r, http.StatusNotFound, "not-found", "Not found", "This account has no such authenticator.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
