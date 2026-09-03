package api

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
)

// issuerOriginRe lifts the directory's origin out of the authentik issuer
// (https://auth.example/application/o/<slug>/ → https://auth.example).
var issuerOriginRe = regexp.MustCompile(`^(https?://[^/]+)/application/o/[^/]+/?$`)

// userDirectoryDevice mirrors the generated anonymous item type.
type userDirectoryDevice = struct {
	CreatedAt *time.Time `json:"createdAt,omitempty"`
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
	out.AccountUrl = str(origin + "/if/user/#/settings")
	out.PasswordChangeUrl = str(origin + "/if/flow/default-password-change/")
	out.TotpSetupUrl = str(origin + "/if/flow/default-authenticator-totp-setup/")
	out.WebauthnSetupUrl = str(origin + "/if/flow/default-authenticator-webauthn-setup/")

	if lister, ok := s.dirEraser.(directoryDevices); ok {
		p := principalFrom(r.Context())
		row, err := s.q().GetUserByID(r.Context(), p.UserID)
		if err != nil {
			problemInternal(w, r)
			return
		}
		devs, err := lister.DevicesByEmail(r.Context(), row.Email)
		if err != nil {
			s.log.Warn("user directory: devices", "err", err)
			out.DevicesError = str("the directory did not answer; the links above still work")
		} else {
			list := make([]userDirectoryDevice, 0, len(devs))
			for _, d := range devs {
				list = append(list, userDirectoryDevice{CreatedAt: d.CreatedAt, Kind: d.Kind, Name: d.Name})
			}
			out.Devices = &list
		}
	}
	writeJSON(w, http.StatusOK, out)
}
