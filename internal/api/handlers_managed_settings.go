package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/pkg/managedsettings"
)

// ManagedSettingsContent is what an extension answers for one member: the
// organization whose settings they are, its version and the settings. The
// core adds what binds the document to this registry and this account.
type ManagedSettingsContent struct {
	Org      string
	Version  int64
	Settings map[string]managedsettings.Setting
}

// ManagedSettingsSource answers a person's managed settings, or nil when
// none apply to them (they are in no organization that sets any, or their
// organization's subscription does not include them). Membership is read
// at the call, so a former member gets nil at their next fetch.
type ManagedSettingsSource func(ctx context.Context, user uuid.UUID) (*ManagedSettingsContent, error)

type managedSettingsState struct {
	from string
	src  ManagedSettingsSource
}

// SetManagedSettings installs the extension that answers managed settings.
// A deployment has one: a second panics at start-up, so two extensions
// can never both decide what a member is held to.
func (s *Server) SetManagedSettings(name string, src ManagedSettingsSource) {
	if src == nil {
		return
	}
	if s.managedSettings.src != nil {
		panic("api: " + name + " and " + s.managedSettings.from + " both answer managed settings; a deployment has one")
	}
	s.managedSettings = managedSettingsState{from: name, src: src}
}

// GetUserManagedSettings implements GET /user/managed-settings: the
// caller's managed settings as a signed envelope, or 204 when none apply.
func (s *Server) GetUserManagedSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActUserSelfRead, uuid.Nil) {
		return
	}
	if s.managedSettings.src == nil {
		noManagedSettings(w)
		return
	}
	ctx := r.Context()
	p := principalFrom(ctx)
	content, err := s.managedSettings.src(ctx, p.UserID)
	if err != nil {
		s.log.ErrorContext(ctx, "managed settings: source", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	if content == nil {
		noManagedSettings(w)
		return
	}
	if s.signer == nil {
		// Never serve a document a client cannot verify: an unsigned one
		// could not be told apart from one an attacker wrote.
		writeProblem(w, r, http.StatusServiceUnavailable, "managed-settings-unsigned",
			"Managed settings unavailable",
			"This registry has no signing key, so it cannot serve managed settings a client could verify.")
		return
	}
	registry := strings.TrimRight(s.cfg.BaseURL, "/")
	if registry == "" {
		// The document names the registry a client must have it from; a
		// registry that does not know its own address cannot bind it.
		writeProblem(w, r, http.StatusServiceUnavailable, "managed-settings-unbound",
			"Managed settings unavailable",
			"This registry has no base URL configured, so it cannot bind managed settings to itself.")
		return
	}
	doc := managedsettings.Document{
		Schema:   managedsettings.Schema,
		Registry: registry,
		Account:  p.UserID.String(),
		Org:      content.Org,
		Version:  content.Version,
		IssuedAt: time.Now().UTC().Truncate(time.Second),
		Settings: content.Settings,
	}
	payload, err := managedsettings.Seal(doc)
	if err != nil {
		s.log.ErrorContext(ctx, "managed settings: invalid content", "user", p.UserID, "org", content.Org, "from", s.managedSettings.from, "err", err)
		problemInternal(w, r)
		return
	}
	sig, err := s.signer.SignPayload(managedsettings.PayloadType, payload)
	if err != nil {
		s.log.ErrorContext(ctx, "managed settings: sign", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, managedsettings.Wrap(payload, sig))
}

// noManagedSettings answers that no managed settings apply to the caller.
func noManagedSettings(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
