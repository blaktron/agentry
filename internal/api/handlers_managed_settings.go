package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/pkg/managedsettings"
)

// ManagedSettingsSource answers the signed managed settings that apply to
// a person: the envelope the key holder signed for their organization's
// current version, or nil when none apply (they are in no organization
// that sets any, or their organization's subscription does not include
// them). Membership is read at the call, so a former member gets nil at
// their next fetch.
type ManagedSettingsSource func(ctx context.Context, user uuid.UUID) (*managedsettings.Envelope, error)

// ManagedSettingsSigner signs an organization's managed settings. Only a
// process that holds the registry's signing key has one: the api role
// does not, so a document is signed by the worker when it is saved and
// the api serves what was stored.
type ManagedSettingsSigner interface {
	// Sign validates the settings against the catalogue, binds them to
	// this registry and the organization, and signs them.
	Sign(org string, version int64, settings map[string]managedsettings.Setting) (managedsettings.Envelope, error)
	// KeyID is the signing key's id: a stored envelope without a
	// signature by it was signed before a rotation and wants signing
	// again.
	KeyID() string
}

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

// ManagedSettingsSigner is this process's signer of managed settings, or
// nil when it holds no signing key or knows no base URL to bind them to.
func (s *Server) ManagedSettingsSigner() ManagedSettingsSigner {
	if s.signer == nil || s.registryURL() == "" {
		return nil
	}
	return managedSettingsSigner{s: s}
}

func (s *Server) registryURL() string { return strings.TrimRight(s.cfg.BaseURL, "/") }

type managedSettingsSigner struct{ s *Server }

func (m managedSettingsSigner) Sign(org string, version int64, settings map[string]managedsettings.Setting) (managedsettings.Envelope, error) {
	payload, err := managedsettings.Seal(managedsettings.Document{
		Schema:   managedsettings.Schema,
		Registry: m.s.registryURL(),
		Org:      org,
		Version:  version,
		IssuedAt: time.Now().UTC().Truncate(time.Second),
		Settings: settings,
	})
	if err != nil {
		return managedsettings.Envelope{}, err
	}
	sig, err := m.s.signer.SignPayload(managedsettings.PayloadType, payload)
	if err != nil {
		return managedsettings.Envelope{}, err
	}
	return managedsettings.Wrap(payload, sig), nil
}

func (m managedSettingsSigner) KeyID() string { return m.s.signer.KeyID() }

// GetUserManagedSettings implements GET /user/managed-settings: the
// caller's managed settings as the signed envelope, or 204 when none
// apply. The api serves what the key holder signed, and only after it has
// checked the envelope against the keys this registry advertises and the
// registry it names, so it never serves a document a client would refuse.
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
	env, err := s.managedSettings.src(ctx, p.UserID)
	if err != nil {
		s.log.ErrorContext(ctx, "managed settings: source", "user", p.UserID, "err", err)
		problemInternal(w, r)
		return
	}
	if env == nil {
		noManagedSettings(w)
		return
	}
	if s.registryURL() == "" {
		// The document names the registry a client must have it from; a
		// registry that does not know its own address cannot check it.
		writeProblem(w, r, http.StatusServiceUnavailable, "managed-settings-unbound",
			"Managed settings unavailable",
			"This registry has no base URL configured, so it cannot serve managed settings.")
		return
	}
	if err := s.checkManagedSettings(ctx, *env); err != nil {
		s.log.ErrorContext(ctx, "managed settings: stored envelope refused", "user", p.UserID, "from", s.managedSettings.from, "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "managed-settings-unverified",
			"Managed settings unavailable",
			"The registry could not verify the managed settings it holds for you. Try again later.")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

// checkManagedSettings opens a stored envelope with the keys this registry
// advertises and checks that it names this registry.
func (s *Server) checkManagedSettings(ctx context.Context, env managedsettings.Envelope) error {
	lastErr := errors.New("no signing key is advertised")
	for _, k := range s.signingKeySet(ctx) {
		doc, err := managedsettings.Open(env, k.PublicKey)
		if err != nil {
			lastErr = err
			continue
		}
		if doc.Registry != s.registryURL() {
			return errors.New("the document names another registry: " + doc.Registry)
		}
		return nil
	}
	return lastErr
}

// noManagedSettings answers that no managed settings apply to the caller.
func noManagedSettings(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
