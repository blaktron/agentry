package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// directoryEraser deletes a person's sign-in account in the external
// directory service as part of account erasure (§12.7, agentry#20). With
// credentials held by the directory (DEV-057), the registry's own
// pseudonymization leaves the email, display name and password hash alive
// there — and the person able to sign in again and JIT-create a fresh
// account. Erasure is only erasure if both halves happen.
type directoryEraser interface {
	// EraseByEmail deletes the directory account with exactly this email.
	// Returns (false, nil) when no such account exists.
	EraseByEmail(ctx context.Context, email string) (bool, error)
}

// authentikEraser speaks authentik's core users API with a bearer token.
type authentikEraser struct {
	base  string
	token string
	http  *http.Client
}

func newAuthentikEraser(base, token string) *authentikEraser {
	return &authentikEraser{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Timeout: 15 * time.Second}}
}

func (a *authentikEraser) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	res, err := a.http.Do(req)
	// A transport error names the URL, and the lookup's URL carries the
	// person's address in its query. The error goes to the audit log and the
	// server's log for an erasure (agentry#499), so it keeps the method and
	// the cause and drops the URL.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = fmt.Errorf("%s %s: %w", method, strings.SplitN(path, "?", 2)[0], ue.Err)
	}
	return res, err
}

func (a *authentikEraser) EraseByEmail(ctx context.Context, email string) (bool, error) {
	res, err := a.do(ctx, http.MethodGet, "/api/v3/core/users/?page_size=10&email="+url.QueryEscape(email))
	if err != nil {
		return false, fmt.Errorf("directory lookup: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("directory lookup: %d", res.StatusCode)
	}
	var page struct {
		Results []struct {
			PK          int    `json:"pk"`
			Email       string `json:"email"`
			Type        string `json:"type"`
			IsSuperuser bool   `json:"is_superuser"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return false, fmt.Errorf("directory lookup: %w", err)
	}
	deleted := false
	for _, u := range page.Results {
		// Delete only exact, case-insensitive matches, and never a service
		// account or a superuser — an operator's own account must not be
		// erasable by a registry user who happens to share its address.
		// authentik 2026.8's email= filter is itself exact and
		// case-sensitive, so an address held with other capitals is not
		// found at all (agentry#617; the staff mirror uses search=).
		if !strings.EqualFold(u.Email, email) || u.IsSuperuser || strings.Contains(u.Type, "service") {
			continue
		}
		res, err := a.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v3/core/users/%d/", u.PK))
		if err != nil {
			return deleted, fmt.Errorf("directory delete: %w", err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			return deleted, fmt.Errorf("directory delete: %d", res.StatusCode)
		}
		deleted = true
	}
	return deleted, nil
}

// directoryDevices is the read side of the same admin access: the
// authenticators a user has enrolled, for the settings page (agentry#113).
type directoryDevices interface {
	DevicesByEmail(ctx context.Context, email string) ([]DirectoryDevice, error)
	// DeleteDevice removes one of the account's authenticators; false when
	// the account has no device of that kind and id (never somebody else's).
	DeleteDevice(ctx context.Context, email, kind, id string) (bool, error)
}

// DirectoryDevice is one enrolled authenticator as the directory reports it.
type DirectoryDevice struct {
	ID        string
	Kind      string
	Name      string
	CreatedAt *time.Time
}

// DevicesByEmail lists the authenticators of the directory account with
// this email (authentik: /authenticators/admin/all/?user=<pk>). No account
// or no devices is an empty list, not an error.
func (a *authentikEraser) DevicesByEmail(ctx context.Context, email string) ([]DirectoryDevice, error) {
	res, err := a.do(ctx, http.MethodGet, "/api/v3/core/users/?page_size=10&email="+url.QueryEscape(email))
	if err != nil {
		return nil, fmt.Errorf("directory lookup: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory lookup: %d", res.StatusCode)
	}
	var page struct {
		Results []struct {
			PK    int    `json:"pk"`
			Email string `json:"email"`
			Type  string `json:"type"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("directory lookup: %w", err)
	}
	pk := 0
	for _, u := range page.Results {
		if strings.EqualFold(u.Email, email) && !strings.Contains(u.Type, "service") {
			pk = u.PK
			break
		}
	}
	if pk == 0 {
		return []DirectoryDevice{}, nil
	}
	res, err = a.do(ctx, http.MethodGet, fmt.Sprintf("/api/v3/authenticators/admin/all/?user=%d", pk))
	if err != nil {
		return nil, fmt.Errorf("directory devices: %w", err)
	}
	body, _ = io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory devices: %d", res.StatusCode)
	}
	var raw []struct {
		PK          json.RawMessage `json:"pk"`
		Name        string          `json:"name"`
		Type        string          `json:"type"`
		VerboseName string          `json:"verbose_name"`
		Created     string          `json:"created"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("directory devices: %w", err)
	}
	out := make([]DirectoryDevice, 0, len(raw))
	for _, d := range raw {
		dev := DirectoryDevice{ID: strings.Trim(string(d.PK), `"`), Kind: deviceKind(d.Type, d.VerboseName), Name: d.Name}
		if dev.Name == "" {
			dev.Name = d.VerboseName
		}
		if t, err := time.Parse(time.RFC3339Nano, d.Created); err == nil {
			dev.CreatedAt = &t
		}
		out = append(out, dev)
	}
	return out, nil
}

// DeleteDevice implements directoryDevices: the device must be one the
// account's own list reports (kind and id), so a caller can never reach
// another account's authenticator through this path.
func (a *authentikEraser) DeleteDevice(ctx context.Context, email, kind, id string) (bool, error) {
	if _, ok := deviceAdminPath[kind]; !ok || id == "" {
		return false, nil
	}
	devs, err := a.DevicesByEmail(ctx, email)
	if err != nil {
		return false, err
	}
	found := false
	for _, d := range devs {
		if d.Kind == kind && d.ID == id {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	res, err := a.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v3/authenticators/admin/%s/%s/", deviceAdminPath[kind], url.PathEscape(id)))
	if err != nil {
		return false, fmt.Errorf("directory device delete: %w", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	switch res.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("directory device delete: %d", res.StatusCode)
}

// deviceAdminPath maps the device kinds the API reports to authentik's
// admin authenticator endpoints.
var deviceAdminPath = map[string]string{
	"totp": "totp", "webauthn": "webauthn", "static": "static", "duo": "duo", "sms": "sms", "email": "email",
}

// deviceKind folds authentik's device class names onto the settings page's
// vocabulary.
func deviceKind(typ, verbose string) string {
	s := strings.ToLower(typ + " " + verbose)
	switch {
	case strings.Contains(s, "totp"):
		return "totp"
	case strings.Contains(s, "webauthn"):
		return "webauthn"
	case strings.Contains(s, "static"):
		return "static"
	case strings.Contains(s, "duo"):
		return "duo"
	case strings.Contains(s, "sms"):
		return "sms"
	case strings.Contains(s, "email"):
		return "email"
	}
	return "other"
}
