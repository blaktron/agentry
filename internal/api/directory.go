package api

import (
	"context"
	"encoding/json"
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
	return a.http.Do(req)
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
		// The filter is a substring match on authentik's side; delete only
		// exact, case-insensitive matches, and never a service account or a
		// superuser — an operator's own account must not be erasable by a
		// registry user who happens to share its address.
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
