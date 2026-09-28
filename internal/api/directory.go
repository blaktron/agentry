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

	"github.com/google/uuid"
)

// directoryEraser deletes a person's sign-in account in the external
// directory service as part of account erasure (§12.7, agentry#20). With
// credentials held by the directory (DEV-057), the registry's own
// pseudonymization leaves the email, display name and password hash alive
// there — and the person able to sign in again and JIT-create a fresh
// account. Erasure is only erasure if both halves happen.
type directoryEraser interface {
	// EraseAccount deletes the directory account the link names (see
	// findAccount), never a superuser or a service account, and says which
	// rule it looked by. Returns false with no error when no account
	// qualifies.
	EraseAccount(ctx context.Context, link directoryLink) (bool, directoryLookup, error)
}

// directoryLink is how the registry names a person's directory account
// (agentry#727): the directory's own id for it, learnt at sign-in; the uid
// the directory reports for it, which is the registry's `authentik:`
// subject; and the registry's copy of the address, the lookup of last
// resort. The id and the uid are zero for an account that never signed in
// through the directory, and the id alone for one that has not signed in
// since the directory began sending it.
type directoryLink struct {
	AccountID int64
	UID       string
	Email     string
}

// directoryLookup is how findAccount ended: the rule that found the
// account, or why none was taken. The erasure's audit row records it.
type directoryLookup string

const (
	dirLookupByID      directoryLookup = "id"
	dirLookupByUID     directoryLookup = "uid"
	dirLookupByAddress directoryLookup = "address"
	// The three that leave an account the person may hold in place: more
	// than one account at the address, the recorded id now holding an
	// account with another uid, and a superuser, which erasure never
	// deletes. Erasure reports these as unresolved, for the operator.
	dirLookupAddressShared directoryLookup = "address-shared"
	dirLookupIDMismatch    directoryLookup = "id-mismatch"
	dirLookupSuperuser     directoryLookup = "superuser"
)

// unresolved reports a lookup that may have left the person's account in
// the directory.
func (l directoryLookup) unresolved() bool {
	return l == dirLookupAddressShared || l == dirLookupIDMismatch || l == dirLookupSuperuser
}

// directoryLinksFor names every directory account the person is linked to
// (agentry#727), oldest first: the directory's id and uid from each
// directory sign-in, with the registry's address as the last resort. With
// no directory sign-in it is the address alone.
func (s *Server) directoryLinksFor(ctx context.Context, userID uuid.UUID, email string) ([]directoryLink, error) {
	rows, err := s.q().ListUserDirectoryLinks(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("read the account's directory links: %w", err)
	}
	if len(rows) == 0 {
		return []directoryLink{{Email: email}}, nil
	}
	links := make([]directoryLink, 0, len(rows))
	for _, r := range rows {
		links = append(links, directoryLink{AccountID: r.DirectoryAccountID, UID: r.DirectorySubject, Email: email})
	}
	return links, nil
}

// directoryLinkFor is the oldest of directoryLinksFor, which the settings
// page reads so its answer does not move while the account keeps it.
func (s *Server) directoryLinkFor(ctx context.Context, userID uuid.UUID, email string) (directoryLink, error) {
	links, err := s.directoryLinksFor(ctx, userID, email)
	if err != nil {
		return directoryLink{Email: email}, err
	}
	return links[0], nil
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

// findAccount finds the directory account a link names, by the one rule
// every directory lookup the registry makes shares (agentry#727,
// agentry#617):
//
//  1. When the registry has learnt the directory's id for the account, the
//     account at that id, and only if its uid is the linked one: an id that
//     holds another account now never reaches it (id-mismatch).
//  2. For an identity that signed in before the directory sent the id, the
//     account at the registry's address that carries the linked uid.
//  3. For an account that never signed in through the directory, the
//     account at the address, and only when exactly one holds it: authentik
//     does not keep addresses unique (agentry#712), and a guess between two
//     is somebody else's account half the time (address-shared).
//
// Addresses match exactly and case-blind; a service account never counts.
// nil, with how it looked, when no account qualifies.
func (a *authentikEraser) findAccount(ctx context.Context, link directoryLink) (*authentikUser, directoryLookup, error) {
	if link.AccountID > 0 {
		u, err := a.accountByID(ctx, link.AccountID)
		if err != nil || u == nil {
			return nil, dirLookupByID, err
		}
		if link.UID == "" || u.UID != link.UID || u.isService() {
			return nil, dirLookupIDMismatch, nil
		}
		return u, dirLookupByID, nil
	}
	if link.Email == "" {
		return nil, dirLookupByAddress, nil
	}
	accounts, err := a.accountsAt(ctx, link.Email)
	if err != nil {
		return nil, dirLookupByAddress, err
	}
	if link.UID != "" {
		for i := range accounts {
			if accounts[i].UID == link.UID {
				return &accounts[i], dirLookupByUID, nil
			}
		}
		return nil, dirLookupByUID, nil
	}
	switch len(accounts) {
	case 0:
		return nil, dirLookupByAddress, nil
	case 1:
	default:
		return nil, dirLookupAddressShared, nil
	}
	return &accounts[0], dirLookupByAddress, nil
}

// accountByID reads one directory account by its id; nil when there is none.
func (a *authentikEraser) accountByID(ctx context.Context, pk int64) (*authentikUser, error) {
	res, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/api/v3/core/users/%d/", pk))
	if err != nil {
		return nil, fmt.Errorf("directory lookup: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("directory lookup: %d", res.StatusCode)
	}
	var u authentikUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("directory lookup: %w", err)
	}
	return &u, nil
}

// accountsAt lists the directory accounts at exactly this address,
// case-blind, active or not, service accounts left out. authentik 2026.8's
// email= filter is exact and case-sensitive (agentry#617), so an address
// the directory holds with capitals would never be found from the
// registry's lower-cased one; search= is case-blind and also matches parts
// of the username and the name, so it only narrows.
func (a *authentikEraser) accountsAt(ctx context.Context, email string) ([]authentikUser, error) {
	var out []authentikUser
	for page := 1; page > 0; {
		var users authentikPage[authentikUser]
		path := fmt.Sprintf("/api/v3/core/users/?page_size=50&page=%d&search=%s", page, url.QueryEscape(email))
		if err := a.doJSON(ctx, http.MethodGet, path, nil, &users); err != nil {
			return nil, fmt.Errorf("directory lookup: %w", err)
		}
		for _, u := range users.Results {
			if strings.EqualFold(u.Email, email) && !u.isService() {
				out = append(out, u)
			}
		}
		page = users.Pagination.Next
	}
	return out, nil
}

// EraseAccount implements directoryEraser. A superuser is never deleted,
// however it was found: an operator's own account must not be erasable
// through a registry account.
func (a *authentikEraser) EraseAccount(ctx context.Context, link directoryLink) (bool, directoryLookup, error) {
	u, how, err := a.findAccount(ctx, link)
	if err != nil || u == nil {
		return false, how, err
	}
	if u.IsSuperuser {
		return false, dirLookupSuperuser, nil
	}
	res, err := a.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v3/core/users/%d/", u.PK))
	if err != nil {
		return false, how, fmt.Errorf("directory delete: %w", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	switch res.StatusCode {
	case http.StatusNoContent:
		return true, how, nil
	case http.StatusNotFound:
		// Gone between the lookup and the delete: nothing left to erase.
		return false, how, nil
	}
	return false, how, fmt.Errorf("directory delete: %d", res.StatusCode)
}

// directoryDevices is the read side of the same admin access: the
// authenticators a user has enrolled, for the settings page (agentry#113).
type directoryDevices interface {
	Devices(ctx context.Context, link directoryLink) ([]DirectoryDevice, error)
	// DeleteDevice removes one of the account's authenticators; false when
	// the account has no device of that kind and id (never somebody else's).
	DeleteDevice(ctx context.Context, link directoryLink, kind, id string) (bool, error)
}

// DirectoryDevice is one enrolled authenticator as the directory reports it.
type DirectoryDevice struct {
	ID        string
	Kind      string
	Name      string
	CreatedAt *time.Time
}

// Devices lists the authenticators of the directory account the link names
// (findAccount; authentik: /authenticators/admin/all/?user=<pk>). No
// account or no devices is an empty list, not an error.
func (a *authentikEraser) Devices(ctx context.Context, link directoryLink) ([]DirectoryDevice, error) {
	u, _, err := a.findAccount(ctx, link)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return []DirectoryDevice{}, nil
	}
	res, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/api/v3/authenticators/admin/all/?user=%d", u.PK))
	if err != nil {
		return nil, fmt.Errorf("directory devices: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
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
func (a *authentikEraser) DeleteDevice(ctx context.Context, link directoryLink, kind, id string) (bool, error) {
	if _, ok := deviceAdminPath[kind]; !ok || id == "" {
		return false, nil
	}
	devs, err := a.Devices(ctx, link)
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
