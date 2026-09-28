package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// directorySignIns is what the settings page needs to know about how the
// caller signs in at the directory (agentry#706): the social provider the
// account was first connected to, and whether it has a password.
type directorySignIns interface {
	SignInFacts(ctx context.Context, email, uid string) (DirectorySignInFacts, error)
}

// DirectorySignInFacts is what the directory says; a nil field is one it
// did not answer, which the settings page shows as nothing.
type DirectorySignInFacts struct {
	FirstSource *DirectorySource
	HasPassword *bool
}

// DirectorySource is a social provider as the directory names it.
type DirectorySource struct {
	Slug string
	Name string
}

// SignInFacts reads the facts for the directory account at email whose uid
// is uid, the subject the caller's directory sign-in is linked to. An
// address alone never picks the account: authentik does not keep addresses
// unique (agentry#712), so with no linked uid, or no account carrying it,
// nothing is reported. The first connection is the earliest one the account
// has. Whether it has a password is the account's agentry_has_password
// attribute, which the account-flows blueprint keeps (authentik's API has no
// such field); nil until the account has signed in or written a password
// under a blueprint that keeps it.
func (a *authentikEraser) SignInFacts(ctx context.Context, email, uid string) (DirectorySignInFacts, error) {
	var out DirectorySignInFacts
	if uid == "" {
		return out, nil
	}
	accounts, err := a.AccountsByEmail(ctx, email)
	if err != nil {
		return out, fmt.Errorf("directory lookup: %w", err)
	}
	pk := 0
	var hasPassword *bool
	for _, acc := range accounts {
		if acc.UID == uid {
			pk, hasPassword = acc.PK, acc.HasPassword
			break
		}
	}
	if pk == 0 {
		return out, nil
	}

	src, err := a.firstConnection(ctx, pk)
	if err != nil {
		return out, err
	}
	out.FirstSource = src
	out.HasPassword = hasPassword
	return out, nil
}

// firstConnection is the account's earliest source connection, by pk (the
// connections API ignores filters it does not know, so it is asked by the
// user's pk and nothing else).
func (a *authentikEraser) firstConnection(ctx context.Context, pk int) (*DirectorySource, error) {
	var first *DirectorySource
	var firstAt time.Time
	for page := 1; page > 0; {
		var conns authentikPage[struct {
			Created   time.Time `json:"created"`
			SourceObj struct {
				Slug string `json:"slug"`
				Name string `json:"name"`
			} `json:"source_obj"`
		}]
		path := fmt.Sprintf("/api/v3/sources/user_connections/all/?page_size=50&page=%d&user=%d", page, pk)
		if err := a.doJSON(ctx, http.MethodGet, path, nil, &conns); err != nil {
			return nil, fmt.Errorf("directory connections: %w", err)
		}
		for _, c := range conns.Results {
			if c.SourceObj.Slug == "" {
				continue
			}
			if first == nil || c.Created.Before(firstAt) {
				first = &DirectorySource{Slug: c.SourceObj.Slug, Name: c.SourceObj.Name}
				firstAt = c.Created
			}
		}
		page = conns.Pagination.Next
	}
	return first, nil
}
