package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// directorySignInFacts is what the settings page needs to know about how the
// caller signs in at the directory: the social provider the
// account was first connected to, and whether it has a password.
type directorySignInFacts interface {
	SignInFacts(ctx context.Context, link DirectoryLink) (DirectorySignInFacts, error)
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

// SignInFacts reads the facts for the directory account the caller's
// directory sign-in is linked to (findAccount's first two rules). An
// address alone never picks the account here: with no linked uid, or no
// account carrying it, nothing is reported. The first connection is the
// earliest one the account has. Whether it has a password is the account's
// agentry_has_password attribute, which the account-flows blueprint keeps
// (authentik's API has no such field); nil until the account has signed in
// or written a password under a blueprint that keeps it.
func (a *authentikEraser) SignInFacts(ctx context.Context, link DirectoryLink) (DirectorySignInFacts, error) {
	var out DirectorySignInFacts
	if link.UID == "" {
		return out, nil
	}
	u, _, err := a.findAccount(ctx, link)
	if err != nil || u == nil {
		return out, err
	}

	// The two answers are independent: a failed connections read still
	// returns the password answer, with the error.
	out.HasPassword = jsonBool(u.Attributes.HasPassword)
	src, err := a.firstConnection(ctx, u.PK)
	out.FirstSource = src
	return out, err
}

// firstConnection is the account's earliest social connection: an OAuth
// source's, since every social provider is one (an LDAP, SAML or Kerberos
// connection is not a way someone signed up). It reads the OAuth connections
// list, not the list of all connections, whose rows name every source by
// the base model and so cannot say which kind it is (seen on 2026.8.0); the
// token needs view on OAuth source connections for it. It asks by the
// user's pk and keeps only rows that say they are that user's: the API
// ignores filters it does not know, and a renamed one must not report
// somebody else's.
func (a *authentikEraser) firstConnection(ctx context.Context, pk int) (*DirectorySource, error) {
	var first *DirectorySource
	var firstAt time.Time
	for page := 1; page > 0; {
		var conns authentikPage[struct {
			User      int       `json:"user"`
			Created   time.Time `json:"created"`
			SourceObj struct {
				Slug string `json:"slug"`
				Name string `json:"name"`
			} `json:"source_obj"`
		}]
		path := fmt.Sprintf("/api/v3/sources/user_connections/oauth/?page_size=50&page=%d&user=%d", page, pk)
		if err := a.doJSON(ctx, http.MethodGet, path, nil, &conns); err != nil {
			return nil, fmt.Errorf("directory connections: %w", err)
		}
		for _, c := range conns.Results {
			if c.User != pk || c.SourceObj.Slug == "" {
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
