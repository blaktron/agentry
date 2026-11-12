package connector

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// entraHost is Microsoft Entra ID's sign-in host; an admin-consent link is
// on it alone.
const entraHost = "login.microsoftonline.com"

// entraAdminConsentRedirect is where Entra sends the administrator's
// browser once they have approved: the loopback callback a connector's
// public client registers, which Entra requires the link to name. Nothing
// listens there for an administrator, so the page may not load; the
// approval is made by then.
const entraAdminConsentRedirect = "http://localhost/callback"

// graphScopePrefix qualifies a Microsoft Graph permission.
const graphScopePrefix = "https://graph.microsoft.com/"

// entraClientID is an Entra application (client) id.
var entraClientID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// graphPermission is a Graph permission's name, such as Mail.Read.
var graphPermission = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,63}$`)

// oidcScopes are the OpenID Connect scopes a consent may carry, which no
// administrator grants: they are left out of an admin-consent link.
var oidcScopes = map[string]bool{"openid": true, "profile": true, "email": true, "offline_access": true}

// IsEntraIssuer reports whether issuer is a Microsoft Entra v2.0 authority:
// https://login.microsoftonline.com/<tenant>/v2.0.
func IsEntraIssuer(issuer string) bool {
	u, err := url.Parse(trimIssuer(issuer))
	if err != nil || u.Scheme != "https" || u.Host != entraHost || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "v2.0"
}

// EntraAdminConsentURL is the link an administrator follows to approve a
// public client's Microsoft Graph permissions for their whole organization.
// The organizations authority lets the administrator sign in to their own
// tenant, so the person who was refused needs to know nothing of it. Each
// scope is a Graph permission, qualified as https://graph.microsoft.com/<name>
// or bare; the OpenID Connect scopes are left out, and anything else is
// refused, as is a client id that is not an Entra application id.
func EntraAdminConsentURL(publicClientID string, scopes []string) (string, error) {
	if !entraClientID.MatchString(publicClientID) {
		return "", errors.New("connector: the public client id is not an Entra application id")
	}
	var granted []string
	for _, s := range scopes {
		if oidcScopes[s] {
			continue
		}
		name := strings.TrimPrefix(s, graphScopePrefix)
		if !graphPermission.MatchString(name) {
			return "", errors.New("connector: " + s + " is not a Microsoft Graph permission")
		}
		granted = append(granted, graphScopePrefix+name)
	}
	if len(granted) == 0 {
		return "", errors.New("connector: no Microsoft Graph permission to approve")
	}
	q := url.Values{"client_id": {publicClientID}, "scope": {strings.Join(granted, " ")}, "redirect_uri": {entraAdminConsentRedirect}}
	return "https://" + entraHost + "/organizations/v2.0/adminconsent?" + q.Encode(), nil
}
