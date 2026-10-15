package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blaktron/agentry/internal/auth"
	oidcrp "github.com/blaktron/agentry/internal/auth/oidc"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// TestSsoConnection implements POST /orgs/{org}/sso/connections/{kind}/test:
// the "does this connection make sense" probe an admin needs
// before asking a colleague to try a real login. Read-only against the
// IdP (OIDC discovery only; SAML parses stored metadata) and never uses
// the client secret. A failing probe is ok=false with the reason, 200.
func (s *Server) TestSsoConnection(w http.ResponseWriter, r *http.Request, org OrgHandle, kind TestSsoConnectionParamsKind) {
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if !s.authorize(w, r, auth.ActOrgSettingsManage, orgRow.ID) {
		return
	}
	k := string(kind)
	out := SsoConnectionTest{Kind: SsoConnectionTestKind(k), CheckedAt: time.Now().UTC()}
	fail := func(msg string) {
		out.Ok = false
		out.Summary = msg
		writeJSON(w, http.StatusOK, out)
	}
	conn, err := s.q().GetSSOConnection(r.Context(), storegen.GetSSOConnectionParams{OrgID: orgRow.ID, Kind: k})
	if err != nil {
		fail("no " + k + " connection is configured")
		return
	}
	details := map[string]string{}
	var warnings []string
	switch k {
	case "saml":
		var c samlsp.Config
		if err := json.Unmarshal(conn.Config, &c); err != nil {
			fail("stored SAML config does not parse: " + err.Error())
			return
		}
		d, err := samlsp.DescribeIDP(c)
		if err != nil {
			fail("IdP metadata: " + err.Error())
			return
		}
		details["entityId"] = d.EntityID
		details["ssoUrl"] = strings.Join(d.SSOURLs, ", ")
		details["certificates"] = fmt.Sprint(d.Certificates)
		if d.Certificates == 0 {
			warnings = append(warnings, "no signing certificate in the metadata: assertions cannot be verified")
		}
		if d.EarliestCertExpiry != nil {
			details["certExpires"] = d.EarliestCertExpiry.UTC().Format(time.RFC3339)
			if until := time.Until(*d.EarliestCertExpiry); until < 0 {
				warnings = append(warnings, "the IdP signing certificate has expired")
			} else if until < 30*24*time.Hour {
				warnings = append(warnings, "the IdP signing certificate expires within 30 days")
			}
		}
		if d.ValidUntil != nil && d.ValidUntil.Before(time.Now()) {
			warnings = append(warnings, "the metadata document's validUntil is in the past")
		}
		metadataURL, acsURL, _ := s.ssoURLs(r, orgRow.Handle)
		details["spMetadataUrl"] = metadataURL
		details["acsUrl"] = acsURL
		out.Ok = true
		out.Summary = fmt.Sprintf("SAML metadata parsed: %s, %d certificate(s); sign-in goes to %s", d.EntityID, d.Certificates, firstOr(d.SSOURLs, "?"))
	case "oidc":
		var st storedOIDCConfig
		if err := json.Unmarshal(conn.Config, &st); err != nil {
			fail("stored OIDC config does not parse: " + err.Error())
			return
		}
		if st.ClientSecretEnc == "" {
			warnings = append(warnings, "no client secret stored: the code exchange will fail unless the IdP allows public clients")
		}
		_, _, redirect := s.ssoURLs(r, orgRow.Handle)
		start := time.Now()
		// Discovery only: no secret in the config, so nothing sensitive is
		// sent. Through the guarded client (oidcContext), and the admin
		// learns the status, never the body an internal address answered.
		rp, err := oidcrp.New(s.oidcContext(r.Context()), oidcrp.Config{Issuer: st.Issuer, ClientID: st.ClientID, Scopes: st.Scopes}, redirect)
		if err != nil {
			fail(oidcFailureSummary(st.Issuer, err))
			return
		}
		d := rp.Describe()
		details["issuer"] = d.Issuer
		details["authorizationEndpoint"] = d.AuthURL
		details["tokenEndpoint"] = d.TokenURL
		details["jwksUri"] = d.JWKSURL
		details["redirectUri"] = redirect
		details["discoveryMs"] = fmt.Sprint(time.Since(start).Milliseconds())
		if d.AuthURL == "" || d.TokenURL == "" {
			warnings = append(warnings, "discovery document lacks authorization or token endpoint")
		}
		if !strings.HasPrefix(d.AuthURL, "https://") && !strings.HasPrefix(d.Issuer, "http://localhost") && !strings.HasPrefix(d.Issuer, "http://127.") {
			warnings = append(warnings, "authorization endpoint is not https")
		}
		out.Ok = true
		out.Summary = fmt.Sprintf("OIDC discovery OK for %s (%s ms); register redirect URI %s at the IdP", d.Issuer, details["discoveryMs"], redirect)
	default:
		fail("unknown kind")
		return
	}
	if len(details) > 0 {
		out.Details = &details
	}
	if len(warnings) > 0 {
		out.Warnings = &warnings
	}
	writeJSON(w, http.StatusOK, out)
}

func firstOr(v []string, def string) string {
	if len(v) == 0 {
		return def
	}
	return v[0]
}
