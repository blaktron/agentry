package ui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Organization administration (DEV-091, plan core-web-split §3.2): the
// settings the site's org admin page offers, as plain forms over the same
// /orgs/{org}/* operations. Authorization is the API's: a member who is
// not an admin sees the refusal the API gives.

type orgInfo struct {
	Handle         string `json:"handle"`
	DisplayName    string `json:"displayName"`
	SsoRequired    *bool  `json:"ssoRequired"`
	VerifiedDomain string `json:"verifiedDomain"`
	Seats          *seats `json:"seats"`
}

// seats is what the organization holds against its allowance; Max 0 is
// unbounded, which is what a registry with no billing extension answers.
type seats struct {
	Used    int64 `json:"used"`
	Invited int64 `json:"invited"`
	Pending int64 `json:"pending"`
	Max     int64 `json:"max"`
}

// orgMember is the API's Membership: the user nested, the role beside it.
type orgMember struct {
	User struct {
		Handle      string `json:"handle"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Role    string `json:"role"`
	ViaScim bool   `json:"viaScim"`
	State   string `json:"state"`
}

// Pending reports whether this membership is waiting for an admin.
func (m orgMember) Pending() bool { return m.State == "pending" }

// invitation is an open invitation on the org page.
type invitation struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expiresAt"`
	Expired   bool   `json:"expired"`
	InvitedBy string `json:"invitedBy"`
}

type team struct {
	ID      string      `json:"id"`
	Slug    string      `json:"slug"`
	Members []orgMember `json:"-"`
}

type ssoConnection struct {
	Kind    string         `json:"kind"`
	Enabled bool           `json:"enabled"`
	Config  map[string]any `json:"config"`
}

type scimToken struct {
	ID        string     `json:"id"`
	CreatedAt *time.Time `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

type domainClaim struct {
	Domain      string     `json:"domain"`
	Verified    bool       `json:"verified"`
	VerifiedAt  *time.Time `json:"verifiedAt"`
	RecordName  string     `json:"recordName"`
	RecordValue string     `json:"recordValue"`
}

type webhook struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Active bool     `json:"active"`
}

var (
	// The roles the API accepts (agentry#360): admin and member everywhere;
	// security_reviewer only inside a first-party organization, which the
	// API decides — the page offers it and shows the refusal.
	orgRoles      = []string{"admin", "member", "security_reviewer"}
	webhookEvents = []string{"version.published", "version.rejected", "version.yanked", "agent.quarantined"}
)

type orgData struct {
	Org     orgInfo
	Handle  string
	Members []orgMember
	Teams   []team
	Policy  string
	SSO     []ssoConnection
	// The stored state each SSO form reflects on load (agentry#272): before
	// this the textarea and both Enabled boxes rendered empty, so a save
	// silently disabled a connection unless the box was re-ticked.
	SAMLMetadata string
	SAMLEnabled  bool
	OIDCEnabled  bool
	SCIM         []scimToken
	Domains      []domainClaim
	Webhooks     []webhook
	Invitations  []invitation
	Roles        []string
	Events       []string
	Refused      string
	OIDCIssuer   string
	OIDCClient   string
}

func (h *handler) orgPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	org := r.PathValue("org")
	c := h.call(r)
	d := orgData{Handle: org, Roles: orgRoles, Events: webhookEvents}
	base := "/orgs/" + url.PathEscape(org)
	res, err := c.do(http.MethodGet, base, nil)
	if err != nil || !res.OK() {
		status := http.StatusBadGateway
		msg := notSent
		if err == nil {
			status, msg = res.Status, res.detail()
		}
		h.render(w, r, status, "message", page{Title: "Organization " + org, User: u, Error: msg})
		return
	}
	_ = res.decode(&d.Org)
	// Members is the admin gate: the API refuses it to non-admins, and the
	// page says so rather than showing empty sections.
	if res, err := c.do(http.MethodGet, base+"/members", nil); err == nil {
		if res.OK() {
			_ = res.decode(&d.Members)
		} else {
			d.Refused = res.detail()
		}
	}
	if d.Refused == "" {
		if res, err := c.do(http.MethodGet, base+"/invitations", nil); err == nil && res.OK() {
			_ = res.decode(&d.Invitations)
		}
		if res, err := c.do(http.MethodGet, base+"/teams", nil); err == nil && res.OK() {
			_ = res.decode(&d.Teams)
			for i := range d.Teams {
				if mres, err := c.do(http.MethodGet, base+"/teams/"+url.PathEscape(d.Teams[i].Slug)+"/members", nil); err == nil && mres.OK() {
					_ = mres.decode(&d.Teams[i].Members)
				}
			}
		}
		if res, err := c.do(http.MethodGet, base+"/policy", nil); err == nil && res.OK() {
			var doc any
			if json.Unmarshal(res.Body, &doc) == nil {
				if pretty, err := json.MarshalIndent(doc, "", "  "); err == nil {
					d.Policy = string(pretty)
				}
			}
		}
		if res, err := c.do(http.MethodGet, base+"/sso/connections", nil); err == nil && res.OK() {
			_ = res.decode(&d.SSO)
			for _, conn := range d.SSO {
				switch conn.Kind {
				case "oidc":
					d.OIDCIssuer, _ = conn.Config["issuer"].(string)
					d.OIDCClient, _ = conn.Config["clientId"].(string)
					d.OIDCEnabled = conn.Enabled
				case "saml":
					d.SAMLMetadata, _ = conn.Config["idpMetadataXml"].(string)
					d.SAMLEnabled = conn.Enabled
				}
			}
		}
		if res, err := c.do(http.MethodGet, base+"/scim/tokens", nil); err == nil && res.OK() {
			_ = res.decode(&d.SCIM)
		}
		if res, err := c.do(http.MethodGet, base+"/domain-claims", nil); err == nil && res.OK() {
			_ = res.decode(&d.Domains)
		}
		if res, err := c.do(http.MethodGet, base+"/webhooks", nil); err == nil && res.OK() {
			_ = res.decode(&d.Webhooks)
		}
	}
	status := http.StatusOK
	if d.Refused != "" {
		status = http.StatusForbidden
	}
	h.render(w, r, status, "org", page{Title: "Organization " + org, User: u, Data: d})
}

// orgAction is every org admin form: one handler, one `section` field,
// each section mapping onto the API operation the site's routes call.
func (h *handler) orgAction(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	org := r.PathValue("org")
	base := "/orgs/" + url.PathEscape(org)
	backTo := "/ui/orgs/" + url.PathEscape(org)
	c := h.call(r)
	f := r.PostFormValue
	var (
		res response
		err error
		ok  string
	)
	switch f("section") {
	case "org":
		body := map[string]any{"displayName": strings.TrimSpace(f("displayName"))}
		if v := f("ssoRequired"); v != "" {
			body["ssoRequired"] = v == "true"
		}
		res, err = c.do(http.MethodPatch, base, body)
		ok = "Organization saved."
	case "member":
		handle := strings.TrimSpace(f("handle"))
		if handle == "" {
			h.back(w, r, backTo, "", "Enter the member's handle.")
			return
		}
		role := f("role")
		if role == "" {
			role = "member"
		}
		switch f("action") {
		case "remove":
			res, err = c.do(http.MethodDelete, base+"/members/"+url.PathEscape(handle), nil)
			ok = handle + " removed. Their org-bound tokens stop working."
		case "approve":
			// Where the seat is taken (agentry#361): a person the IdP
			// provisioned is waiting until an admin says so.
			res, err = c.do(http.MethodPost, base+"/members/"+url.PathEscape(handle)+"/approve", map[string]string{"role": role})
			ok = handle + " approved as " + role + "."
		case "decline":
			res, err = c.do(http.MethodPost, base+"/members/"+url.PathEscape(handle)+"/decline", nil)
			ok = handle + " declined."
		default:
			res, err = c.do(http.MethodPut, base+"/members/"+url.PathEscape(handle), map[string]string{"role": role})
			ok = handle + " is " + role + "."
		}
	case "invitation":
		switch f("action") {
		case "revoke":
			id := strings.TrimSpace(f("id"))
			if id == "" {
				h.back(w, r, backTo, "", "Choose an invitation to revoke.")
				return
			}
			res, err = c.do(http.MethodDelete, base+"/invitations/"+url.PathEscape(id), nil)
			ok = "Invitation revoked. Its seat is free and its link stops working."
		default:
			email := strings.TrimSpace(f("email"))
			if email == "" {
				h.back(w, r, backTo, "", "Enter the address to invite.")
				return
			}
			role := f("role")
			if role == "" {
				role = "member"
			}
			res, err = c.do(http.MethodPost, base+"/invitations", map[string]string{"email": email, "role": role})
			if err == nil && res.OK() {
				var created struct {
					AcceptURL string `json:"acceptUrl"`
					Mailed    bool   `json:"mailed"`
				}
				_ = json.Unmarshal(res.Body, &created)
				// The link is shown once. When the registry did not mail it
				// — it mails no address it has not verified — this page is
				// the only place the admin will ever see it.
				ok = "Invited " + email + " as " + role + ". "
				if created.Mailed {
					ok += "The invitation was emailed to them."
				} else {
					ok += "It was not emailed, because that address is not a verified account here. Send them this link, which is shown once: " + created.AcceptURL
				}
			}
		}
	case "team":
		slug := strings.TrimSpace(f("slug"))
		if slug == "" {
			h.back(w, r, backTo, "", "Enter the team slug.")
			return
		}
		switch f("action") {
		case "delete":
			res, err = c.do(http.MethodDelete, base+"/teams/"+url.PathEscape(slug), nil)
			ok = "Team " + slug + " deleted."
		case "add-member":
			res, err = c.do(http.MethodPost, base+"/teams/"+url.PathEscape(slug)+"/members", map[string]string{"handle": strings.TrimSpace(f("handle"))})
			ok = "Added to " + slug + "."
		case "remove-member":
			res, err = c.do(http.MethodDelete, base+"/teams/"+url.PathEscape(slug)+"/members/"+url.PathEscape(strings.TrimSpace(f("handle"))), nil)
			ok = "Removed from " + slug + "."
		default:
			res, err = c.do(http.MethodPost, base+"/teams", map[string]string{"slug": slug})
			ok = "Team " + slug + " created."
		}
	case "policy":
		var doc any
		if json.Unmarshal([]byte(f("policy")), &doc) != nil {
			h.back(w, r, backTo, "", "The policy must be valid JSON.")
			return
		}
		res, err = c.do(http.MethodPut, base+"/policy", doc)
		ok = "Policy saved."
	case "sso":
		kind := f("kind")
		if kind != "saml" && kind != "oidc" {
			h.back(w, r, backTo, "", "The connection kind must be saml or oidc.")
			return
		}
		switch f("action") {
		case "test":
			// The probe answers 200 whether it passed or failed (ok=false
			// carries the reason), so the verdict is in the body, not the
			// status (agentry#272).
			res, err = c.do(http.MethodPost, base+"/sso/connections/"+kind+"/test", nil)
			if err == nil && res.OK() {
				var probe struct {
					OK       bool     `json:"ok"`
					Summary  string   `json:"summary"`
					Warnings []string `json:"warnings"`
				}
				if res.decode(&probe) != nil || probe.Summary == "" {
					h.back(w, r, backTo, "", kind+" connection checked, but the result could not be read.")
					return
				}
				msg := probe.Summary
				if len(probe.Warnings) > 0 {
					msg += " Warnings: " + strings.Join(probe.Warnings, "; ")
				}
				if !probe.OK {
					h.back(w, r, backTo, "", msg)
					return
				}
				h.back(w, r, backTo, msg, "")
				return
			}
		case "delete":
			res, err = c.do(http.MethodDelete, base+"/sso/connections/"+kind, nil)
			ok = kind + " connection removed. Sign-in through it stops; current sessions stand."
		default:
			cfg := map[string]string{}
			if kind == "saml" {
				cfg["idpMetadataXml"] = f("idpMetadataXml")
			} else {
				cfg["issuer"] = strings.TrimSpace(f("issuer"))
				cfg["clientId"] = strings.TrimSpace(f("clientId"))
				if s := f("clientSecret"); s != "" {
					cfg["clientSecret"] = s
				}
			}
			res, err = c.do(http.MethodPut, base+"/sso/connections/"+kind, map[string]any{"enabled": f("enabled") == "true", "config": cfg})
			ok = kind + " connection saved."
		}
	case "scim":
		if f("action") == "revoke" {
			res, err = c.do(http.MethodDelete, base+"/scim/tokens/"+url.PathEscape(f("tokenId")), nil)
			ok = "SCIM token revoked. It stops authenticating at the next request."
		} else {
			res, err = c.do(http.MethodPost, base+"/scim/tokens", map[string]any{})
			if err == nil && res.OK() {
				var created struct {
					Token string `json:"token"`
				}
				_ = res.decode(&created)
				h.render(w, r, http.StatusOK, "showonce", page{Title: "SCIM token created", User: h.currentUser(r), Data: showOnceData{
					Intro: "Copy the value below now. It is not stored and cannot be shown again. Your IdP sends it as a bearer token to /scim/v2.",
					Lines: []showOnceLine{{"SCIM bearer token", created.Token}},
					Back:  backTo,
				}})
				return
			}
		}
	case "domain":
		domain := strings.ToLower(strings.TrimSpace(f("domain")))
		if domain == "" {
			h.back(w, r, backTo, "", "Enter the domain.")
			return
		}
		if f("action") == "verify" {
			res, err = c.do(http.MethodPost, base+"/domain-claims/verify", map[string]string{"domain": domain})
			ok = domain + " verified. SSO can now link accounts with that email domain."
		} else {
			res, err = c.do(http.MethodPost, base+"/domain-claims", map[string]string{"domain": domain})
			ok = domain + " claimed; add the DNS record shown and verify."
		}
	case "webhook":
		switch f("action") {
		case "delete":
			res, err = c.do(http.MethodDelete, base+"/webhooks/"+url.PathEscape(f("id")), nil)
			ok = "Webhook deleted. No further deliveries go to that endpoint."
		case "ping":
			res, err = c.do(http.MethodPost, base+"/webhooks/"+url.PathEscape(f("id"))+"/ping", nil)
			ok = "Ping queued for delivery."
		default:
			events := r.PostForm["events"]
			if len(events) == 0 {
				h.back(w, r, backTo, "", "Pick at least one event.")
				return
			}
			res, err = c.do(http.MethodPost, base+"/webhooks", map[string]any{"url": strings.TrimSpace(f("url")), "events": events})
			if err == nil && res.OK() {
				var created struct {
					Secret string `json:"secret"`
				}
				_ = res.decode(&created)
				if created.Secret == "" {
					created.Secret = "(not returned)"
				}
				h.render(w, r, http.StatusOK, "showonce", page{Title: "Webhook created", User: h.currentUser(r), Data: showOnceData{
					Intro: "Copy the signing secret now. The server keeps it sealed and does not show it again, and signs every delivery with it under X-Agentry-Signature.",
					Lines: []showOnceLine{{"Endpoint", strings.TrimSpace(f("url"))}, {"Signing secret", created.Secret}},
					Back:  backTo,
				}})
				return
			}
		}
	default:
		h.back(w, r, backTo, "", "The form did not name a section.")
		return
	}
	if err != nil || !res.OK() {
		h.back(w, r, backTo, "", failMsg(res, err))
		return
	}
	h.back(w, r, backTo, ok, "")
}

// orgsIndex lists the organizations the caller can administer (from
// GET /user), each linking to its page; anyone can also type a handle.
func (h *handler) orgsIndex(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	var admin []userOrg
	for _, o := range u.Orgs {
		if o.Role == "admin" {
			admin = append(admin, o)
		}
	}
	h.render(w, r, http.StatusOK, "orgs", page{Title: "Organizations", User: u, Data: admin})
}
