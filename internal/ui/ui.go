// Package ui is the server's own browser surface (DEV-091, plan
// core-web-split §3.2): the pages a registry needs to be usable without a
// site in front of it — the device-authorize page the CLI and the desktop
// app open, sign-in, and the account basics — served by agentryd at /ui/.
//
// It is deliberately plain: server-rendered html/template, no JavaScript,
// one stylesheet, brand from config. Every page acts through the API's own
// handlers in-process with the browser's cookies (client.go), so a page can
// do nothing the API would refuse and the authorization matrix stays the
// only one.
package ui

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

const (
	sessionCookie = "agentry_session"
	csrfCookie    = "agentry_csrf"
)

// Brand is what the pages call this deployment and where they send people.
type Brand struct {
	Name          string
	LogoURL       string
	CSSURL        string
	SupportEmail  string
	SecurityEmail string
	PrivacyURL    string
	TermsURL      string
}

// Provider is a sign-in provider the login page offers (config social.*).
type Provider struct {
	ID    string
	Label string
}

// Options wires the surface to the server.
type Options struct {
	// API is the server's full handler chain (middleware included); every
	// page call goes through it in-process.
	API http.Handler
	// Mode is config ui.mode: full or authorize (off is never mounted).
	Mode string
	// SiteURL is config web.url: when set, sign-in and the account pages
	// are the site's, and only the authorize page is served here.
	SiteURL string
	// BaseURL is the server's public origin (for absolute links); may be "".
	BaseURL string
	Brand   Brand
	// Providers are the configured social/OIDC providers, in display order.
	Providers []Provider
	// ExternalOnly says a directory service owns credentials: no password
	// form, sign-in goes through a provider, password/MFA live in the
	// directory (DEV-057).
	ExternalOnly bool
	// IdPLogoutURL, when set, is where sign-out sends the browser after the
	// session is revoked (the directory's end-session flow).
	IdPLogoutURL string
	CookieSecure bool
	Log          *slog.Logger
}

type handler struct {
	opt  Options
	tmpl templates
	log  *slog.Logger
	csp  string
	mux  *http.ServeMux
}

// New returns the handler to mount at /ui/.
func New(opt Options) http.Handler {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Mode == "" {
		opt.Mode = "full"
	}
	if opt.Brand.Name == "" {
		opt.Brand.Name = "Agentry"
	}
	opt.SiteURL = strings.TrimRight(opt.SiteURL, "/")
	opt.BaseURL = strings.TrimRight(opt.BaseURL, "/")
	tmpl, err := loadTemplates()
	if err != nil {
		panic(err) // embedded templates: a build-time mistake, never a request-time one
	}
	h := &handler{opt: opt, tmpl: tmpl, log: opt.Log, mux: http.NewServeMux()}
	h.csp = h.buildCSP()
	m := h.mux
	m.HandleFunc("GET /ui/static/ui.css", h.serveCSS)
	m.HandleFunc("GET /ui/authorize", h.authorizePage)
	m.HandleFunc("POST /ui/authorize", h.authorizeApprove)
	m.HandleFunc("GET /ui/{$}", h.landing)
	m.HandleFunc("GET /ui", h.landing)
	if opt.Mode == "full" {
		m.HandleFunc("GET /ui/login", h.loginPage)
		m.HandleFunc("POST /ui/login", h.loginSubmit)
		m.HandleFunc("POST /ui/logout", h.logout)
		m.HandleFunc("GET /ui/verify-email", h.verifyEmail)
		m.HandleFunc("GET /ui/account", h.accountPage)
		m.HandleFunc("GET /ui/account/directory", h.accountPage)
		m.HandleFunc("POST /ui/account", h.accountSave)
		m.HandleFunc("POST /ui/account/directory/devices", h.directoryDeviceRemove)
		m.HandleFunc("GET /ui/account/tokens", h.tokensPage)
		m.HandleFunc("POST /ui/account/tokens", h.tokensSubmit)
		m.HandleFunc("GET /ui/account/ssh-keys", h.sshKeysPage)
		m.HandleFunc("POST /ui/account/ssh-keys", h.sshKeysSubmit)
		m.HandleFunc("GET /ui/account/sessions", h.sessionsPage)
		m.HandleFunc("POST /ui/account/sessions", h.sessionsSubmit)
		m.HandleFunc("GET /ui/review", h.reviewQueue)
		m.HandleFunc("GET /ui/review/{id}", h.reviewItemPage)
		m.HandleFunc("POST /ui/review/{id}/decision", h.reviewDecide)
		m.HandleFunc("POST /ui/review/{id}/findings/{fid}/verdict", h.findingVerdict)
		m.HandleFunc("GET /ui/staff", h.staffPage)
		m.HandleFunc("POST /ui/staff/abuse", h.staffAbuseTriage)
		m.HandleFunc("POST /ui/staff/agent-action", h.staffAgentAction)
		m.HandleFunc("POST /ui/staff/ruleset-release", h.staffRulesetRelease)
		m.HandleFunc("GET /ui/orgs", h.orgsIndex)
		m.HandleFunc("GET /ui/orgs/{org}", h.orgPage)
		m.HandleFunc("POST /ui/orgs/{org}", h.orgAction)
	}
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// A path no pattern claims gets this surface's own 404 page rather than
	// the mux's bare text; a path that exists under another method keeps the
	// mux's 405 and its Allow header.
	if _, pat := h.mux.Handler(r); pat == "" && !h.pathHasOtherMethod(r) {
		h.refuse(w, r, http.StatusNotFound, "No such page", "The registry serves no page at this address. Check the link you followed.")
		return
	}
	h.mux.ServeHTTP(w, r)
}

// pathHasOtherMethod says whether some pattern claims this path under a
// method other than the request's. Only GET and POST are ever registered
// here, so probing those two settles it.
func (h *handler) pathHasOtherMethod(r *http.Request) bool {
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if m == r.Method {
			continue
		}
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pat := h.mux.Handler(probe); pat != "" {
			return true
		}
	}
	return false
}

// refuse answers a request this surface will not act on with the message
// page inside the layout, at the status the bare http.Error used to send.
// A refusal reaches a signed-in reader as often as a signed-out one — a stale
// CSRF cookie, a mistyped path — so the page resolves the session like any
// other and keeps the nav and Sign out where they were. currentUser is an
// in-process API call and a nil result is fine: it renders the signed-out
// layout. The one link is a way back, because a page with no controls at all
// leaves the browser's Back button as the only exit.
func (h *handler) refuse(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	link, text := h.wayBack(r)
	h.render(w, r, status, "message", page{
		Title: title,
		Error: msg,
		User:  h.currentUser(r),
		Data:  map[string]string{"Link": link, "LinkText": text},
	})
}

// wayBack is where a refusal's link points: the page the browser came from
// when the Referer is a path on this origin, else this surface's entrance.
// safeNext is the same admission rule the sign-in flow's next uses, so a
// crafted Referer cannot turn this into an off-site link.
func (h *handler) wayBack(r *http.Request) (string, string) {
	if u, err := url.Parse(r.Header.Get("Referer")); err == nil {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		if u.Host == "" || u.Host == host {
			if p := safeNext(u.EscapedPath(), ""); p != "" {
				return p, "Go back"
			}
		}
	}
	return "/ui/", "Go to the registry"
}

func (h *handler) serveCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(stylesheet)
}

// buildCSP: the pages carry no scripts; styles are the embedded sheet (plus
// the brand's, if any); images are self, data: and the brand logo's origin;
// forms post here and, for the device authorize flow, redirect to the
// loopback listener (agentry#172: form-action governs the redirect after a
// POST in Chrome), and sign-out may redirect to the directory or the site.
func (h *handler) buildCSP() string {
	style := "'self' 'unsafe-inline'"
	if o := originOf(h.opt.Brand.CSSURL); o != "" {
		style += " " + o
	}
	img := "'self' data:"
	if o := originOf(h.opt.Brand.LogoURL); o != "" {
		img += " " + o
	}
	form := "'self' http://127.0.0.1:*"
	for _, u := range []string{h.opt.IdPLogoutURL, h.opt.SiteURL} {
		if o := originOf(u); o != "" && !strings.Contains(form, o) {
			form += " " + o
		}
	}
	return "default-src 'none'; style-src " + style + "; img-src " + img + "; form-action " + form + "; base-uri 'none'; frame-ancestors 'none'"
}

func originOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// call binds the in-process client to this browser request.
func (h *handler) call(r *http.Request) apiCall {
	return apiCall{api: h.opt.API, r: r, csrf: cookieValue(r, csrfCookie)}
}

// currentUser resolves the browser's session through GET /user; nil when
// signed out (or the session is stale).
func (h *handler) currentUser(r *http.Request) *userInfo {
	if cookieValue(r, sessionCookie) == "" {
		return nil
	}
	res, err := h.call(r).do(http.MethodGet, "/user", nil)
	if err != nil || !res.OK() {
		return nil
	}
	var u userInfo
	if err := res.decode(&u); err != nil || u.ID == "" {
		return nil
	}
	return &u
}

// loginURL is where a signed-out browser is sent: the site's sign-in when a
// site fronts this server, else this surface's own. next is a path on this
// origin to return to.
func (h *handler) loginURL(next string) string {
	base := "/ui/login"
	if h.opt.SiteURL != "" {
		base = h.opt.SiteURL + "/login"
	}
	if next != "" {
		return base + "?next=" + url.QueryEscape(next)
	}
	return base
}

// homeURL is where sign-out ends and where the landing page sends a
// signed-out visitor with nothing to do.
func (h *handler) homeURL() string {
	if h.opt.SiteURL != "" {
		return h.opt.SiteURL + "/"
	}
	return "/ui/"
}

// requireUser redirects a signed-out browser to sign-in (remembering where
// it was) and returns nil.
func (h *handler) requireUser(w http.ResponseWriter, r *http.Request) *userInfo {
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, h.loginURL(r.URL.RequestURI()), http.StatusSeeOther)
	}
	return u
}

// sameOrigin is the same rule the site applies to its form posts (agentry-web, lib/forms.ts):
// Sec-Fetch-Site when the browser sends it, else Origin against Host.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == host
}

// acceptForm parses a form post and applies the two checks every mutation
// gets: same origin, and the hidden _csrf field matching the CSRF cookie
// (a double submit on top of the API's own header check).
func (h *handler) acceptForm(w http.ResponseWriter, r *http.Request) bool {
	if !sameOrigin(r) {
		h.refuseCrossOrigin(w, r)
		return false
	}
	if err := r.ParseForm(); err != nil {
		h.refuseBadForm(w, r)
		return false
	}
	if c := cookieValue(r, csrfCookie); c == "" || r.PostFormValue("_csrf") != c {
		h.refuse(w, r, http.StatusForbidden, "Form token mismatch", "The form's token does not match your cookie, so the registry refused it. Reload the page and sign in again if it keeps failing.")
		return false
	}
	return true
}

// The two refusals the sign-in form shares with every other form: it posts
// before there is a session to carry a CSRF token, so it checks these two
// itself (pages_auth.go loginSubmit).
func (h *handler) refuseCrossOrigin(w http.ResponseWriter, r *http.Request) {
	h.refuse(w, r, http.StatusForbidden, "Form refused", "This form was posted from another site, so the registry refused it. Open the page again and submit it from here.")
}

func (h *handler) refuseBadForm(w http.ResponseWriter, r *http.Request) {
	h.refuse(w, r, http.StatusBadRequest, "Unreadable form", "The registry could not read this form's fields, so nothing changed. Reload the page and submit it again.")
}

// back redirects to path with a flash. The flash rides in a short-lived
// cookie the next render reads and clears, never in the URL: a `?ok=` a
// page honoured let any address choose the page's notice, on the
// registry's own domain (agentry#271). The cookie keeps a server-produced
// message that is not a fixed string — an SSO probe's summary, an IdP's
// warning — without a whitelist. Rendered as text by the page, never as
// HTML.
func (h *handler) back(w http.ResponseWriter, r *http.Request, path string, ok, errMsg string) {
	h.setFlash(w, ok, errMsg)
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// flashCookie carries one page's notice from a redirect to the render
// that follows it, scoped to the UI and gone within a minute or on first
// read.
const flashCookie = "agentry_flash"

type flash struct {
	OK    string `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h *handler) setFlash(w http.ResponseWriter, ok, errMsg string) {
	if ok == "" && errMsg == "" {
		return
	}
	b, _ := json.Marshal(flash{OK: ok, Error: errMsg})
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString(b),
		Path: "/ui", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.opt.CookieSecure, MaxAge: 60})
}

// takeFlash reads the flash cookie the request carries, if any, and
// clears it; a cookie that does not decode is cleared and ignored.
func (h *handler) takeFlash(w http.ResponseWriter, r *http.Request) (flash, bool) {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return flash{}, false
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/ui", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: h.opt.CookieSecure, MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return flash{}, false
	}
	var f flash
	if json.Unmarshal(b, &f) != nil {
		return flash{}, false
	}
	return f, true
}

// safeNext admits only a path-absolute reference on this origin, the same
// rule as the API's social-login callback.
func safeNext(v, fallback string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/\\") || strings.ContainsAny(v, "\r\n") {
		return fallback
	}
	return v
}
