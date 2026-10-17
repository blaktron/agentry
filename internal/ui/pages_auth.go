package ui

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/internal/auth"
)

// notSent says an in-process call did not reach the API (it cannot be
// read as an answer), so nothing the form asked for happened.
const notSent = "The request was not sent. Nothing changed."

// landing: /ui/ — the signed-out go to sign-in (or, with a site in front,
// to the site); the signed-in are told who they are, since every page they
// would use here is the device-authorize page the program opens for them.
func (h *handler) landing(w http.ResponseWriter, r *http.Request) {
	if h.opt.Mode != "full" {
		http.Redirect(w, r, h.homeURL(), http.StatusSeeOther)
		return
	}
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, h.loginURL(""), http.StatusSeeOther)
		return
	}
	h.render(w, r, http.StatusOK, "message", page{
		Title: "Signed in",
		User:  u,
		Flash: "You are signed in as " + u.Handle + ". The command line and the desktop app sign in through this registry's device-authorize page, which they open for you.",
	})
}

type loginData struct {
	Providers    []Provider
	ProviderHref map[string]string
}

// loginPage is the sign-in hand-off: the registry keeps no credentials, so
// signing in is the deployment's OpenID provider's. With one provider and
// nothing to show, the browser goes straight there.
func (h *handler) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"), "/ui/")
	if h.currentUser(r) != nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	d := loginData{Providers: h.opt.Providers, ProviderHref: map[string]string{}}
	for _, p := range h.opt.Providers {
		d.ProviderHref[p.ID] = "/api/v1/auth/oidc/" + p.ID + "/start?next=" + url.QueryEscape(next)
	}
	// The signed-out entrance is the one page another component addresses
	// with a message: on a headless deployment the API's sign-in callback
	// sends a failed sign-in here as ?error= (internal/api webPaths.login),
	// as the site's /login reads it. Honoured on this page alone, as text;
	// every other notice rides the flash cookie.
	pg := page{Title: "Sign in", Data: d, Error: r.URL.Query().Get("error")}
	// One provider is the way in, so go there directly unless the page has
	// something to show: that message, or a notice a redirect left for this
	// render.
	_, hasFlash := r.Cookie(flashCookie)
	if len(h.opt.Providers) == 1 && pg.Error == "" && hasFlash != nil {
		http.Redirect(w, r, d.ProviderHref[h.opt.Providers[0].ID], http.StatusSeeOther)
		return
	}
	h.render(w, r, http.StatusOK, "login", pg)
}

// logout revokes the session through POST /auth/logout and clears both
// cookies whatever the API said; the browser is then sent through the
// provider's end-session flow, where one is configured, so the next sign-in
// asks again.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	dest := h.homeURL()
	if h.opt.IdPLogoutURL != "" {
		dest = h.opt.IdPLogoutURL
	}
	if res, err := h.call(r).do(http.MethodPost, "/auth/logout", nil); err == nil && res.Status == http.StatusOK {
		var body struct {
			IdpLogoutUrl string `json:"idpLogoutUrl"`
		}
		if res.decode(&body) == nil && (strings.HasPrefix(body.IdpLogoutUrl, "https://") || strings.HasPrefix(body.IdpLogoutUrl, "http://")) {
			dest = body.IdpLogoutUrl
		}
	}
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.opt.CookieSecure, MaxAge: -1})
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// verifyEmail: the link a verification email carries (GET) posts the token
// to POST /auth/verify-email and says how it went.
func (h *handler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	p := page{Title: "Verify your email"}
	if token == "" {
		p.Error = "This link is missing its token. Open the link from the email again, or request a new verification email."
		h.render(w, r, http.StatusBadRequest, "message", p)
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/auth/verify-email", map[string]string{"token": token})
	switch {
	case err != nil:
		p.Error = notSent
		h.render(w, r, http.StatusBadGateway, "message", p)
	case res.OK():
		p.Flash = "Your email address is confirmed and your account is activated."
		p.Data = map[string]string{"Link": h.loginURL(""), "LinkText": "Sign in"}
		h.render(w, r, http.StatusOK, "message", p)
	default:
		p.Error = res.detail()
		h.render(w, r, http.StatusBadRequest, "message", p)
	}
}

// The device authorize flow: the CLI or the
// desktop app starts a one-shot listener on 127.0.0.1:<port>, opens this
// page with its state nonce, and waits. The page asks one question; the
// approval records a single-use grant through POST /user/tokens/desktop-grant
// and hands the loopback listener the exchange CODE — never a token.
const (
	portMin = 1024
	portMax = 65535
)

var stateRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

type authorizeData struct {
	Port  int
	State string
	Valid bool
	// Scopes are what approving grants, from the grant's own list.
	Scopes string
}

func parseAuthorizeParams(port, state string) authorizeData {
	n, err := strconv.Atoi(port)
	d := authorizeData{Port: n, State: state, Scopes: strings.Join(auth.SignInGrantScopes(), ", ")}
	d.Valid = err == nil && n >= portMin && n <= portMax && stateRE.MatchString(state)
	return d
}

func (h *handler) authorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := parseAuthorizeParams(q.Get("port"), q.Get("state"))
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, h.loginURL(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	status := http.StatusOK
	if !d.Valid {
		status = http.StatusBadRequest
	}
	h.render(w, r, status, "authorize", page{Title: "Authorize this device", User: u, Data: d})
}

func (h *handler) authorizeApprove(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	d := parseAuthorizeParams(r.PostFormValue("port"), r.PostFormValue("state"))
	if !d.Valid {
		h.refuse(w, r, http.StatusBadRequest, "Invalid device request", "The port or state in this form is not valid. Start the sign-in again from the program.")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/user/tokens/desktop-grant", map[string]string{"state": d.State})
	if err != nil || !res.OK() {
		msg := notSent
		if err == nil {
			msg = res.detail()
		}
		if res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden {
			http.Redirect(w, r, h.loginURL("/ui/authorize?port="+strconv.Itoa(d.Port)+"&state="+url.QueryEscape(d.State)), http.StatusSeeOther)
			return
		}
		h.back(w, r, "/ui/authorize?port="+strconv.Itoa(d.Port)+"&state="+url.QueryEscape(d.State), "", msg)
		return
	}
	var grant struct {
		Code string `json:"code"`
	}
	if res.decode(&grant) != nil || grant.Code == "" {
		h.back(w, r, "/ui/authorize?port="+strconv.Itoa(d.Port)+"&state="+url.QueryEscape(d.State), "", "No code was issued. This device is not authorized.")
		return
	}
	cb := url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(d.Port), Path: "/callback"}
	cb.RawQuery = url.Values{"state": {d.State}, "code": {grant.Code}}.Encode()
	http.Redirect(w, r, cb.String(), http.StatusSeeOther)
}
