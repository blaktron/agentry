package ui

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// landing: /ui/ — the signed-in go to their account, the signed-out to
// sign-in (or, with a site in front, to the site).
func (h *handler) landing(w http.ResponseWriter, r *http.Request) {
	if h.opt.Mode != "full" {
		http.Redirect(w, r, h.homeURL(), http.StatusSeeOther)
		return
	}
	if h.currentUser(r) != nil {
		http.Redirect(w, r, "/ui/account", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, h.loginURL(""), http.StatusSeeOther)
}

type loginData struct {
	Next         string
	Login        string
	TOTP         bool
	Providers    []Provider
	ProviderHref map[string]string
	ExternalOnly bool
}

func (h *handler) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"), "/ui/account")
	if h.currentUser(r) != nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	d := loginData{Next: next, Login: r.URL.Query().Get("login"), TOTP: r.URL.Query().Get("totp") == "1", Providers: h.opt.Providers, ExternalOnly: h.opt.ExternalOnly, ProviderHref: map[string]string{}}
	for _, p := range h.opt.Providers {
		d.ProviderHref[p.ID] = "/api/v1/auth/oidc/" + p.ID + "/start?next=" + url.QueryEscape(next)
	}
	// One directory and nothing else: the directory IS the way in, so go
	// there directly unless the page has something to say (agentry#164).
	if h.opt.ExternalOnly && len(h.opt.Providers) == 1 && r.URL.Query().Get("error") == "" && r.URL.Query().Get("ok") == "" {
		http.Redirect(w, r, d.ProviderHref[h.opt.Providers[0].ID], http.StatusSeeOther)
		return
	}
	h.render(w, r, http.StatusOK, "login", page{Title: "Sign in", Data: d})
}

// loginSubmit posts the native credentials to POST /auth/login in-process
// and mirrors the session it issued onto the browser, with the CSRF cookie
// the form posts need (agentry#77).
func (h *handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-origin form post rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"), "/ui/account")
	body := map[string]string{"login": r.PostFormValue("login"), "password": r.PostFormValue("password")}
	if code := strings.TrimSpace(r.PostFormValue("totpCode")); code != "" {
		body["totpCode"] = code
	}
	res, err := h.call(r).do(http.MethodPost, "/auth/login", body)
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	if !res.OK() {
		q := url.Values{"next": {next}, "login": {body["login"]}}
		if strings.HasSuffix(res.problemType(), "totp-required") {
			q.Set("totp", "1")
			q.Set("error", "Enter your two-factor code.")
		} else {
			q.Set("error", res.detail())
		}
		http.Redirect(w, r, "/ui/login?"+q.Encode(), http.StatusSeeOther)
		return
	}
	var out struct {
		CsrfToken string `json:"csrfToken"`
	}
	_ = res.decode(&out)
	sess := findSetCookie(res.Header, sessionCookie)
	if sess == "" || cookieValueOf(sess) == "" || out.CsrfToken == "" {
		back(w, r, "/ui/login", "", "sign-in succeeded but no session was issued")
		return
	}
	forwardCookies(w, res.Header)
	setCookieLike(w, csrfCookie, out.CsrfToken, sess, h.opt.CookieSecure)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// logout revokes the session through POST /auth/logout and clears both
// cookies whatever the API said; a directory-owned account is sent through
// the directory's end-session flow so the next sign-in asks again (DEV-057).
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
		p.Error = "The server could not be reached. Try again in a moment."
		h.render(w, r, http.StatusBadGateway, "message", p)
	case res.OK():
		p.Flash = "Your email address is verified. You can sign in."
		p.Data = map[string]string{"Link": h.loginURL(""), "LinkText": "Sign in"}
		h.render(w, r, http.StatusOK, "message", p)
	default:
		p.Error = res.detail()
		h.render(w, r, http.StatusBadRequest, "message", p)
	}
}

// The device authorize flow (DEV-058, D-015, DR-17, D-018): the CLI or the
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
}

func parseAuthorizeParams(port, state string) authorizeData {
	n, err := strconv.Atoi(port)
	d := authorizeData{Port: n, State: state}
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
		http.Error(w, "invalid device callback parameters", http.StatusBadRequest)
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/user/tokens/desktop-grant", map[string]string{"state": d.State})
	if err != nil || !res.OK() {
		msg := "the server could not be reached"
		if err == nil {
			msg = res.detail()
		}
		if res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden {
			http.Redirect(w, r, h.loginURL("/ui/authorize?port="+strconv.Itoa(d.Port)+"&state="+url.QueryEscape(d.State)), http.StatusSeeOther)
			return
		}
		back(w, r, "/ui/authorize?port="+strconv.Itoa(d.Port)+"&state="+url.QueryEscape(d.State), "", msg)
		return
	}
	var grant struct {
		Code string `json:"code"`
	}
	if res.decode(&grant) != nil || grant.Code == "" {
		back(w, r, "/ui/authorize?port="+strconv.Itoa(d.Port)+"&state="+url.QueryEscape(d.State), "", "no code was issued")
		return
	}
	cb := url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(d.Port), Path: "/callback"}
	cb.RawQuery = url.Values{"state": {d.State}, "code": {grant.Code}}.Encode()
	http.Redirect(w, r, cb.String(), http.StatusSeeOther)
}
