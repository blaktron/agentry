package ui

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The account basics: who you are, the directory's password/MFA links (or
// the native TOTP state), personal access tokens, SSH keys, sessions. Each
// page reads through the API and each form posts through it.

type directoryInfo struct {
	Managed           bool   `json:"managed"`
	PasswordChangeUrl string `json:"passwordChangeUrl"`
	TotpSetupUrl      string `json:"totpSetupUrl"`
	WebauthnSetupUrl  string `json:"webauthnSetupUrl"`
	DevicesError      string `json:"devicesError"`
	Devices           *[]struct {
		ID        string     `json:"id"`
		Kind      string     `json:"kind"`
		Name      string     `json:"name"`
		CreatedAt *time.Time `json:"createdAt"`
	} `json:"devices"`
}

type accountData struct {
	Directory *directoryInfo
	Support   string
}

func (h *handler) accountPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	d := accountData{Support: h.opt.Brand.SupportEmail}
	if h.opt.ExternalOnly {
		if res, err := h.call(r).do(http.MethodGet, "/user/directory", nil); err == nil && res.OK() {
			var dir directoryInfo
			if res.decode(&dir) == nil {
				d.Directory = &dir
			}
		}
	}
	h.render(w, r, http.StatusOK, "account", page{Title: "Account", User: u, Data: d})
}

func (h *handler) accountSave(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("displayName"))
	res, err := h.call(r).do(http.MethodPatch, "/user", map[string]string{"displayName": name})
	if err != nil || !res.OK() {
		back(w, r, "/ui/account", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/account", "Profile saved.", "")
}

func (h *handler) directoryDeviceRemove(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	kind, id := r.PostFormValue("kind"), r.PostFormValue("deviceId")
	if kind == "" || id == "" {
		back(w, r, "/ui/account", "", "The form did not say which authenticator to remove.")
		return
	}
	res, err := h.call(r).do(http.MethodDelete, "/user/directory/devices/"+url.PathEscape(kind)+"/"+url.PathEscape(id), nil)
	if err != nil || !res.OK() {
		back(w, r, "/ui/account", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/account", "Authenticator removed. Sign-in no longer accepts it.", "")
}

type token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

// scopes is the PAT scope set the pages offer (§12.3), in the order shown.
var scopes = []string{"agent:read", "agent:publish", "repo:read", "repo:write", "user:profile", "org:admin", "review:act", "audit:read"}

type tokensData struct {
	Tokens []token
	Scopes []string
}

func (h *handler) tokensPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	var list []token
	if res, err := h.call(r).do(http.MethodGet, "/user/tokens", nil); err == nil && res.OK() {
		_ = res.decode(&list)
	}
	h.render(w, r, http.StatusOK, "tokens", page{Title: "Personal access tokens", User: u, Data: tokensData{Tokens: list, Scopes: scopes}})
}

func (h *handler) tokensSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	c := h.call(r)
	if r.PostFormValue("action") == "revoke" {
		id := r.PostFormValue("tokenId")
		res, err := c.do(http.MethodDelete, "/user/tokens/"+url.PathEscape(id), nil)
		if err != nil || !res.OK() {
			back(w, r, "/ui/account/tokens", "", failMsg(res, err))
			return
		}
		back(w, r, "/ui/account/tokens", "Token revoked. Calls with it fail now.", "")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	sc := r.PostForm["scopes"]
	if name == "" {
		back(w, r, "/ui/account/tokens", "", "A token needs a name.")
		return
	}
	if len(sc) == 0 {
		back(w, r, "/ui/account/tokens", "", "Pick at least one scope.")
		return
	}
	res, err := c.do(http.MethodPost, "/user/tokens", map[string]any{"name": name, "scopes": sc})
	if err != nil || !res.OK() {
		back(w, r, "/ui/account/tokens", "", failMsg(res, err))
		return
	}
	var created struct {
		Token string `json:"token"`
	}
	if res.decode(&created) != nil || created.Token == "" {
		back(w, r, "/ui/account/tokens", "", "The token was created but not shown. Revoke it in the list and create another.")
		return
	}
	// Shown once, never in a URL (the same rule as the site's show-once): the page is the
	// POST's own response.
	h.render(w, r, http.StatusOK, "showonce", page{Title: "Token created", User: h.currentUser(r), Data: showOnceData{
		Intro: "Copy the value below now. It is not stored and cannot be shown again.",
		Lines: []showOnceLine{{"Personal access token \"" + name + "\"", created.Token}, {"Scopes", strings.Join(sc, " ")}},
		Back:  "/ui/account/tokens",
	}})
}

type showOnceLine struct{ Label, Value string }
type showOnceData struct {
	Intro string
	Lines []showOnceLine
	Back  string
}

type sshKey struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	KeyType     string     `json:"keyType"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastUsedAt  *time.Time `json:"lastUsedAt"`
}

func (h *handler) sshKeysPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	var list []sshKey
	if res, err := h.call(r).do(http.MethodGet, "/user/ssh-keys", nil); err == nil && res.OK() {
		_ = res.decode(&list)
	}
	h.render(w, r, http.StatusOK, "sshkeys", page{Title: "SSH keys", User: u, Data: list})
}

func (h *handler) sshKeysSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	c := h.call(r)
	if r.PostFormValue("action") == "remove" {
		res, err := c.do(http.MethodDelete, "/user/ssh-keys/"+url.PathEscape(r.PostFormValue("keyId")), nil)
		if err != nil || !res.OK() {
			back(w, r, "/ui/account/ssh-keys", "", failMsg(res, err))
			return
		}
		back(w, r, "/ui/account/ssh-keys", "Key removed. Git over SSH refuses it now.", "")
		return
	}
	title, key := strings.TrimSpace(r.PostFormValue("title")), strings.TrimSpace(r.PostFormValue("publicKey"))
	if title == "" || key == "" {
		back(w, r, "/ui/account/ssh-keys", "", "A key needs a title and the public key.")
		return
	}
	res, err := c.do(http.MethodPost, "/user/ssh-keys", map[string]string{"title": title, "publicKey": key})
	if err != nil || !res.OK() {
		back(w, r, "/ui/account/ssh-keys", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/account/ssh-keys", "Key added.", "")
}

type session struct {
	ID         string     `json:"id"`
	Current    bool       `json:"current"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
	IP         string     `json:"ip"`
	UserAgent  string     `json:"userAgent"`
}

func (h *handler) sessionsPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	var out struct {
		Sessions []session `json:"sessions"`
	}
	if res, err := h.call(r).do(http.MethodGet, "/user/sessions", nil); err == nil && res.OK() {
		_ = res.decode(&out)
	}
	h.render(w, r, http.StatusOK, "sessions", page{Title: "Sessions", User: u, Data: out.Sessions})
}

func (h *handler) sessionsSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	c := h.call(r)
	var (
		res response
		err error
		ok  string
	)
	if r.PostFormValue("action") == "revoke-others" {
		res, err = c.do(http.MethodDelete, "/user/sessions", nil)
		ok = "Every other session is signed out. This browser stays signed in."
	} else {
		res, err = c.do(http.MethodDelete, "/user/sessions/"+url.PathEscape(r.PostFormValue("sessionId")), nil)
		ok = "Session revoked. That browser is signed out now."
	}
	if err != nil || !res.OK() {
		back(w, r, "/ui/account/sessions", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/account/sessions", ok, "")
}

// failMsg is what a form says when the call behind it did not succeed. The
// error branch is not a network failure: the API is dispatched in-process
// (client.go — ServeHTTP cannot fail), so do() returns an error only when the
// request could not be built at all, and then nothing was sent and nothing
// changed. Every page says exactly that, in these words.
func failMsg(res response, err error) string {
	if err != nil {
		return notSent
	}
	return res.detail()
}

// notSent is the one copy for that branch, shared by every page.
const notSent = "The request was not sent. Nothing changed."
