package ui

import (
	"net/http"
	"net/url"
	"strconv"
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
	// DirectoryError is set when the directory read failed: the page says
	// it could not look rather than rendering the non-directory account
	// (agentry#271).
	DirectoryError string
	Support        string
	// Notifications is the person's mail and in-app switches (agentry#190),
	// shown and set here so the mails' footer has a page to name
	// (agentry#274); NotificationsError says the read failed.
	Notifications      *notificationSettings
	NotificationsError string
	// Knowledge is the knowledge meter (agentry#593): what the person keeps
	// in the registry against their allocation. KnowledgeOff says the
	// registry keeps no packs; KnowledgeError that the read failed.
	Knowledge      *knowledgeUsage
	KnowledgeOff   bool
	KnowledgeError string
}

// knowledgeUsage is the API's KnowledgeUsage, with its sizes in words.
type knowledgeUsage struct {
	Bytes  int64 `json:"bytes"`
	Packs  int   `json:"packs"`
	Used   int64 `json:"used"`
	Max    int64 `json:"max"`
	Pooled bool  `json:"pooled"`
}

// Kept, Counted and Allocation are the meter's sizes, in MB with one
// decimal: the person's own packs, what counts against the allocation (the
// pool's total when it is shared), and the allocation.
func (k knowledgeUsage) Kept() string       { return megabytes(k.Bytes) }
func (k knowledgeUsage) Counted() string    { return megabytes(k.Used) }
func (k knowledgeUsage) Allocation() string { return megabytes(k.Max) }

func megabytes(n int64) string {
	return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
}

// notificationSettings is the API's NotificationSettings, the six mail
// switches and the one in-app switch.
type notificationSettings struct {
	Email struct {
		DependencyAlerts bool `json:"dependencyAlerts"`
		Quarantine       bool `json:"quarantine"`
		ReviewDecisions  bool `json:"reviewDecisions"`
		Advisories       bool `json:"advisories"`
		OrgInvites       bool `json:"orgInvites"`
		// Billing is the hosted product's subscription mail (agentry#366).
		// This page renders every switch it is given and sends every one
		// back, so it names the field; a registry with no billing sends
		// none of these and the switch simply governs nothing.
		Billing bool `json:"billing"`
	} `json:"email"`
	Web struct {
		DependencyAlerts bool `json:"dependencyAlerts"`
	} `json:"web"`
}

func (h *handler) accountPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	d := accountData{Support: h.opt.Brand.SupportEmail}
	if res, err := h.call(r).do(http.MethodGet, "/user/notifications", nil); err != nil || !res.OK() {
		d.NotificationsError = readFailed("your notification settings", res, err)
	} else {
		var ns notificationSettings
		if res.decode(&ns) == nil {
			d.Notifications = &ns
		}
	}
	switch res, err := h.call(r).do(http.MethodGet, "/knowledge/usage", nil); {
	case err == nil && strings.HasSuffix(res.problemType(), "/knowledge-unconfigured"):
		d.KnowledgeOff = true
	case err != nil || !res.OK():
		d.KnowledgeError = readFailed("your knowledge allocation", res, err)
	default:
		var ku knowledgeUsage
		if res.decode(&ku) == nil {
			d.Knowledge = &ku
		}
	}
	if h.opt.ExternalOnly {
		res, err := h.call(r).do(http.MethodGet, "/user/directory", nil)
		if err != nil || !res.OK() {
			d.DirectoryError = readFailed("the password and authenticator links", res, err)
		} else {
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
		h.back(w, r, "/ui/account", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/account", "Profile saved.", "")
}

func (h *handler) directoryDeviceRemove(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	kind, id := r.PostFormValue("kind"), r.PostFormValue("deviceId")
	if kind == "" || id == "" {
		h.back(w, r, "/ui/account", "", "The form did not say which authenticator to remove.")
		return
	}
	res, err := h.call(r).do(http.MethodDelete, "/user/directory/devices/"+url.PathEscape(kind)+"/"+url.PathEscape(id), nil)
	if err != nil || !res.OK() {
		h.back(w, r, "/ui/account", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/account", "Authenticator removed. Sign-in no longer accepts it.", "")
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
var scopes = []string{"agent:read", "agent:publish", "repo:read", "repo:write", "user:profile", "org:admin", "review:act", "audit:read", "run:read", "run:write", "knowledge:read", "knowledge:write", "secret:write"}

type tokensData struct {
	Tokens []token
	Scopes []string
	// LoadError is the readFailed notice when the list could not be read;
	// the empty state is for an answered-empty list only (agentry#271).
	LoadError string
}

type sshKeysData struct {
	Keys      []sshKey
	LoadError string
}

type sessionsData struct {
	Sessions  []session
	LoadError string
}

// notificationsSave replaces the person's notification settings from the
// form: a box unticked is a switch off, so the whole set is sent, as the
// API's PUT expects.
func (h *handler) notificationsSave(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	on := func(field string) bool { return r.PostFormValue(field) == "true" }
	var ns notificationSettings
	ns.Email.DependencyAlerts = on("email.dependencyAlerts")
	ns.Email.Quarantine = on("email.quarantine")
	ns.Email.ReviewDecisions = on("email.reviewDecisions")
	ns.Email.Advisories = on("email.advisories")
	ns.Email.OrgInvites = on("email.orgInvites")
	ns.Email.Billing = on("email.billing")
	ns.Web.DependencyAlerts = on("web.dependencyAlerts")
	res, err := h.call(r).do(http.MethodPut, "/user/notifications", ns)
	if err != nil || !res.OK() {
		h.back(w, r, "/ui/account", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/account", "Notification settings saved.", "")
}

func (h *handler) tokensPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	d := tokensData{Scopes: scopes}
	res, err := h.call(r).do(http.MethodGet, "/user/tokens", nil)
	if err != nil || !res.OK() {
		d.LoadError = readFailed("your tokens", res, err)
	} else {
		_ = res.decode(&d.Tokens)
	}
	h.render(w, r, http.StatusOK, "tokens", page{Title: "Personal access tokens", User: u, Data: d})
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
			h.back(w, r, "/ui/account/tokens", "", failMsg(res, err))
			return
		}
		h.back(w, r, "/ui/account/tokens", "Token revoked. Calls with it fail now.", "")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	sc := r.PostForm["scopes"]
	if name == "" {
		h.back(w, r, "/ui/account/tokens", "", "A token needs a name.")
		return
	}
	if len(sc) == 0 {
		h.back(w, r, "/ui/account/tokens", "", "Pick at least one scope.")
		return
	}
	res, err := c.do(http.MethodPost, "/user/tokens", map[string]any{"name": name, "scopes": sc})
	if err != nil || !res.OK() {
		h.back(w, r, "/ui/account/tokens", "", failMsg(res, err))
		return
	}
	var created struct {
		Token string `json:"token"`
	}
	if res.decode(&created) != nil || created.Token == "" {
		h.back(w, r, "/ui/account/tokens", "", "The token was created but not shown. Revoke it in the list and create another.")
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
	var d sshKeysData
	res, err := h.call(r).do(http.MethodGet, "/user/ssh-keys", nil)
	if err != nil || !res.OK() {
		d.LoadError = readFailed("your SSH keys", res, err)
	} else {
		_ = res.decode(&d.Keys)
	}
	h.render(w, r, http.StatusOK, "sshkeys", page{Title: "SSH keys", User: u, Data: d})
}

func (h *handler) sshKeysSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	c := h.call(r)
	if r.PostFormValue("action") == "remove" {
		res, err := c.do(http.MethodDelete, "/user/ssh-keys/"+url.PathEscape(r.PostFormValue("keyId")), nil)
		if err != nil || !res.OK() {
			h.back(w, r, "/ui/account/ssh-keys", "", failMsg(res, err))
			return
		}
		h.back(w, r, "/ui/account/ssh-keys", "Key removed. Git over SSH refuses it now.", "")
		return
	}
	title, key := strings.TrimSpace(r.PostFormValue("title")), strings.TrimSpace(r.PostFormValue("publicKey"))
	if title == "" || key == "" {
		h.back(w, r, "/ui/account/ssh-keys", "", "A key needs a title and the public key.")
		return
	}
	res, err := c.do(http.MethodPost, "/user/ssh-keys", map[string]string{"title": title, "publicKey": key})
	if err != nil || !res.OK() {
		h.back(w, r, "/ui/account/ssh-keys", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/account/ssh-keys", "Key added.", "")
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
	var d sessionsData
	res, err := h.call(r).do(http.MethodGet, "/user/sessions", nil)
	if err != nil || !res.OK() {
		d.LoadError = readFailed("your sessions", res, err)
	} else {
		var out struct {
			Sessions []session `json:"sessions"`
		}
		_ = res.decode(&out)
		d.Sessions = out.Sessions
	}
	h.render(w, r, http.StatusOK, "sessions", page{Title: "Sessions", User: u, Data: d})
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
		h.back(w, r, "/ui/account/sessions", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/account/sessions", ok, "")
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

// readFailed is the notice a page shows when a read failed: the page
// could not look, which is not the same as nothing being there
// (agentry#271). The empty state is rendered only on an answered-empty
// read. A problem detail is a sentence of its own (internal/api
// problem.go), so it stands between the lead and the advice.
func readFailed(what string, res response, err error) string {
	if err != nil {
		return "The registry could not fetch " + what + ": the request was not sent. Reload to try again."
	}
	return "The registry could not fetch " + what + ". " + res.detail() + " Reload to try again."
}

// notSent is the one copy for that branch, shared by every page.
const notSent = "The request was not sent. Nothing changed."
