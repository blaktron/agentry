package api_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// The org admin page against the real API: an owner sees the sections and
// changes the policy and the teams through the forms; a stranger gets the
// refusal the API gives.
func TestCoreUIOrgAdmin(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("uiorg")
	env.verifyEmail(owner)
	sess := env.login(owner)
	org := "uiorg-co" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": org, "displayName": "UI Org"}, nil, http.StatusCreated)

	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse(env.srv.URL)
	jar.SetCookies(base, []*http.Cookie{{Name: "agentry_session", Value: sess.session}, {Name: "agentry_csrf", Value: sess.csrf}})
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	getPage := func(path string) (int, string) {
		t.Helper()
		res, err := client.Get(env.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	postForm := func(form url.Values) *http.Response {
		t.Helper()
		form.Set("_csrf", sess.csrf)
		req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/ui/orgs/"+org, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if code, body := getPage("/ui/orgs"); code != http.StatusOK || !strings.Contains(body, org) {
		t.Fatalf("orgs index: %d %s", code, body)
	}
	if code, body := getPage("/ui/orgs/" + org); code != http.StatusOK || !strings.Contains(body, "UI Org") || !strings.Contains(body, "<strong>"+owner+"</strong>") {
		t.Fatalf("org page: %d %s", code, body)
	}
	res := postForm(url.Values{"section": {"team"}, "slug": {"platform"}})
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "ok=Team+platform+created") {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("team: %d %s %s", res.StatusCode, res.Header.Get("Location"), b)
	}
	code, body := getPage("/ui/orgs/" + org)
	if code != http.StatusOK || !strings.Contains(body, "<strong>platform</strong>") {
		t.Fatalf("team listed: %d %s", code, body)
	}
	// The policy round-trips through the textarea.
	start := strings.Index(body, `name="policy"`)
	if start < 0 {
		t.Fatalf("no policy textarea")
	}
	res = postForm(url.Values{"section": {"policy"}, "policy": {`{"mcpServers": {"allowVulnerable": false}}`}})
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "ok=Policy+saved") {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("policy: %d %s %s", res.StatusCode, res.Header.Get("Location"), b)
	}

	// A stranger: the org exists, the admin sections are refused.
	stranger := env.register("uiorg-x")
	env.verifyEmail(stranger)
	s2 := env.login(stranger)
	jar2, _ := cookiejar.New(nil)
	jar2.SetCookies(base, []*http.Cookie{{Name: "agentry_session", Value: s2.session}, {Name: "agentry_csrf", Value: s2.csrf}})
	c2 := &http.Client{Jar: jar2}
	r2, err := c2.Get(env.srv.URL + "/ui/orgs/" + org)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden || strings.Contains(string(b2), "Create webhook") {
		t.Fatalf("stranger: %d %s", r2.StatusCode, b2)
	}
}
