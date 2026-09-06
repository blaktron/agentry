package api_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// The operator surface against the real pipeline: a submitted version in
// the platform queue, opened by staff in /ui/review, a finding verdict, the
// approval that publishes it — all through the server's own pages.
func TestCoreUIReviewAndStaff(t *testing.T) {
	env := newTestEnv(t)
	author, itemID, staff := setupReviewItem(t, env, "uirev")

	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse(env.srv.URL)
	jar.SetCookies(base, []*http.Cookie{{Name: "agentry_session", Value: staff.session}, {Name: "agentry_csrf", Value: staff.csrf}})
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
	postForm := func(path string, form url.Values) *http.Response {
		t.Helper()
		form.Set("_csrf", staff.csrf)
		req, _ := http.NewRequest(http.MethodPost, env.srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	if code, body := getPage("/ui/review"); code != http.StatusOK || !strings.Contains(body, author+"/risky") {
		t.Fatalf("queue: %d %s", code, body)
	}
	if code, body := getPage("/ui/staff"); code != http.StatusOK || !strings.Contains(body, author+"/risky") || !strings.Contains(body, "Ruleset releases") {
		t.Fatalf("staff: %d %s", code, body)
	}
	code, body := getPage("/ui/review/" + itemID + "?file=SKILL.md")
	if code != http.StatusOK || !strings.Contains(body, "Ignore all previous instructions") || !strings.Contains(body, "Approve and publish") {
		t.Fatalf("item: %d %s", code, body)
	}
	// A finding to give a verdict on: the fixture's SKILL.md trips S1.
	fid := ""
	if i := strings.Index(body, "/findings/"); i >= 0 {
		rest := body[i+len("/findings/"):]
		fid = rest[:strings.Index(rest, "/")]
	}
	if fid != "" {
		res := postForm("/ui/review/"+itemID+"/findings/"+fid+"/verdict", url.Values{"verdict": {"dismissed_false_positive"}, "reason": {"fixture text"}})
		if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "ok=Verdict") {
			t.Fatalf("verdict: %d %s", res.StatusCode, res.Header.Get("Location"))
		}
	}
	res := postForm("/ui/review/"+itemID+"/decision", url.Values{"decision": {"approve"}, "rationale": {"reviewed in the core UI"}})
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/ui/review?ok=Approved") {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("decision: %d %s %s", res.StatusCode, res.Header.Get("Location"), b)
	}
	env.waitStatus(author, "risky", "1.0.0", "published")

	// The author is not staff: the staff page says so and the platform
	// queue is refused, through the same authorization the API applies.
	authorSess := env.login(author)
	jar2, _ := cookiejar.New(nil)
	jar2.SetCookies(base, []*http.Cookie{{Name: "agentry_session", Value: authorSess.session}, {Name: "agentry_csrf", Value: authorSess.csrf}})
	c2 := &http.Client{Jar: jar2}
	r2, err := c2.Get(env.srv.URL + "/ui/staff")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden || !strings.Contains(string(b2), "not platform staff") {
		t.Fatalf("author on staff page: %d %s", r2.StatusCode, b2)
	}
}
