package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// An endpoint's address is checked when it is created or changed: one the
// delivery client could not send to is refused on url, and the refusal does
// not repeat the address, whose path and query can carry a secret.
func TestAWebhookAddressTheClientCannotSendToIsRefused(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("wu-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "wuorg" + env.sfx
	env.createOrg(sess, orgH)
	hooks := "/api/v1/orgs/" + orgH + "/webhooks"

	const token = "tok_URL_3c59dc048e88"
	refused := map[string]string{
		"a token where the port goes": "https://hooks.example.test:" + token + "/x",
		"no host":                     "https:///hook/" + token,
		"only a port":                 "https://:8443/hook/" + token,
		"port zero":                   "https://hooks.example.test:0/" + token,
		"a port past 65535":           "https://hooks.example.test:65536/" + token,
		"a space in the host":         "https://hooks example.test/" + token,
		"not https":                   "http://hooks.example.test/" + token,
	}
	refusal := func(method, path string, body map[string]any) (int, string, []byte) {
		t.Helper()
		res := env.do(sess, method, path, body)
		defer func() { _ = res.Body.Close() }()
		raw, _ := io.ReadAll(res.Body)
		var p struct {
			Errors []struct{ Field, Message string } `json:"errors"`
		}
		_ = json.Unmarshal(raw, &p)
		field := ""
		if len(p.Errors) == 1 {
			field = p.Errors[0].Field
		}
		return res.StatusCode, field, raw
	}
	for name, u := range refused {
		code, field, raw := refusal(http.MethodPost, hooks, map[string]any{"url": u, "events": []string{"version.published"}})
		if code != http.StatusUnprocessableEntity || field != "url" {
			t.Errorf("creating with %s: %d on %q, want 422 on url: %s", name, code, field, raw)
		}
		if strings.Contains(string(raw), token) {
			t.Errorf("creating with %s: the refusal repeats the address: %s", name, raw)
		}
	}

	var ids []string
	for _, u := range []string{"https://hooks.example.test/hook", "https://hooks.example.test:8443/hook"} {
		var created struct {
			Id string `json:"id"`
		}
		env.doJSON(sess, http.MethodPost, hooks, map[string]any{"url": u, "events": []string{"version.published"}}, &created, http.StatusCreated)
		ids = append(ids, created.Id)
	}

	for name, u := range refused {
		code, field, raw := refusal(http.MethodPatch, hooks+"/"+ids[0], map[string]any{"url": u})
		if code != http.StatusUnprocessableEntity || field != "url" {
			t.Errorf("changing to %s: %d on %q, want 422 on url: %s", name, code, field, raw)
		}
		if strings.Contains(string(raw), token) {
			t.Errorf("changing to %s: the refusal repeats the address: %s", name, raw)
		}
	}
	var got struct {
		Url string `json:"url"`
	}
	env.doJSON(sess, http.MethodGet, hooks+"/"+ids[0], nil, &got, http.StatusOK)
	if got.Url != "https://hooks.example.test/hook" {
		t.Errorf("after the refused changes the address is %q, want it unchanged", got.Url)
	}
}
