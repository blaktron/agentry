package ui

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The account page consumes the API's text value; it must never promote a
// display name to markup, even when an upstream identity accepts that text.
func TestAccountHTMLDisplayNameIsText(t *testing.T) {
	base := fakeAPI(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("agentry_session"); r.Method == http.MethodGet && r.URL.Path == "/api/v1/user" && err == nil && c.Value == fakeSession {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "u1", "handle": "chris", "email": "c@example.test", "emailVerified": true,
				"displayName": "<img src=x onerror=alert(1)>",
			})
			return
		}
		base.ServeHTTP(w, r)
	})
	w := get(newUI(t, Options{API: api}), "/ui/account", sessCookie, csrfCookieV)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<img src=x onerror=alert(1)>") || !strings.Contains(w.Body.String(), "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatalf("account display name is not text: status %d, body %s", w.Code, w.Body.String())
	}
}
