package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/internal/auth"
)

// TestUnactivated: an unconfirmed real address is unactivated; a confirmed
// one, or a placeholder no link can reach, is not.
func TestUnactivated(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		verified bool
		email    string
		want     bool
	}{
		{false, "ada@example.test", true},
		{true, "ada@example.test", false},
		{false, "ada@github.social.local", false},
		{false, "ADA@GITHUB.SOCIAL.LOCAL", false},
		// The placeholder is the address's end, not a part of it: a real
		// address that merely mentions it is unconfirmed like any other.
		{false, "ada@github.social.local.example.test", true},
		{false, "ada.social.local@example.test", true},
		{false, "", true},
	} {
		at := &now
		if !tc.verified {
			at = nil
		}
		if got := auth.Unactivated(at, tc.email); got != tc.want {
			t.Errorf("Unactivated(verified=%v, %q) = %v, want %v", tc.verified, tc.email, got, tc.want)
		}
	}
}

// unactivatedOperations are the operations an unactivated account may call
// with a writing method. Every other
// writing operation in the spec is refused, so a new one starts refused.
var unactivatedOperations = map[string]bool{
	"verifyEmail": true, "logout": true, "exchangeDesktopCode": true,
	"sendEmailVerification": true, "updateCurrentUser": true,
	"deleteCurrentUser": true, "clearCurrentUserData": true,
	"revokeOtherUserSessions": true, "revokeUserSession": true, "clearTrustedDevices": true,
	"revokeToken": true, "removeSshKey": true, "createDesktopGrant": true,
	"acceptInvitation": true,
}

// TestUnactivatedWritesFollowTheSpec holds the gate's list to the spec, one
// operation at a time.
func TestUnactivatedWritesFollowTheSpec(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	seen := map[string]bool{}
	for path, ops := range spec.Paths {
		concrete := "/api/v1" + param.ReplaceAllString(path, "x1")
		for method, raw := range ops {
			m := strings.ToUpper(method)
			fields, _ := raw.(map[string]any)
			opID, _ := fields["operationId"].(string)
			op := struct{ OperationID string }{opID}
			switch m {
			case http.MethodGet:
				if !unactivatedMayWrite(m, concrete) {
					t.Errorf("GET %s (%s) refused: reads are never refused", path, op.OperationID)
				}
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				want := unactivatedOperations[op.OperationID]
				seen[op.OperationID] = true
				if got := unactivatedMayWrite(m, concrete); got != want {
					t.Errorf("%s %s (%s): allowed %v, want %v", m, path, op.OperationID, got, want)
				}
			}
		}
	}
	for id := range unactivatedOperations {
		if !seen[id] {
			t.Errorf("the allowed operation %s is not a writing operation in the spec", id)
		}
	}
	// Reads of every kind pass, whatever the path.
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		for _, p := range []string{"/api/v1/user", "/api/v1/user/tokens", "/api/v1/orgs/acme/members", "/ui/account", "/"} {
			if !unactivatedMayWrite(method, p) {
				t.Errorf("%s %s refused: reads are never refused", method, p)
			}
		}
	}
	// A trailing slash names the same route, and a path segment that is
	// empty or missing is not a token id.
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/api/v1/user/email-verification/", true},
		{http.MethodDelete, "/api/v1/user/tokens/x1/", true},
		{http.MethodDelete, "/api/v1/user/tokens//", false},
		{http.MethodDelete, "/api/v1/user/tokens", false},
		{http.MethodDelete, "/api/v1/user/tokens/x1/extra", false},
		{http.MethodDelete, "/api/v1/user/sessions/x1", true},
		{http.MethodDelete, "/api/v1/user/sessions/x1/extra", false},
		{http.MethodDelete, "/api/v1/user/trusted-devices/x1", false},
		{http.MethodPut, "/api/v1/user/email-verification", false},
		{http.MethodPost, "/api/v1/user/email-verificationx", false},
		{http.MethodPost, "api/v1/user/email-verification", false},
	} {
		if got := unactivatedMayWrite(tc.method, tc.path); got != tc.want {
			t.Errorf("unactivatedMayWrite(%s, %q) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
	// A trailing /* matches what lies under the prefix and nothing beside it.
	for path, want := range map[string]bool{"/a/b": true, "/a/b/c": true, "/a": false, "/a/": true, "/ab/c": false, "/b/a/c": false} {
		if got := pathMatches("/a/*", path); got != want {
			t.Errorf("pathMatches(/a/*, %q) = %v, want %v", path, got, want)
		}
	}
	// Outside the generated surface: an extension's writes are refused.
	for _, p := range []string{"/api/v1/x/billing/checkout", "/api/v1/x/billing/low-balance/ack", "/ui/account", "/api/v1/userx/delete"} {
		if unactivatedMayWrite(http.MethodPost, p) {
			t.Errorf("POST %s allowed", p)
		}
	}
}

// TestRefuseUnactivated: only an unactivated principal is refused, with the
// problem type the site recognizes.
func TestRefuseUnactivated(t *testing.T) {
	for _, tc := range []struct {
		name    string
		p       *auth.Principal
		method  string
		path    string
		refused bool
	}{
		{"unactivated star", &auth.Principal{Unactivated: true}, http.MethodPut, "/api/v1/user/stars/acme/agent", true},
		{"unactivated read", &auth.Principal{Unactivated: true}, http.MethodGet, "/api/v1/user", false},
		{"unactivated resend", &auth.Principal{Unactivated: true}, http.MethodPost, "/api/v1/user/email-verification", false},
		{"activated star", &auth.Principal{EmailVerified: true}, http.MethodPut, "/api/v1/user/stars/acme/agent", false},
		{"anonymous", &auth.Principal{Anonymous: true}, http.MethodPost, "/api/v1/auth/desktop/exchange", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if got := refuseUnactivated(w, r, tc.p); got != tc.refused {
				t.Fatalf("refused %v, want %v", got, tc.refused)
			}
			if !tc.refused {
				return
			}
			var body struct {
				Type   string `json:"type"`
				Status int    `json:"status"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != http.StatusForbidden || !strings.HasSuffix(body.Type, "account-unactivated") {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
}
