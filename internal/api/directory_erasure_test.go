package api_test

// Erasure deletes the sign-in account in the directory service too
// (agentry#20): exactly the account with the erased email, never a
// superuser or a service account sharing it, and the outcome is audited.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

func TestErasureDeletesDirectoryAccount(t *testing.T) {
	var deleted []string
	var lookups []string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer idp-admin-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
			email := r.URL.Query().Get("email")
			lookups = append(lookups, email)
			// authentik's filter is a substring match; hand back the exact
			// account, a superuser with the same address, a service account,
			// and a near-miss — only the first may be deleted.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
				{"pk": 41, "email": email, "type": "internal", "is_superuser": false},
				{"pk": 1, "email": email, "type": "internal", "is_superuser": true},
				{"pk": 77, "email": email, "type": "internal_service_account", "is_superuser": false},
				{"pk": 99, "email": "x" + email, "type": "internal", "is_superuser": false},
			}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer idp.Close()

	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.IdPAdminURL = idp.URL
		c.Auth.IdPAdminToken = "idp-admin-token"
	})
	user := env.register("dir-erase")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)

	if len(lookups) != 1 || !strings.HasPrefix(lookups[0], user+"@") {
		t.Fatalf("directory lookups = %v, want one for the erased address", lookups)
	}
	if len(deleted) != 1 || deleted[0] != "/api/v3/core/users/41/" {
		t.Fatalf("directory deletes = %v, want exactly the matching non-superuser account", deleted)
	}

	var outcome string
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'directoryErasure' FROM audit_events WHERE action = 'user.directory_erase' ORDER BY occurred_at DESC LIMIT 1`).Scan(&outcome)
	if err != nil || outcome != "deleted" {
		t.Fatalf("audit directoryErasure = %q (%v), want deleted", outcome, err)
	}
}

func TestErasureWithoutDirectoryIsAudited(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("dir-none")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)
	var outcome string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'directoryErasure' FROM audit_events WHERE action = 'user.directory_erase' ORDER BY occurred_at DESC LIMIT 1`).Scan(&outcome); err != nil || outcome != "not-configured" {
		t.Fatalf("audit directoryErasure = %q (%v), want not-configured", outcome, err)
	}
}
