package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
)

// The organization-gate seam: an extension route that names an
// organization asks the core whether the organization is there to be read
// or acted on, and gets the answer the core's own routes give — absent when
// it is suspended or erased, readable but frozen in its decommission hold —
// without reading orgs.state itself. A probe extension answers 404 where
// the seam says the organization is not readable, as an extension's own
// route must, and reports what the seam said otherwise.
func TestOrgGateSeamAnswersAsTheCoreDoes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /gate/{id}", func(w http.ResponseWriter, r *http.Request) {
				id, err := uuid.Parse(r.PathValue("id"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				readable, err := s.OrgReadable(r.Context(), id)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if !readable {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writable, err := s.OrgWritable(r.Context(), id)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]bool{"writable": writable})
			})
		})
	})
	ctx := context.Background()

	admin := env.seedCaller("og-founder")
	staff := env.register("og-staff")
	env.makePlatformStaff(t, staff)
	staffSess := env.login(staff)
	org := "og-org" + env.sfx
	orgID := env.createOrg(admin, org)

	// ask reports the probe's status and, for a 200, whether the seam
	// allows acting on the organization.
	ask := func(id string) (int, bool) {
		t.Helper()
		res := env.do(admin, http.MethodGet, "/api/v1/x/probe/gate/"+id, nil)
		var body struct {
			Writable bool `json:"writable"`
		}
		if res.StatusCode == http.StatusOK {
			decodeInto(t, res, &body)
		} else {
			_ = res.Body.Close()
		}
		return res.StatusCode, body.Writable
	}
	state := func(s string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = $2 WHERE id = $1`, orgID, s); err != nil {
			t.Fatal(err)
		}
	}

	if code, writable := ask(orgID); code != http.StatusOK || !writable {
		t.Fatalf("an active organization: %d writable=%v, want 200 writable", code, writable)
	}

	// Suspended by staff through the door: absent, as the core's routes
	// answer it.
	env.doJSON(staffSess, http.MethodPost, "/api/v1/orgs/"+org+"/suspend", map[string]any{"reason": "the gate seam's test"}, nil, http.StatusOK)
	if code, _ := ask(orgID); code != http.StatusNotFound {
		t.Fatalf("a suspended organization: %d, want 404", code)
	}
	if res := env.do(admin, http.MethodGet, "/api/v1/orgs/"+org, nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("the core's own read of a suspended organization: %d, want 404 (the seam must agree)", res.StatusCode)
	} else {
		_ = res.Body.Close()
	}
	env.doJSON(staffSess, http.MethodPost, "/api/v1/orgs/"+org+"/reinstate", nil, nil, http.StatusOK)
	if code, writable := ask(orgID); code != http.StatusOK || !writable {
		t.Fatalf("a reinstated organization: %d writable=%v, want 200 writable", code, writable)
	}

	// In its decommission hold the organization still reads and nothing
	// else is permitted.
	state("decommissioning")
	if code, writable := ask(orgID); code != http.StatusOK || writable {
		t.Fatalf("an organization in its hold: %d writable=%v, want 200 and not writable", code, writable)
	}

	// Erased, or never there: absent, never an error.
	state("decommissioned")
	if code, _ := ask(orgID); code != http.StatusNotFound {
		t.Fatalf("an erased organization: %d, want 404", code)
	}
	if code, _ := ask(uuid.NewString()); code != http.StatusNotFound {
		t.Fatalf("an organization that does not exist: %d, want 404", code)
	}
}
