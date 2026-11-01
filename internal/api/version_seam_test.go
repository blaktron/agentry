package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
)

// The version seam: an extension asks the core about one version of an
// agent and gets its status, the agent's quarantine, and the advisories
// that name it with their fix, answered only where the core's own version
// route answers the same caller.
func TestVersionSeamAnswersAsTheVersionRouteDoes(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /version/{ns}/{name}/{version}", func(w http.ResponseWriter, r *http.Request) {
				st, ok, err := s.AgentVersion(r.Context(), api.PrincipalFrom(r.Context()), r.PathValue("ns"), r.PathValue("name"), r.PathValue("version"))
				switch {
				case err != nil:
					w.WriteHeader(http.StatusInternalServerError)
				case !ok:
					w.WriteHeader(http.StatusNotFound)
				default:
					type adv struct{ Affected, FixedIn string }
					out := struct {
						Status, Quarantine string
						Advisories         []adv
					}{Status: string(st.Status), Quarantine: st.Agent.QuarantineState, Advisories: []adv{}}
					for _, a := range st.Advisories {
						out.Advisories = append(out.Advisories, adv{a.AffectedVersions, a.FixedIn})
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(out)
				}
			})
		})
	})
	ctx := context.Background()
	owner := env.seedCaller("vs-owner")
	outsider := env.seedCaller("vs-outsider")
	for _, a := range []struct{ name, visibility string }{{"pub", "public"}, {"priv", "private"}} {
		env.doJSON(owner, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": owner.name, "name": a.name, "visibility": a.visibility}, nil, http.StatusCreated)
	}
	seed := func(name, version, status string) {
		t.Helper()
		if _, err := env.st.Pool().Exec(ctx,
			`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source, status)
			 SELECT gen_random_uuid(), a.id, $3, '{}', '{}', 'stable', h.id, 'cli-upload', $4
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`,
			owner.name, name, version, status); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"pub", "priv"} {
		seed(name, "1.0.0", "published")
		seed(name, "1.1.0", "yanked")
		seed(name, "2.0.0", "published")
		if _, err := env.st.Pool().Exec(ctx,
			`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
			 SELECT gen_random_uuid(), a.id, '<2.0.0', 'high', 'before 2.0.0', now()
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`, owner.name, name); err != nil {
			t.Fatal(err)
		}
	}

	type answer struct {
		Status, Quarantine string
		Advisories         []struct{ Affected, FixedIn string }
	}
	ask := func(c caller, name, version string) (int, answer) {
		t.Helper()
		res := env.do(c, http.MethodGet, "/api/v1/x/probe/version/"+owner.name+"/"+name+"/"+version, nil)
		route := env.do(c, http.MethodGet, "/api/v1/agents/"+owner.name+"/"+name+"/versions/"+version, nil)
		_ = route.Body.Close()
		if (res.StatusCode == 200) != (route.StatusCode == 200) {
			t.Errorf("%s on %s@%s: the seam says %d, the version route says %d", c.name, name, version, res.StatusCode, route.StatusCode)
		}
		var a answer
		if res.StatusCode == 200 {
			decodeInto(t, res, &a)
		} else {
			_ = res.Body.Close()
		}
		return res.StatusCode, a
	}

	// The pinned version is published, named by the advisory, and fixed in 2.0.0.
	code, a := ask(owner, "pub", "1.0.0")
	if code != 200 || a.Status != "published" || a.Quarantine != "none" || len(a.Advisories) != 1 || a.Advisories[0].Affected != "<2.0.0" || a.Advisories[0].FixedIn != "2.0.0" {
		t.Fatalf("the owner on pub@1.0.0: %d %+v", code, a)
	}
	// Anyone who reads a public agent reads its versions the same way.
	if code, a := ask(outsider, "pub", "1.0.0"); code != 200 || len(a.Advisories) != 1 {
		t.Errorf("an outsider on pub@1.0.0: %d %+v", code, a)
	}
	// A yanked version says so, and the advisory names it too.
	if code, a := ask(owner, "pub", "1.1.0"); code != 200 || a.Status != "yanked" || len(a.Advisories) != 1 || a.Advisories[0].FixedIn != "2.0.0" {
		t.Errorf("the owner on pub@1.1.0: %d %+v", code, a)
	}
	// The fixed version is named by nothing.
	if code, a := ask(owner, "pub", "2.0.0"); code != 200 || len(a.Advisories) != 0 {
		t.Errorf("the owner on pub@2.0.0: %d %+v", code, a)
	}
	// A private agent is absent to an outsider; a version that does not
	// exist is absent to its owner; neither is an error.
	if code, _ := ask(outsider, "priv", "1.0.0"); code != 404 {
		t.Errorf("an outsider on a private agent's version: %d, want 404", code)
	}
	if code, _ := ask(owner, "pub", "9.9.9"); code != 404 {
		t.Errorf("a version that does not exist: %d, want 404", code)
	}
	if code, _ := ask(anonymous, "priv", "1.0.0"); code != 404 {
		t.Errorf("anonymous on a private agent's version: %d, want 404", code)
	}
	// The agent's own quarantine is read beside the version's status.
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agents SET quarantine_state = 'quarantined' WHERE name = 'pub' AND namespace_id = (SELECT id FROM handles WHERE handle = $1)`, owner.name); err != nil {
		t.Fatal(err)
	}
	if code, a := ask(owner, "pub", "1.0.0"); code != 200 || a.Quarantine != "quarantined" {
		t.Errorf("a quarantined agent: %d %+v", code, a)
	}
}
