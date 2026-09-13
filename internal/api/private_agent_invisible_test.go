package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
)

// TestPrivateAgentInvisibleToNonReaders pins the rule of agentry#313 (the
// operator, 2026-09-13): nobody but the private agent's readers can learn
// that a registry hosts it. Every by-name route answers a caller who cannot
// read the agent exactly as it answers a name that does not exist — 404,
// never the 401 that would say "sign in and this exists" — anonymous or
// signed in as a stranger, for reads and for writes; the advisories
// `?affecting=` path is the same gate; the owner still sees everything.
func TestPrivateAgentInvisibleToNonReaders(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("priv-owner")
	env.verifyEmail(owner)
	ownerSess := env.login(owner)
	stranger := env.register("priv-stranger")
	env.verifyEmail(stranger)
	strangerSess := env.login(stranger)
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "secret", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)

	// The problem document, less the instance path that names the request.
	get := func(c caller, path string) (int, map[string]any) {
		res := env.do(c, http.MethodGet, path, nil)
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		var doc map[string]any
		_ = json.Unmarshal(b, &doc)
		delete(doc, "instance")
		return res.StatusCode, doc
	}
	missingStatus, missingBody := get(anonymous, "/api/v1/agents/"+owner+"/no-such-agent")
	if missingStatus != http.StatusNotFound {
		t.Fatalf("missing agent: got %d", missingStatus)
	}

	for _, c := range []struct {
		name string
		c    caller
	}{{"anonymous", anonymous}, {"stranger", strangerSess}} {
		for _, path := range []string{
			"/api/v1/agents/" + owner + "/secret",
			"/api/v1/agents/" + owner + "/secret/versions",
			"/api/v1/advisories?affecting=" + owner + "/secret",
		} {
			st, body := get(c.c, path)
			if st != http.StatusNotFound {
				t.Fatalf("%s GET %s: got %d, want the missing agent's 404", c.name, path, st)
			}
			if !reflect.DeepEqual(body, missingBody) {
				t.Fatalf("%s GET %s: the 404 differs from a missing agent's:\n%v\nvs\n%v", c.name, path, body, missingBody)
			}
		}
		// A write on a private agent by a non-reader is a 404 too, not a
		// 401 or 403 that would confirm the name.
		res := env.do(c.c, http.MethodPatch, "/api/v1/agents/"+owner+"/secret", map[string]any{"summary": "x"})
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s PATCH private agent: got %d, want 404", c.name, res.StatusCode)
		}
	}

	// The namespace listing agrees with the by-name route: the stranger
	// and the anonymous caller see no private name in it, the owner does.
	list := func(c caller) []string {
		var rows []struct {
			Name string `json:"name"`
		}
		env.doJSON(c, http.MethodGet, "/api/v1/agents?namespace="+owner, nil, &rows, http.StatusOK)
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.Name)
		}
		return names
	}
	for _, c := range []caller{anonymous, strangerSess} {
		for _, n := range list(c) {
			if n == "secret" {
				t.Fatalf("%s: the namespace listing names the private agent", c.name)
			}
		}
	}
	if names := list(ownerSess); len(names) == 0 || names[0] != "secret" {
		t.Fatalf("owner listing: %v", names)
	}

	// The owner reads it, and its (empty) advisory list.
	if st, _ := get(ownerSess, "/api/v1/agents/"+owner+"/secret"); st != http.StatusOK {
		t.Fatalf("owner GET: got %d", st)
	}
	if st, _ := get(ownerSess, "/api/v1/advisories?affecting="+owner+"/secret"); st != http.StatusOK {
		t.Fatalf("owner advisories: got %d", st)
	}

	// A public agent keeps the conventional answers: anonymous reads it,
	// and an anonymous write is a 401 (the name is no secret).
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner, "name": "open", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if st, _ := get(anonymous, "/api/v1/agents/"+owner+"/open"); st != http.StatusOK {
		t.Fatalf("anonymous GET public: got %d", st)
	}
	res := env.do(anonymous, http.MethodPatch, "/api/v1/agents/"+owner+"/open", map[string]any{"summary": "x"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous PATCH public: got %d, want 401", res.StatusCode)
	}
}
