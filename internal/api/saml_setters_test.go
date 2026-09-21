package api_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
)

// TestSAMLSettersReplaceTheSets (agentry#414): SetSAMLReplayCache and
// SetSAMLRequestTracker are the seam a deployment that keeps the two sets
// somewhere else — a Redis, a sidecar — uses instead of the database. Both
// are honoured by the live routes, the landing that issues an AuthnRequest
// and the ACS that consumes it, not merely stored on the server. The sets'
// own behaviour, including the direction they fail in, is tested beside
// them in internal/auth/saml.
func TestSAMLSettersReplaceTheSets(t *testing.T) {
	replay := &stubReplayCache{}
	tracker := &stubRequestTracker{}
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetSAMLReplayCache(replay)
		s.SetSAMLRequestTracker(tracker)
	})
	owner := env.register("saml-set-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "samlset" + env.sfx
	env.createOrg(sess, orgH)
	env.verifyOrgDomain(orgH, "acme.example")
	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(idp.entityID, "https://acs-idp.test/sso", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)
	nameID := "saml-set-" + env.sfx + "@acme.example"
	env.seedMembership(orgH, env.registerEmail("saml-set-member", nameID), "member", "active")

	res := env.getNoRedirect(t, "/sso/"+orgH)
	location := res.Header.Get("Location")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("/sso/%s: got %d want 302", orgH, res.StatusCode)
	}
	requestID := authnRequestID(t, location)
	if !slices.Contains(tracker.tracked, requestID) {
		t.Fatalf("the landing tracked the AuthnRequest somewhere other than the injected tracker (%v)", tracker.tracked)
	}

	metadataURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"
	good := idp.signedResponseFor(t, metadataURL, acsURL, nameID, requestID, false)
	ok := env.postForm(t, acsURL, url.Values{"SAMLResponse": {good}})
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("the assertion answering the injected tracker's request: got %d want 200", ok.StatusCode)
	}
	if !slices.Contains(tracker.consumed, requestID) {
		t.Fatalf("the ACS consumed the request from somewhere other than the injected tracker (%v)", tracker.consumed)
	}
	if len(replay.seen) == 0 {
		t.Fatal("the ACS never asked the injected replay cache about the assertion")
	}
	// The injected cache is the whole of the deployment's replay defence:
	// the same assertion presented again is refused because it says so.
	again := env.postForm(t, acsURL, url.Values{"SAMLResponse": {good}})
	_ = again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replaying against the injected cache: got %d want 401", again.StatusCode)
	}
}

// stubReplayCache behaves as the in-memory cache does and records that the
// server consulted it.
type stubReplayCache struct{ seen []string }

func (c *stubReplayCache) SeenBefore(_ context.Context, id string, _ time.Time) bool {
	if slices.Contains(c.seen, id) {
		return true
	}
	c.seen = append(c.seen, id)
	return false
}

// stubRequestTracker behaves as the in-memory tracker does — an id it was
// told of is outstanding once — and records both sides.
type stubRequestTracker struct {
	tracked  []string
	consumed []string
}

func (t *stubRequestTracker) Track(_ context.Context, id string, _ time.Time) {
	t.tracked = append(t.tracked, id)
}

func (t *stubRequestTracker) Consume(_ context.Context, id string) bool {
	i := slices.Index(t.tracked, id)
	if i < 0 {
		return false
	}
	t.tracked = slices.Delete(t.tracked, i, i+1)
	t.consumed = append(t.consumed, id)
	return true
}
