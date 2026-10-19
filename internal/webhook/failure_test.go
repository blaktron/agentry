package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An endpoint's address can carry a secret in its path or query. A failed
// delivery's text is logged, stored on the delivery row and returned to the
// queue, so it must name the host and nothing after it.
const (
	pathToken  = "tok_PATH_0a1b2c3d4e5f"
	queryToken = "tok_QUERY_9z8y7x6w5v"
	userToken  = "tok_USER_pw5555"
)

func failureTexts(t *testing.T) map[string]string {
	t.Helper()
	endpoints := map[string]string{
		"a refused address":    "https://10.0.0.1/hooks/" + pathToken + "?key=" + queryToken,
		"a refused name":       "https://localhost:8443/services/" + pathToken + "/send?auth=" + queryToken + "#frag_" + pathToken,
		"user information":     "https://svc:" + userToken + "@10.0.0.1/" + pathToken + "?k=" + queryToken,
		"an escaped path":      "https://10.0.0.1/a%2F" + pathToken + "?q=" + queryToken + "%20x",
		"a query without path": "https://10.0.0.1?token=" + queryToken,
	}
	out := map[string]string{}
	client := NewHTTPClient(Guard{}, nil)
	for name, ep := range endpoints {
		req, err := http.NewRequest(http.MethodPost, ep, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = client.Do(req)
		if err == nil {
			t.Fatalf("%s: the guard let %s through", name, ep)
		}
		out[name] = deliveryFailure(err, ep)
	}

	// A transport failure past the guard: nothing listening.
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	ep := ts.URL + "/hooks/" + pathToken + "?key=" + queryToken
	ts.Close()
	_, err := NewHTTPClient(Guard{AllowLoopback: true}, tlsTrusting(ts)).Post(ep, "application/json", strings.NewReader("{}"))
	if err == nil {
		t.Fatal("a closed server answered")
	}
	out["a refused connection"] = deliveryFailure(err, ep)

	// A deadline.
	release := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(release)
	ep = slow.URL + "/hooks/" + pathToken + "?key=" + queryToken
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader("{}"))
	if _, err = NewHTTPClient(Guard{AllowLoopback: true}, tlsTrusting(slow)).Do(req); err == nil {
		t.Fatal("a slow server answered")
	}
	out["a deadline"] = deliveryFailure(err, ep)

	// A request that cannot be built.
	bad := "https://10.0.0.1/hooks/" + pathToken + "\x7f?key=" + queryToken
	_, err = http.NewRequest(http.MethodPost, bad, nil)
	if err == nil {
		t.Fatal("a control character was accepted in a URL")
	}
	out["an address that does not parse"] = deliveryFailure(err, bad)
	out["an address with a bad port"] = func() string {
		ep := "https://10.0.0.1:80x/hooks/" + pathToken + "?key=" + queryToken
		_, err := http.NewRequest(http.MethodPost, ep, nil)
		if err == nil {
			t.Fatal("a bad port was accepted")
		}
		return deliveryFailure(err, ep)
	}()

	// An error that is not a URL error but wraps the address in its text.
	ep = "https://10.0.0.1/hooks/" + pathToken + "?key=" + queryToken
	out["a plain error naming the address"] = deliveryFailure(errors.New("proxy said no to "+ep), ep)
	return out
}

func TestADeliveryFailureNamesTheHostNeverThePathOrQuery(t *testing.T) {
	for name, got := range failureTexts(t) {
		for _, secret := range []string{pathToken, queryToken, userToken, "frag_"} {
			if strings.Contains(got, secret) {
				t.Errorf("%s: %q carries %q", name, got, secret)
			}
		}
		for _, piece := range []string{"/hooks", "/services", "/send", "?key", "?auth", "?token", "svc:", "%2F"} {
			if strings.Contains(got, piece) {
				t.Errorf("%s: %q carries %q", name, got, piece)
			}
		}
	}
}

func TestADeliveryFailureStillSaysWhatWentWrong(t *testing.T) {
	got := failureTexts(t)
	for name, want := range map[string]string{
		"a refused address":    "blocked non-public address",
		"a refused connection": "connection refused",
		"a deadline":           "deadline exceeded",
	} {
		if !strings.Contains(got[name], want) {
			t.Errorf("%s: %q does not say %q", name, got[name], want)
		}
	}
	for _, name := range []string{"a refused address", "a refused name"} {
		if !strings.Contains(got[name], "https://") {
			t.Errorf("%s: %q names no host", name, got[name])
		}
	}
	if !strings.Contains(got["a refused connection"], "127.0.0.1") {
		t.Errorf("a refused connection: %q names no host", got["a refused connection"])
	}
}
