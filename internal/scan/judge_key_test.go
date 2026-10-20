package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// judgeKeyCase is one provider that sends the platform's key over HTTP.
type judgeKeyCase struct {
	name  string
	judge func(base, key string) JudgeProvider
}

func judgeKeyCases() []judgeKeyCase {
	return []judgeKeyCase{
		{"openai", func(base, key string) JudgeProvider {
			return NewHTTPJudge(JudgeConfig{Provider: "openai", BaseURL: base, APIKey: key})
		}},
		{"anthropic", func(base, key string) JudgeProvider {
			return NewHTTPJudge(JudgeConfig{Provider: "anthropic", BaseURL: base, APIKey: key})
		}},
		{"classifier", func(base, key string) JudgeProvider {
			return NewClassifierJudge(JudgeConfig{Provider: "classifier", BaseURL: base + "/classify", APIKey: key})
		}},
	}
}

// A redirect from the configured address is an answer, not a new address to
// send the key to: neither another host nor another path on the same host
// receives the request.
func TestHTTPJudgesRefuseRedirects(t *testing.T) {
	const key = "sk-redirect-test-key-0123456789"
	for _, c := range judgeKeyCases() {
		t.Run(c.name, func(t *testing.T) {
			var elsewhere, moved atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				elsewhere.Add(1)
				http.Error(w, "should not be reached", http.StatusTeapot)
			}))
			defer other.Close()

			for _, target := range []string{"other host", "same host"} {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/moved" {
						moved.Add(1)
						http.Error(w, "should not be reached", http.StatusTeapot)
						return
					}
					to := "/moved"
					if target == "other host" {
						to = other.URL + "/v1/messages"
					}
					http.Redirect(w, r, to, http.StatusFound)
				}))
				_, err := c.judge(srv.URL, key).Judge(context.Background(), judgeTestContent())
				srv.Close()
				if err == nil {
					t.Fatalf("%s: a redirect was answered as a verdict", target)
				}
				if !strings.Contains(err.Error(), "302") {
					t.Errorf("%s: error does not name the redirect: %v", target, err)
				}
			}
			if n := elsewhere.Load(); n != 0 {
				t.Errorf("the request, key and all, was sent to another host %d time(s)", n)
			}
			if n := moved.Load(); n != 0 {
				t.Errorf("the request, key and all, followed a redirect on the same host %d time(s)", n)
			}
		})
	}
}

// A provider that echoes the request's key back in a response body does not
// get it into the judge's error, whether the echo sits at the start of the
// body, at the edge of the excerpt the error keeps, or in a label.
func TestHTTPJudgesRedactAnEchoedKey(t *testing.T) {
	const key = "sk-echoed-test-key-ABCDEFGHIJKLMNOP"
	bodies := map[string]struct {
		status int
		body   string
	}{
		"error body":       {http.StatusUnauthorized, `{"error":"invalid api key ` + key + `"}`},
		"excerpt boundary": {http.StatusUnauthorized, strings.Repeat("x", 190) + key + " rejected"},
		"echoed label":     {http.StatusOK, `[{"label":"` + key + `","score":0.9}]`},
	}
	for _, c := range judgeKeyCases() {
		for name, b := range bodies {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(b.status)
					_, _ = w.Write([]byte(b.body))
				}))
				defer srv.Close()
				_, err := c.judge(srv.URL, key).Judge(context.Background(), judgeTestContent())
				if err == nil {
					t.Fatal("a refused or malformed answer was taken as a verdict")
				}
				for _, part := range []string{key, key[:8], key[len(key)-8:]} {
					if strings.Contains(err.Error(), part) {
						t.Fatalf("the error carries the key (%q): %v", part, err)
					}
				}
			})
		}
	}
}
