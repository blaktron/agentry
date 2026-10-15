package api_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// The image proxy's only gate is its signature, so its key must never be a
// value the open-source tree gives away. With no sealing key configured —
// which dev mode permits — a key derived from a public constant would let
// anyone sign any destination, so a dev-mode server with no sealing key
// signs with a per-process random key.

// publishReadmeImage publishes an agent whose README carries one image and
// returns the src the renderer produced for it (empty when the renderer
// left a placeholder).
func publishReadmeImage(t *testing.T, env *testEnv, handle, name, image string) string {
	t.Helper()
	sess := env.login(handle)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": handle, "name": name, "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub-"+name, "agent:publish", "agent:read")
	files := map[string]string{
		"agent.yaml": skillYAML(handle, name, "1.0.0"),
		"README.md":  "# " + name + "\n\n![Logo](" + image + ")\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
	if status, body := env.uploadVersionCLI(handle, name, pat, files); status != http.StatusAccepted {
		t.Fatalf("upload: %d %s", status, body)
	}
	env.waitStatus(handle, name, "1.0.0", "published")
	res := env.do(sess, http.MethodGet, "/api/v1/agents/"+handle+"/"+name+"/readme", nil)
	html, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	parts := strings.Split(string(html), `src="`)
	if len(parts) < 2 {
		return ""
	}
	src := parts[1][:strings.IndexByte(parts[1], '"')]
	return src
}

func TestImageProxyKeyIsNeverAConstant(t *testing.T) {
	const dest = "https://images.example/logo.png"
	// The signature the public constant would produce for dest.
	constant := sha256.Sum256([]byte("img-proxy:"))
	mac := hmac.New(sha256.New, constant[:])
	mac.Write([]byte(dest))
	forged := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
	ref := base64.RawURLEncoding.EncodeToString([]byte(dest))

	var sigs []string
	for i, h := range []string{"imgkey-a", "imgkey-b"} {
		env := newTestEnvCfg(t, func(c *config.Config) {
			c.BaseURL = "https://registry.test"
			c.DevMode = true
			c.Auth.SealingKey = "" // the configuration the constant key came from
		})
		user := env.register(h)
		env.verifyEmail(user)
		src := publishReadmeImage(t, env, user, "pics", dest)
		if !strings.Contains(src, "/api/v1/img/") {
			t.Fatalf("server %d: the renderer must still proxy an https image: %q", i, src)
		}
		sigs = append(sigs, strings.Split(strings.SplitAfter(src, "/api/v1/img/")[1], "/")[0])
		res := env.do(anonymous, http.MethodGet, "/api/v1/img/"+forged+"/"+ref, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("server %d: a signature under the public constant was accepted: %d", i, res.StatusCode)
		}
	}
	if sigs[0] == sigs[1] {
		t.Fatalf("two servers with no sealing key signed %s identically (%s): the key is derivable", dest, sigs[0])
	}
	if sigs[0] == forged || sigs[1] == forged {
		t.Fatal("a server signed with the public constant")
	}
}

// A plain-http image is left a placeholder: the proxy fetches https only, so
// a signed destination can never be a cleartext GET of a publisher's choosing.
func TestImageProxyRefusesPlainHTTP(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = "https://registry.test" })
	user := env.register("imghttp")
	env.verifyEmail(user)
	src := publishReadmeImage(t, env, user, "pics", "http://images.example/logo.png")
	if strings.Contains(src, "/api/v1/img/") {
		t.Fatalf("an http image was signed for the proxy: %q", src)
	}
}
