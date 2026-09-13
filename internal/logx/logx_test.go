package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logx"
)

func line(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("not one JSON line: %v: %q", err, buf.String())
	}
	return m
}

// Every line written under a request carries the request's id, without the
// call site naming it; a line written outside a request carries none.
func TestRequestIDStampedFromContext(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf, Service: "agentryd", Role: "all", Version: "test"})
	ctx := logx.WithRequestID(context.Background(), "abc123def456")

	log.InfoContext(ctx, "inside", "k", "v")
	m := line(t, &buf)
	if m["request_id"] != "abc123def456" {
		t.Fatalf("request_id = %v, want the context's", m["request_id"])
	}
	for _, k := range []string{"service", "role", "version"} {
		if m[k] == nil {
			t.Errorf("%s missing from the line: %v", k, m)
		}
	}

	buf.Reset()
	log.Info("outside")
	if _, ok := line(t, &buf)["request_id"]; ok {
		t.Fatal("a line outside a request must not carry a request id")
	}

	// With() keeps the stamping: the derived logger is still the contract's.
	buf.Reset()
	log.With("sub", 1).WarnContext(ctx, "derived")
	if line(t, &buf)["request_id"] != "abc123def456" {
		t.Fatal("With() lost the request id stamping")
	}
}

// Every token kind the registry mints is masked wherever it appears: as a
// value, inside a message, inside an error, inside a nested map.
func TestTokensAreMaskedEverywhere(t *testing.T) {
	kinds := map[string]string{
		"pat": auth.PATPrefix, "session": auth.SessionPrefix, "verification": auth.VerificationPrefix,
		"scim": "agyscim_", "desktop grant": "agd_", "webhook secret": "whsec_", "csrf": "csrf_", "bare (oidc state, domain verification)": "",
	}
	for name, prefix := range kinds {
		tok, err := auth.NewToken(prefix)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		log := logx.New(logx.Options{W: &buf})
		log.Info("presented "+tok,
			"value", tok,
			"err", errors.New("bad token "+tok),
			"detail", map[string]any{"nested": map[string]any{"deep": "x " + tok + " y"}, "list": []any{tok}},
		)
		out := buf.String()
		if strings.Contains(out, tok) {
			t.Fatalf("%s token leaked into the line: %s", name, out)
		}
		if !strings.Contains(out, tok[:12]+"…"+logx.Redacted) {
			t.Fatalf("%s token not masked with its display prefix: %s", name, out)
		}
		if strings.Count(out, logx.Redacted) < 5 {
			t.Fatalf("%s: expected the token masked in msg, value, err, deep map and list; got %s", name, out)
		}
	}
	// The display prefix on its own (what the UI shows) is not a token and
	// stays readable.
	if got := logx.MaskTokens("agy_abcdefgh"); got != "agy_abcdefgh" {
		t.Fatalf("display prefix masked: %q", got)
	}
}

// A value under a secret-named key never reaches the line, whatever it is;
// keys that merely contain "key" — an object key, a host key fingerprint —
// are legitimate content and stay.
func TestSecretNamedKeysAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	log.Info("x",
		"token", "t", "Password", "p", "client_secret", "s", "Authorization", "Bearer x",
		"cookie", "c", "api_key", "k", "smtp_password", "sp",
		"object_key", "archive/1.tgz", "hostkey_fingerprint", "SHA256:abc", "public_key", "ssh-ed25519 AAAA",
		"detail", map[string]any{"token": "inner", "keep": "me"},
	)
	m := line(t, &buf)
	for _, k := range []string{"token", "Password", "client_secret", "Authorization", "cookie", "api_key", "smtp_password"} {
		if m[k] != logx.Redacted {
			t.Errorf("%s = %v, want %q", k, m[k], logx.Redacted)
		}
	}
	for k, want := range map[string]string{"object_key": "archive/1.tgz", "hostkey_fingerprint": "SHA256:abc", "public_key": "ssh-ed25519 AAAA"} {
		if m[k] != want {
			t.Errorf("%s = %v, want it kept", k, m[k])
		}
	}
	d := m["detail"].(map[string]any)
	if d["token"] != logx.Redacted || d["keep"] != "me" {
		t.Errorf("nested map: %v", d)
	}
}

// A string above MaxStringLen is cut so the whole line stays below Docker's
// 16 KB split; the marker says it was; the cut lands on a rune boundary; a
// panic's stack gets more room than any other value.
func TestLongValuesAreTruncated(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	big := strings.Repeat("a", 20000)
	log.Info("x", "err", errors.New(big), "v", big)
	if buf.Len() > 16*1024 {
		t.Fatalf("line is %d bytes; Docker splits above 16384", buf.Len())
	}
	m := line(t, &buf)
	v := m["v"].(string)
	if len(v) != logx.MaxStringLen+len("…[truncated]") || !strings.HasSuffix(v, "…[truncated]") {
		t.Fatalf("v = %d bytes, suffix %q", len(v), v[len(v)-14:])
	}

	// The panic line's shape: the stack keeps more than any other value and
	// the line still fits.
	buf.Reset()
	log.Error("panic in handler", "path", "/api/v1/x", "panic", big, "stack", strings.Repeat("s", 20000))
	if buf.Len() > 16*1024 {
		t.Fatalf("panic line is %d bytes; Docker splits above 16384", buf.Len())
	}
	if st := line(t, &buf)["stack"].(string); len(st) != logx.MaxStackLen+len("…[truncated]") {
		t.Fatalf("stack = %d bytes, want the stack bound", len(st))
	}

	buf.Reset()
	multibyte := strings.Repeat("é", 3000) // 6000 bytes; 4096 is not a rune boundary
	log.Info("x", "v", multibyte)
	got := line(t, &buf)["v"].(string)
	if strings.ContainsRune(got, '\uFFFD') || !strings.HasSuffix(got, "…[truncated]") {
		t.Fatalf("truncation split a rune: %q", got[len(got)-20:])
	}
}

func TestParseLevel(t *testing.T) {
	var buf bytes.Buffer
	logx.New(logx.Options{W: &buf, Level: "warn"}).Info("dropped")
	if buf.Len() != 0 {
		t.Fatal("info written at level warn")
	}
	logx.New(logx.Options{W: &buf, Level: "nonsense"}).Info("kept")
	if buf.Len() == 0 {
		t.Fatal("an unknown level must mean info, as it always has")
	}
}
