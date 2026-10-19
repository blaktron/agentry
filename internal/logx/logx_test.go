package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/url"
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
	// Each identity field carries its own value, and one left unset is not
	// written as an empty field.
	if m["service"] != "agentryd" || m["role"] != "all" || m["version"] != "test" {
		t.Errorf("identity fields = %v %v %v, want agentryd all test", m["service"], m["role"], m["version"])
	}
	var bare bytes.Buffer
	logx.New(logx.Options{W: &bare}).Info("no identity")
	for _, k := range []string{"service", "role", "version"} {
		if v, ok := line(t, &bare)[k]; ok {
			t.Errorf("%s = %v written although the option was empty", k, v)
		}
	}
	var partial bytes.Buffer
	logx.New(logx.Options{W: &partial, Role: "worker"}).Info("role only")
	if pm := line(t, &partial); pm["role"] != "worker" || pm["service"] != nil || pm["version"] != nil {
		t.Errorf("role-only identity = %v", pm)
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

	// So does WithGroup(): the id is still on the line, wherever the group
	// puts it.
	buf.Reset()
	log.WithGroup("g").InfoContext(ctx, "grouped")
	if !strings.Contains(buf.String(), `"request_id":"abc123def456"`) {
		t.Fatalf("WithGroup() lost the request id stamping: %s", buf.String())
	}

	// The lookup itself: an empty context, and no context at all, carry no id.
	if got := logx.RequestIDFrom(context.Background()); got != "" {
		t.Fatalf("RequestIDFrom(background) = %q", got)
	}
	var none context.Context
	if got := logx.RequestIDFrom(none); got != "" {
		t.Fatalf("RequestIDFrom(nil) = %q", got)
	}
	if got := logx.RequestIDFrom(ctx); got != "abc123def456" {
		t.Fatalf("RequestIDFrom(ctx) = %q", got)
	}
}

// Every token kind the registry mints is masked wherever it appears: as a
// value, inside a message, inside an error, inside a nested map.
func TestTokensAreMaskedEverywhere(t *testing.T) {
	kinds := map[string]string{
		"pat": auth.PATPrefix, "session": auth.SessionPrefix, "verification": auth.VerificationPrefix,
		"desktop grant": "agd_", "webhook secret": "whsec_", "csrf": "csrf_", "bare (oidc state, domain verification)": "",
		// Pinned rather than left to the regex's shape: tokenRE's `agy[a-z]*_`
		// happens to cover both of these, and "happens to" is not a guarantee
		// anyone would notice breaking.
		"trusted device": auth.TrustedDevicePrefix, "invitation": auth.InvitePrefix,
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
			// A byte slice is encoded by the JSON handler as base64, which no
			// token pattern matches; it is read as the text it holds.
			"body", []byte("Authorization failed for "+tok),
			"raw", json.RawMessage(`{"seen":"`+tok+`"}`),
			"batch", [][]byte{[]byte(tok)},
			// A secret-named key is recognised in camelCase and kebab-case.
			"signingKey", tok,
			"detail2", map[string]any{"clientSecret": tok, "X-Api-Key": tok},
			// A key that is empty because a caller's variable was, and a token
			// that a cache key or a file name builds into a longer word.
			"", tok,
			"cache", "sess_"+tok+"_1",
		)
		out := buf.String()
		if strings.Contains(out, tok) {
			t.Fatalf("%s token leaked into the line: %s", name, out)
		}
		if !strings.Contains(out, tok[:12]+"…"+logx.Redacted) {
			t.Fatalf("%s token not masked with its display prefix: %s", name, out)
		}
		if strings.Count(out, logx.Redacted) < 13 {
			t.Fatalf("%s: expected the token masked in msg, value, err, deep map, list, bytes, raw JSON, byte batch, three secret-named keys, an empty key and a joined word; got %s", name, out)
		}
	}
	// The display prefix on its own (what the UI shows) is not a token and
	// stays readable.
	if got := logx.MaskTokens("agy_abcdefgh"); got != "agy_abcdefgh" {
		t.Fatalf("display prefix masked: %q", got)
	}

	// The masked form is the 12-character display prefix, an ellipsis and the
	// marker, wherever the token stands as its own word: after punctuation,
	// at either end, upper-cased, repeated.
	tok, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		t.Fatal(err)
	}
	masked := tok[:12] + "…[redacted]"
	for in, want := range map[string]string{
		tok:                                   masked,
		"Authorization: Bearer " + tok:        "Authorization: Bearer " + masked,
		"k=" + tok + ",next":                  "k=" + masked + ",next",
		`{"a":"` + tok + `"}`:                 `{"a":"` + masked + `"}`,
		"(" + tok + ") and " + tok + "\n":     "(" + masked + ") and " + masked + "\n",
		"path/" + tok + ".json":               "path/" + masked + ".json",
		strings.ToUpper(tok):                  strings.ToUpper(tok[:12]) + "…[redacted]",
		"short " + tok[:51]:                   "short " + tok[:51],
		"no token in a sentence of fifty-two": "no token in a sentence of fifty-two",
		// A 52-character run that is not base32 (a hex digest has 0, 1, 8 or
		// 9 in every window) is not a token.
		strings.Repeat("0", 52):  strings.Repeat("0", 52),
		strings.Repeat("9a", 26): strings.Repeat("9a", 26),
	} {
		if got := logx.MaskTokens(in); got != want {
			t.Errorf("MaskTokens(%q) = %q, want %q", in, got, want)
		}
	}
	// A byte-exact line: the redaction marker is the literal text the
	// dashboards and the docs show.
	var lit bytes.Buffer
	logx.New(logx.Options{W: &lit}).Info("x", "password", "p")
	if !strings.Contains(lit.String(), `"password":"[redacted]"`) {
		t.Fatalf("redaction marker is not the documented text: %s", lit.String())
	}
	t.Run("every shape of value", sanitizeShapes)
}

// A token is masked whatever characters touch it: a prefix and a suffix made
// of letters, digits or underscores, as a cache key or a file name builds
// them, hide nothing; and a run that is not a token — a hex digest, a long
// lowercase word, a token one character short — stays readable.
func TestTokenJoinedToOtherCharactersIsMasked(t *testing.T) {
	for _, prefix := range []string{auth.PATPrefix, auth.SessionPrefix, ""} {
		tok, err := auth.NewToken(prefix)
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range []string{
			"sess_%s", "x%s", "%sx", "9%s", "%s9", "%s_1", "_%s", "%s_", "Z%s", "%sZ",
			"k=%s", "pre/%s.json", "Bearer %s", "[%s]", "%s,%s", "sess_%s_1",
		} {
			joined := strings.ReplaceAll(form, "%s", tok)
			var buf bytes.Buffer
			logx.New(logx.Options{W: &buf}).Info("joined "+joined, "v", joined, "err", errors.New(joined))
			out := buf.String()
			if strings.Contains(out, tok[12:]) {
				t.Errorf("%q: the token's tail reached the line: %s", form, out)
			}
			if !strings.Contains(out, logx.Redacted) {
				t.Errorf("%q: nothing masked: %s", form, out)
			}
		}
	}

	for name, s := range map[string]string{
		"hex digest":        strings.Repeat("0123456789abcdef", 4),
		"long lowercase":    strings.Repeat("abcdefghij", 5) + "k-" + strings.Repeat("lmnop", 10),
		"one char short":    strings.Repeat("a", 51),
		"base32 and a stop": strings.Repeat("a", 30) + "." + strings.Repeat("b", 30),
	} {
		if got := logx.MaskTokens(s); got != s {
			t.Errorf("%s was masked: %q", name, got)
		}
	}
}

// A value under an empty key is sanitised like any other; a group with an
// empty name, which slog inlines, is sanitised too.
func TestEmptyKeyValueIsSanitised(t *testing.T) {
	tok, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	log.Info("x", "", tok)
	if out := buf.String(); strings.Contains(out, tok) || !strings.Contains(out, tok[:12]+"…"+logx.Redacted) {
		t.Fatalf("a token under an empty key was not masked: %s", out)
	}

	buf.Reset()
	log.Info("x", slog.Group("", "inner", tok, "token", "t"), "", errors.New("bad "+tok), "", map[string]any{"": tok})
	out := buf.String()
	if strings.Contains(out, tok) {
		t.Fatalf("a token under an empty group or an empty key leaked: %s", out)
	}
	if strings.Contains(out, `"token":"t"`) {
		t.Fatalf("a secret-named key inside an empty group was kept: %s", out)
	}

	// An attribute with no key and no value is dropped by the handler, not
	// turned into a line field.
	buf.Reset()
	log.Info("x", slog.Attr{})
	if m := line(t, &buf); m[""] != nil {
		t.Fatalf("an empty attribute was written: %v", m)
	}
}

// A typed-nil pointer that implements error or fmt.Stringer is logged as
// null; it does not panic inside the logging call, at the top level or
// nested in a map or a slice.
func TestTypedNilValuesDoNotPanic(t *testing.T) {
	var u *url.URL
	var e *net.OpError
	var b *bytes.Buffer
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	log.Info("x", "u", u, "e", e, "b", b,
		"nested", map[string]any{"u": u, "e": e}, "list", []any{u, e}, "ok", "kept")
	m := line(t, &buf)
	for _, k := range []string{"u", "e", "b"} {
		if v, present := m[k]; !present || v != nil {
			t.Errorf("%s = %v (present %v), want null", k, v, present)
		}
	}
	if n := m["nested"].(map[string]any); n["u"] != nil || n["e"] != nil {
		t.Errorf("nested = %v, want nulls", n)
	}
	if l := m["list"].([]any); l[0] != nil || l[1] != nil {
		t.Errorf("list = %v, want nulls", l)
	}
	if m["ok"] != "kept" {
		t.Errorf("a neighbouring value was lost: %v", m)
	}

	// A non-nil pointer of the same types is still logged as its text.
	buf.Reset()
	log.Info("x", "u", &url.URL{Scheme: "https", Host: "example.test"})
	if m := line(t, &buf); m["u"] != "https://example.test" {
		t.Errorf("u = %v, want the URL's text", m["u"])
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
		// The same names in camelCase, kebab-case and dotted form.
		"signingKey", "sk", "privateKey", "pk", "apiKey", "ak", "accessKey", "ack", "secretKey", "sek",
		"clientSecret", "cs", "refreshToken", "rt", "X-Api-Key", "xk", "db.password", "dp",
		"publicKey", "ssh-ed25519 BBBB", "objectKey", "archive/2.tgz", "hostKeyFingerprint", "SHA256:def",
		// Every suffix of the list: passwd, credential(s), cookie, spaced and
		// mixed-case spellings; and names that only contain one are kept.
		"db_passwd", "p1", "credential", "c1", "credentials", "c2", "Set-Cookie", "sc", "api key", "ak2", "ACCESS_KEY", "ack2", "auth_secret", "as", "signing.key", "sgk", "Private.Key", "pvk",
		"token_count", "tc", "secret_name", "sn", "tokens", "ts", "password_policy", "pp", "cookie_name", "cn", "authorization_url", "au",
	)
	m := line(t, &buf)
	for _, k := range []string{"token", "Password", "client_secret", "Authorization", "cookie", "api_key", "smtp_password",
		"signingKey", "privateKey", "apiKey", "accessKey", "secretKey", "clientSecret", "refreshToken", "X-Api-Key", "db.password",
		"db_passwd", "credential", "credentials", "Set-Cookie", "api key", "ACCESS_KEY", "auth_secret", "signing.key", "Private.Key"} {
		if m[k] != logx.Redacted {
			t.Errorf("%s = %v, want %q", k, m[k], logx.Redacted)
		}
	}
	for k, want := range map[string]string{"object_key": "archive/1.tgz", "hostkey_fingerprint": "SHA256:abc", "public_key": "ssh-ed25519 AAAA",
		"publicKey": "ssh-ed25519 BBBB", "objectKey": "archive/2.tgz", "hostKeyFingerprint": "SHA256:def"} {
		if m[k] != want {
			t.Errorf("%s = %v, want it kept", k, m[k])
		}
	}
	for k, want := range map[string]string{"token_count": "tc", "secret_name": "sn", "tokens": "ts", "password_policy": "pp", "cookie_name": "cn", "authorization_url": "au"} {
		if m[k] != want {
			t.Errorf("%s = %v, want it kept as %q", k, m[k], want)
		}
	}
	d := m["detail"].(map[string]any)
	if d["token"] != logx.Redacted || d["keep"] != "me" {
		t.Errorf("nested map: %v", d)
	}
}

// sanitizeShapes is Sanitize on its own: the same two rules over every shape a
// value can take, including the ones the JSON handler would otherwise encode
// without looking (a string-keyed map of strings, a slice of strings, a
// Stringer) and a group, whose members are sanitised one by one.
func sanitizeShapes(t *testing.T) {
	tok, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		t.Fatal(err)
	}
	masked := tok[:12] + "…" + logx.Redacted

	if got := logx.Sanitize(nil, slog.String("stack", "at "+tok+"\n")); got.Value.String() != "at "+masked+"\n" {
		t.Errorf("a token in a stack was not masked: %q", got.Value.String())
	}
	g := logx.Sanitize(nil, slog.Group("g", slog.String("password", "p"), slog.String("v", "x "+tok), slog.Group("inner", slog.String("api_key", "k"), slog.String("keep", "me"))))
	if g.Value.Kind() != slog.KindGroup {
		t.Fatalf("a group came back as %v", g.Value.Kind())
	}
	want := map[string]string{"password": logx.Redacted, "v": "x " + masked}
	for _, a := range g.Value.Group() {
		if a.Key == "inner" {
			for _, b := range a.Value.Group() {
				if (b.Key == "api_key" && b.Value.String() != logx.Redacted) || (b.Key == "keep" && b.Value.String() != "me") {
					t.Errorf("inner group member %s = %q", b.Key, b.Value.String())
				}
			}
			continue
		}
		if w, ok := want[a.Key]; !ok || a.Value.String() != w {
			t.Errorf("group member %s = %q, want %q", a.Key, a.Value.String(), want[a.Key])
		}
		delete(want, a.Key)
	}
	if len(want) != 0 {
		t.Errorf("group members lost: %v", want)
	}

	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	log.Info("shapes",
		"strmap", map[string]string{"token": tok, "note": "see " + tok, "keep": "me"},
		"strs", []string{"a " + tok, "b"},
		"stringer", stringerOf("with "+tok),
		"anys", []any{"x " + tok, errors.New("e " + tok), nil},
		"nilany", nil,
		"num", 7,
		slog.Group("sub", "secret", "s", "n", 1),
		"raw", json.RawMessage(`{"a":"`+tok+`"}`),
		"batch", [][]byte{[]byte("p " + tok)},
	)
	if strings.Contains(buf.String(), tok) {
		t.Fatalf("a token reached the line: %s", buf.String())
	}
	m := line(t, &buf)
	sm, _ := m["strmap"].(map[string]any)
	if sm["token"] != logx.Redacted || sm["note"] != "see "+masked || sm["keep"] != "me" {
		t.Errorf("map[string]string = %v", m["strmap"])
	}
	if ss, _ := m["strs"].([]any); len(ss) != 2 || ss[0] != "a "+masked || ss[1] != "b" {
		t.Errorf("[]string = %v", m["strs"])
	}
	if m["stringer"] != "with "+masked {
		t.Errorf("Stringer = %v", m["stringer"])
	}
	if as, _ := m["anys"].([]any); len(as) != 3 || as[0] != "x "+masked || as[1] != "e "+masked || as[2] != nil {
		t.Errorf("[]any = %v", m["anys"])
	}
	if v, ok := m["nilany"]; !ok || v != nil {
		t.Errorf("a nil value = %v (present %v)", v, ok)
	}
	if m["num"] != float64(7) {
		t.Errorf("a number = %v", m["num"])
	}
	if grp, _ := m["sub"].(map[string]any); grp["secret"] != logx.Redacted || grp["n"] != float64(1) {
		t.Errorf("group = %v", m["sub"])
	}
}

type stringerOf string

func (s stringerOf) String() string { return string(s) }

// MaskEmail keeps the first character of the local part and the whole domain
// after the last @, and nothing else of the address.
func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"alice@example.com":  "a…@example.com",
		"a@b.io":             "a…@b.io",
		"first.last@corp.eu": "f…@corp.eu",
		"odd@local@host.org": "o…@host.org",
		"@example.com":       "…",
		"no-at-sign":         "…",
		"":                   "…",
	} {
		if got := logx.MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
	if got := logx.MaskEmail("alice@example.com"); strings.Contains(got, "lice") {
		t.Errorf("the local part leaked: %q", got)
	}
}

// A string above MaxStringLen is cut so the whole line stays below Docker's
// 16 KB split; the marker says it was; the cut lands on a rune boundary; a
// panic's stack gets more room than any other value.
func TestLongValuesAreTruncated(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf})
	// Spaced, so it is long text and not one 20,000-character base32 run.
	big := strings.Repeat("a ", 10000)
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
	log.Error("panic in handler", "path", "/api/v1/x", "panic", big, "stack", strings.Repeat("s ", 10000))
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

	// One ASCII byte in front puts the 4096-byte cut in the middle of a
	// two-byte rune, so the cut has to back up one byte.
	buf.Reset()
	log.Info("x", "v", "a"+multibyte)
	odd := line(t, &buf)["v"].(string)
	if strings.ContainsRune(odd, '\uFFFD') || !strings.HasSuffix(odd, "é…[truncated]") || len(odd) != 4095+len("…[truncated]") {
		t.Fatalf("a cut inside a rune: %d bytes, tail %q", len(odd), odd[len(odd)-20:])
	}

	// The bounds are exact: a value of exactly the limit is untouched and one
	// byte more is cut, for ordinary strings (4096) and for a stack (8192).
	for _, c := range []struct {
		key  string
		n    int
		cut  bool
		keep int
	}{
		{"v", logx.MaxStringLen, false, logx.MaxStringLen},
		{"v", logx.MaxStringLen + 1, true, logx.MaxStringLen},
		{"stack", logx.MaxStackLen, false, logx.MaxStackLen},
		{"stack", logx.MaxStackLen + 1, true, logx.MaxStackLen},
	} {
		buf.Reset()
		// "9" is outside a token's alphabet, so only the length bound acts.
		log.Info("x", c.key, strings.Repeat("9", c.n))
		v := line(t, &buf)[c.key].(string)
		wantLen := c.keep
		if c.cut {
			wantLen += len("…[truncated]")
		}
		if len(v) != wantLen || strings.HasSuffix(v, "…[truncated]") != c.cut {
			t.Errorf("%s of %d bytes came out %d bytes (cut %v), want %d (cut %v)", c.key, c.n, len(v), strings.HasSuffix(v, "…[truncated]"), wantLen, c.cut)
		}
	}
	if logx.MaxStringLen != 4096 || logx.MaxStackLen != 8192 {
		t.Errorf("bounds = %d and %d, want the documented 4096 and 8192", logx.MaxStringLen, logx.MaxStackLen)
	}
	// A token in a stack is masked there as everywhere.
	tok, err := auth.NewToken(auth.PATPrefix)
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	log.Error("panic", "stack", "goroutine 1:\n\tcall("+tok+")")
	if st := line(t, &buf)["stack"].(string); strings.Contains(st, tok) || !strings.Contains(st, tok[:12]+"…[redacted]") {
		t.Errorf("stack = %q", st)
	}
	// A stack that arrives as bytes is read as the text it holds and masked.
	buf.Reset()
	log.Error("panic", "stack", []byte("goroutine 1:\n\tcall("+tok+")"))
	if st, _ := line(t, &buf)["stack"].(string); strings.Contains(st, tok) || !strings.Contains(st, tok[:12]+"…[redacted]") {
		t.Errorf("byte stack = %q", st)
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
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug, "info": slog.LevelInfo, "": slog.LevelInfo, "nonsense": slog.LevelInfo,
		"warn": slog.LevelWarn, "Warning": slog.LevelWarn, "WARN": slog.LevelWarn, "error": slog.LevelError, "ERROR": slog.LevelError,
	} {
		if got := logx.ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
	// The option reaches the logger: debug lines only at debug, error lines at error.
	buf.Reset()
	logx.New(logx.Options{W: &buf, Level: "debug"}).Debug("dbg")
	if buf.Len() == 0 {
		t.Fatal("debug dropped at level debug")
	}
	buf.Reset()
	logx.New(logx.Options{W: &buf}).Debug("dbg")
	if buf.Len() != 0 {
		t.Fatal("debug written at the default level")
	}
	buf.Reset()
	lg := logx.New(logx.Options{W: &buf, Level: "error"})
	lg.Warn("dropped")
	if buf.Len() != 0 {
		t.Fatal("warn written at level error")
	}
	lg.Error("kept")
	if buf.Len() == 0 {
		t.Fatal("error dropped at level error")
	}
}
