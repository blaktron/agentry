package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// apiCall is one in-process request to the API on behalf of the browser
// request r. It carries the browser's cookies, User-Agent and forwarding
// chain (so the API's session, CSRF, rate-limit and audit decisions are the
// ones a direct call would get) and dispatches through the same handler
// chain the network uses — no socket, no second trust decision.
type apiCall struct {
	api  http.Handler
	r    *http.Request
	csrf string
}

// response is what came back: status, headers (Set-Cookie included) and the
// body, decoded on demand.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (res response) OK() bool { return res.Status >= 200 && res.Status < 300 }

func (res response) decode(v any) error {
	if len(bytes.TrimSpace(res.Body)) == 0 {
		return nil
	}
	return json.Unmarshal(res.Body, v)
}

// detail is the human-readable message of a problem+json body, or the
// status text when there is none.
func (res response) detail() string {
	var p struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(res.Body, &p); err == nil {
		if p.Detail != "" {
			return p.Detail
		}
		if p.Title != "" {
			return p.Title
		}
	}
	return http.StatusText(res.Status)
}

// problemType is the problem+json `type`, "" when the body is not one.
func (res response) problemType() string {
	var p struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(res.Body, &p)
	return p.Type
}

func (c apiCall) do(method, path string, body any) (response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return response{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(c.r.Context(), method, "/api/v1"+path, rd)
	if err != nil {
		return response{}, err
	}
	req.RemoteAddr = c.r.RemoteAddr
	req.Host = c.r.Host
	req.TLS = c.r.TLS
	for _, h := range []string{"Cookie", "User-Agent", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP", "Accept-Language"} {
		if v := c.r.Header.Values(h); len(v) > 0 {
			req.Header[h] = v
		}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead && c.csrf != "" {
		req.Header.Set("X-Agentry-CSRF", c.csrf)
	}
	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	c.api.ServeHTTP(rec, req)
	return response{Status: rec.status, Header: rec.header, Body: rec.body.Bytes()}, nil
}

// recorder captures an in-process response. A hand-rolled one so the
// serving binary does not import net/http/httptest.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (rec *recorder) Header() http.Header { return rec.header }
func (rec *recorder) WriteHeader(code int) {
	if !rec.wrote {
		rec.status = code
		rec.wrote = true
	}
}
func (rec *recorder) Write(b []byte) (int, error) {
	rec.wrote = true
	return rec.body.Write(b)
}

// forwardCookies copies the API's Set-Cookie headers onto the browser
// response: a sign-in's session cookie, a sign-out's clearing. The API chose
// the attributes (HttpOnly, SameSite, Secure, lifetime); nothing is rewritten.
func forwardCookies(w http.ResponseWriter, from http.Header) {
	for _, c := range from.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", c)
	}
}

// setCookieLike sets name=value with the attributes of a Set-Cookie line
// the API issued (the CSRF cookie mirrors the session cookie's).
func setCookieLike(w http.ResponseWriter, name, value, like string, secure bool) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure}
	if like != "" {
		for _, part := range strings.Split(like, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if strings.EqualFold(kv[0], "Max-Age") && len(kv) == 2 {
				var n int
				for _, ch := range kv[1] {
					if ch < '0' || ch > '9' {
						n = -1
						break
					}
					n = n*10 + int(ch-'0')
				}
				if n >= 0 {
					c.MaxAge = n
				}
			}
			if strings.EqualFold(kv[0], "Secure") {
				c.Secure = true
			}
		}
	}
	http.SetCookie(w, c)
}

func cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func findSetCookie(h http.Header, name string) string {
	for _, c := range h.Values("Set-Cookie") {
		if strings.HasPrefix(c, name+"=") {
			return c
		}
	}
	return ""
}

func cookieValueOf(setCookie string) string {
	first := strings.SplitN(setCookie, ";", 2)[0]
	kv := strings.SplitN(first, "=", 2)
	if len(kv) == 2 {
		return kv[1]
	}
	return ""
}
