package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
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

func cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}
