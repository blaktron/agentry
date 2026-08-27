// API client plumbing: bearer-authenticated apiclient construction, RFC 9457
// problem rendering, and the §9.4 download/verify helpers shared by
// install and verify.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PLACEHOLDER_ORG/agentry/pkg/apiclient"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/manifest"
)

// Client-side safety caps for release archives. The registry enforces the
// real quotas (§19: 100 MB repo hard cap, 25 MB single object); these only
// bound what the CLI is willing to buffer and unpack.
const (
	maxArchiveBytes      int64 = 512 << 20
	extractMaxFileBytes  int64 = 25 << 20
	extractMaxTotalBytes int64 = 200 << 20
)

// newAPIClient builds a generated client rooted at {registry}/api/v1,
// attaching "Authorization: Bearer <token>" when a token is known.
func newAPIClient(regURL, token string) (*apiclient.ClientWithResponses, error) {
	var opts []apiclient.ClientOption
	if token != "" {
		opts = append(opts, apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		}))
	}
	c, err := apiclient.NewClientWithResponses(regURL+"/api/v1", opts...)
	if err != nil {
		return nil, fmt.Errorf("create API client for %s: %w", regURL, err)
	}
	return c, nil
}

// apiProblem renders a failed API call as an error, preferring the RFC 9457
// problem document when the server sent one.
func apiProblem(op string, status int, p *apiclient.Problem, body []byte) error {
	if p != nil {
		msg := p.Title
		if p.Detail != nil && *p.Detail != "" {
			msg += ": " + *p.Detail
		}
		if p.Errors != nil {
			for _, fe := range *p.Errors {
				msg += fmt.Sprintf("; %s: %s", fe.Field, fe.Message)
			}
		}
		return fmt.Errorf("%s: %s (HTTP %d)", op, msg, status)
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	return fmt.Errorf("%s: HTTP %d: %s", op, status, msg)
}

// sha256Digest computes the "sha256:<hex>" digest of b (D-15 identity form).
func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sameHost reports whether two URLs share a host, so the bearer token is
// only ever attached to the registry itself, never to a CDN (§9.4).
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host == ub.Host
}

// downloadArchive fetches the release archive named by a resolve result
// (§9.4 step 2). Relative archive URLs (self-host) resolve against the
// registry base URL.
func downloadArchive(ctx context.Context, regURL, token string, res *apiclient.ResolveResult) ([]byte, error) {
	archiveURL := res.ArchiveUrl
	if strings.HasPrefix(archiveURL, "/") {
		archiveURL = regURL + archiveURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build download request: %w", err)
	}
	if token != "" && sameHost(archiveURL, regURL) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", archiveURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, apiProblem("download archive", resp.StatusCode, nil, body)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read archive body: %w", err)
	}
	if int64(len(data)) > maxArchiveBytes {
		return nil, fmt.Errorf("archive exceeds the %d-byte client cap", maxArchiveBytes)
	}
	return data, nil
}

// manifestFromResolve decodes the canonical manifest JSON carried by a
// resolve result into the typed manifest.
func manifestFromResolve(res *apiclient.ResolveResult) (*manifest.Manifest, error) {
	raw, err := json.Marshal(res.Manifest)
	if err != nil {
		return nil, fmt.Errorf("re-encode resolved manifest: %w", err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode resolved manifest: %w", err)
	}
	return &m, nil
}

// resolveRef calls GET /resolve for a ns/name[@range] reference.
// installIntent adds the X-Agentry-Install hint so the registry counts an
// install without a download round-trip through the API (§9.4 step 4).
func resolveRef(ctx context.Context, client *apiclient.ClientWithResponses, ref string, installIntent bool) (*apiclient.ResolveResult, error) {
	var editors []apiclient.RequestEditorFn
	if installIntent {
		editors = append(editors, func(_ context.Context, req *http.Request) error {
			req.Header.Set("X-Agentry-Install", "1")
			return nil
		})
	}
	resp, err := client.ResolveRefWithResponse(ctx, &apiclient.ResolveRefParams{Ref: ref}, editors...)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ref, err)
	}
	if resp.JSON200 == nil {
		return nil, apiProblem("resolve "+ref, resp.StatusCode(), resp.ApplicationproblemJSONDefault, resp.Body)
	}
	return resp.JSON200, nil
}
