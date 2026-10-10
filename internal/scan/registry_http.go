package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PackageRegistries answers whether a declared MCP server's package
// registry publishes the version a manifest pins (agentry#1036). OSV
// answers "no advisories" for a version that does not exist, so without
// this S7 recorded such a server as safe and the release published, to be
// refused by every run that tried to install it (mcp-not-resolved).
type PackageRegistries interface {
	// Published reports whether ecosystem ("npm" or "pypi") publishes
	// name@version. An error means the registry gave no answer.
	Published(ctx context.Context, ecosystem, name, version string) (bool, error)
}

// OfflineRegistries is the PackageRegistries of a deployment told not to ask
// (AGENTRY_SCAN_NPM_REGISTRY=none): S7 says it did not check.
type OfflineRegistries struct{}

// Published implements PackageRegistries; it is never called for an offline
// deployment (registriesEnabled).
func (OfflineRegistries) Published(context.Context, string, string, string) (bool, error) {
	return false, errors.New("registries: offline")
}

// registriesEnabled reports a client S7 should ask.
func registriesEnabled(r PackageRegistries) bool {
	if r == nil {
		return false
	}
	_, off := r.(OfflineRegistries)
	return !off
}

// HTTPRegistries asks the public npm registry and PyPI's JSON API, the
// registries the runner installs from by default (DR-67), through the
// worker's egress proxy like the OSV client (the default transport reads
// the proxy variables).
type HTTPRegistries struct {
	// NPM is the npm registry origin, e.g. https://registry.npmjs.org.
	NPM string
	// PyPI is PyPI's origin, e.g. https://pypi.org.
	PyPI string
	// Client is the HTTP client; nil uses a 20s-timeout default.
	Client *http.Client
}

func (r *HTTPRegistries) httpClient() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// Published implements PackageRegistries: a version document that answers
// 200 is published, 404 is not, anything else is no answer.
func (r *HTTPRegistries) Published(ctx context.Context, ecosystem, name, version string) (bool, error) {
	// V5 holds both to a registry's grammar before S7 runs; a dot segment
	// here would walk the registry's path (npm answers /lodash/.. with the
	// package), so S7 does not lean on that.
	for _, seg := range []string{name, version} {
		if seg == "" || seg == "." || seg == ".." {
			return false, fmt.Errorf("registries: %q is not a package name or version", seg)
		}
	}
	var u string
	switch ecosystem {
	case "npm":
		// A scoped name is one path segment, its slash escaped
		// (@scope%2Fname), as npm's own client asks for it.
		u = strings.TrimRight(r.NPM, "/") + "/" + url.PathEscape(name) + "/" + url.PathEscape(version)
	case "pypi":
		u = strings.TrimRight(r.PyPI, "/") + "/pypi/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/json"
	default:
		return false, fmt.Errorf("registries: ecosystem %q not covered", ecosystem)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("registries: %s %s answered %d", ecosystem, name, resp.StatusCode)
	}
}
