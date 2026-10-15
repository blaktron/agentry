package api

import (
	"strings"
	"testing"
	"time"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// A version its registry does not publish is served as error with the
// reason, never as a status the API contract lacks, and never safe.
func TestMCPServerScanNotFoundIsServedAsError(t *testing.T) {
	now := time.Now()
	out := mcpServerScanToAPI(storegen.McpServerScan{Ecosystem: "npm", Package: "x", Version: "0.1.23",
		Status: "not-found", Advisories: []byte("[]"), FirstSeenAt: now, LastCheckedAt: now})
	if out.Status != Error || out.LastError == nil || !strings.Contains(*out.LastError, "does not publish") {
		t.Fatalf("not-found row served as %q, lastError %v", out.Status, out.LastError)
	}
	safe := mcpServerScanToAPI(storegen.McpServerScan{Ecosystem: "npm", Package: "x", Version: "1.0.0",
		Status: "safe", Advisories: []byte("[]"), FirstSeenAt: now, LastCheckedAt: now})
	if safe.Status != Safe || safe.LastError != nil {
		t.Fatalf("safe row served as %q, lastError %v", safe.Status, safe.LastError)
	}
}
