package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/scan"
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
	if *out.LastError != "the package registry does not publish this version" {
		t.Fatalf("not-found row's reason is %q", *out.LastError)
	}
	safe := mcpServerScanToAPI(storegen.McpServerScan{Ecosystem: "npm", Package: "x", Version: "1.0.0",
		Status: "safe", Advisories: []byte("[]"), FirstSeenAt: now, LastCheckedAt: now})
	if safe.Status != Safe || safe.LastError != nil {
		t.Fatalf("safe row served as %q, lastError %v", safe.Status, safe.LastError)
	}
	if safe.MaxSeverity != nil || safe.Advisories == nil || len(safe.Advisories) != 0 {
		t.Fatalf("safe row served with max severity %v and advisories %#v, want none and an empty list", safe.MaxSeverity, safe.Advisories)
	}

	// A lookup that failed keeps its reason, and says nothing is known.
	why := "the vulnerability database did not answer"
	failed := mcpServerScanToAPI(storegen.McpServerScan{Ecosystem: "npm", Package: "x", Version: "0.2.0",
		Status: "error", Advisories: []byte("[]"), LastError: &why, FirstSeenAt: now, LastCheckedAt: now})
	if failed.Status != Error || failed.LastError == nil || *failed.LastError != why {
		t.Fatalf("error row served as %q, lastError %v, want error with its own reason", failed.Status, failed.LastError)
	}

	// A vulnerable row serves each advisory in full, with the rating the
	// gate gives it beside its own: a high advisory scored below 8.5 is
	// medium to the gate.
	score, severe := 7.5, "high"
	advisories, err := json.Marshal([]scan.OSVVulnerability{
		{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Summary: "scored high", Severity: "high", CVSSScore: &score,
			FixedIn: []string{"1.0.1"}, References: []string{"https://example.test/advisory"}},
		{ID: "GHSA-dddd-eeee-ffff", Summary: "no extras", Severity: "critical"},
	})
	if err != nil {
		t.Fatal(err)
	}
	vuln := mcpServerScanToAPI(storegen.McpServerScan{Ecosystem: "npm", Package: "x", Version: "1.2.3",
		Status: "vulnerable", MaxSeverity: &severe, Advisories: advisories, FirstSeenAt: now, LastCheckedAt: now})
	if vuln.Status != Vulnerable || vuln.MaxSeverity == nil || string(*vuln.MaxSeverity) != "high" || vuln.LastError != nil || len(vuln.Advisories) != 2 {
		t.Fatalf("vulnerable row served as %q, max severity %v, lastError %v, %d advisories", vuln.Status, vuln.MaxSeverity, vuln.LastError, len(vuln.Advisories))
	}
	full, bare := vuln.Advisories[0], vuln.Advisories[1]
	if full.Id != "GHSA-aaaa-bbbb-cccc" || full.Summary != "scored high" || full.Severity != "high" || full.GateSeverity != McpAdvisoryGateSeverityMedium ||
		full.CvssScore == nil || *full.CvssScore != 7.5 || full.Aliases == nil || (*full.Aliases)[0] != "CVE-2026-0001" ||
		full.FixedIn == nil || (*full.FixedIn)[0] != "1.0.1" || full.References == nil || (*full.References)[0] != "https://example.test/advisory" {
		t.Fatalf("the first advisory is served as %+v", full)
	}
	if bare.Severity != "critical" || bare.GateSeverity != McpAdvisoryGateSeverityCritical || bare.Aliases != nil || bare.FixedIn != nil || bare.References != nil || bare.CvssScore != nil {
		t.Fatalf("the second advisory is served as %+v", bare)
	}
}
