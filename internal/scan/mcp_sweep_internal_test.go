package scan

import (
	"reflect"
	"testing"
)

// The sweep alerts on a high or critical advisory the registry did not
// already carry — a server that was safe, or vulnerable only at lower
// severities, or that gained one more serious advisory — and never on an
// advisory it already reported.
func TestNewlyAlertable(t *testing.T) {
	high := OSVVulnerability{ID: "GHSA-h", Severity: "high"}
	crit := OSVVulnerability{ID: "GHSA-c", Severity: "critical"}
	low := OSVVulnerability{ID: "GHSA-l", Severity: "low"}
	cases := []struct {
		name string
		prev *MCPScanRecord
		cur  MCPScanRecord
		ids  []string
		sev  string
	}{
		{"safe to high", &MCPScanRecord{Status: "safe"}, MCPScanRecord{Advisories: []OSVVulnerability{high}}, []string{"GHSA-h"}, "high"},
		{"never seen", nil, MCPScanRecord{Advisories: []OSVVulnerability{crit}}, []string{"GHSA-c"}, "critical"},
		{"low only is not an alert", &MCPScanRecord{Status: "safe"}, MCPScanRecord{Advisories: []OSVVulnerability{low}}, nil, ""},
		{"already known", &MCPScanRecord{Status: "vulnerable", Advisories: []OSVVulnerability{high}}, MCPScanRecord{Advisories: []OSVVulnerability{high}}, nil, ""},
		{"one more serious advisory", &MCPScanRecord{Status: "vulnerable", Advisories: []OSVVulnerability{high}}, MCPScanRecord{Advisories: []OSVVulnerability{high, crit}}, []string{"GHSA-c"}, "critical"},
		{"low then high on the same server", &MCPScanRecord{Status: "vulnerable", Advisories: []OSVVulnerability{low}}, MCPScanRecord{Advisories: []OSVVulnerability{low, high}}, []string{"GHSA-h"}, "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids, sev := newlyAlertable(tc.prev, tc.cur)
			if !reflect.DeepEqual(ids, tc.ids) || sev != tc.sev {
				t.Fatalf("got %v/%q, want %v/%q", ids, sev, tc.ids, tc.sev)
			}
		})
	}
}
