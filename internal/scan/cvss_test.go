package scan

import "testing"

// Published vector/score pairs from GitHub's advisory database
// (GET /advisories, cvss_severities); these are the ones that pin each
// version and the 8.5 boundary.
func TestCVSSBaseScoreMatchesPublishedScores(t *testing.T) {
	for _, c := range []struct {
		advisory, vector string
		want             float64
	}{
		// v3.0
		{"GHSA-rcr2-hggw-43wm", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// v3.1, both sides of 8.5, and scope changed
		{"GHSA-6rh5-qq4q-97xh", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L", 8.5},
		{"GHSA-r4vp-3vw6-r2x5", "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4},
		{"GHSA-p6hp-93wp-fh6p", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6},
		{"GHSA-xq74-c7jx-8w5j", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L", 10},
		{"GHSA-633r-hq9m-c4ff", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N", 4},
		// v4.0, from the specification's lookup table
		{"GHSA-fm8p-53ww-hf6w", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		{"GHSA-c2m8-h5v5-343r", "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2},
		{"GHSA-x78j-v8h9-3j2q", "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3},
		{"GHSA-9h9j-4vrj-gf7g", "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N", 5.8},
		// v4.0 with every threat, environmental and supplemental metric "X"
		{"GHSA-hc6q-4vvg-jf79", "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 9.3},
	} {
		if got := cvssBaseScore(c.vector); got != c.want {
			t.Errorf("%s: cvssBaseScore(%s) = %v, want %v", c.advisory, c.vector, got, c.want)
		}
	}
}

func TestCVSSBaseScoreWithoutAUsableScore(t *testing.T) {
	for in, want := range map[string]float64{
		"7.5":                         7.5,
		" 9.8":                        9.8,
		"11":                          -1,
		"-1":                          -1,
		"":                            -1,
		"high":                        -1,
		"CVSS:3.1/AV:N/AC:L":          -1, // incomplete
		"AV:N/AC:L/Au:N/C:P/I:P/A:P":  -1, // CVSS v2: not scored
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P": -1,
		"CVSS:4.0/AV:N":               -1,
	} {
		if got := cvssBaseScore(in); got != want {
			t.Errorf("cvssBaseScore(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAdvisoryGateSeverity(t *testing.T) {
	score := func(f float64) *float64 { return &f }
	for _, c := range []struct {
		name string
		adv  OSVVulnerability
		want Severity
	}{
		{"a Critical rejects whatever its score", OSVVulnerability{Severity: "critical", CVSSScore: score(8.6)}, SevCritical},
		{"a Critical with no score", OSVVulnerability{Severity: "critical"}, SevCritical},
		{"a High at 8.5 is high", OSVVulnerability{Severity: "high", CVSSScore: score(8.5)}, SevHigh},
		{"a High above 8.5 is high", OSVVulnerability{Severity: "high", CVSSScore: score(9.1)}, SevHigh},
		{"a High at 8.4 is medium", OSVVulnerability{Severity: "high", CVSSScore: score(8.4)}, SevMedium},
		{"a High at 7.0 is medium", OSVVulnerability{Severity: "high", CVSSScore: score(7.0)}, SevMedium},
		{"a High with no usable score is high", OSVVulnerability{Severity: "high"}, SevHigh},
		{"a Moderate is its own", OSVVulnerability{Severity: "medium", CVSSScore: score(9.0)}, SevMedium},
		{"a Low is its own", OSVVulnerability{Severity: "low"}, SevLow},
	} {
		if got := AdvisoryGateSeverity(c.adv); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
