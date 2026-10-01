package scan

import (
	"strconv"
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// cvssBaseScore is the CVSS base score an OSV severity entry's "score"
// carries: a CVSS v3.0, v3.1 or v4.0 vector, computed by go-cvss (v4.0's
// score comes from the specification's macrovector lookup table, which is
// why this is a library and not the formula by hand; agentry#774), or a
// plain number, which some databases put there instead. Anything else,
// CVSS v2 included, is -1: no usable score.
func cvssBaseScore(score string) float64 {
	s := strings.TrimSpace(score)
	switch {
	case strings.HasPrefix(s, "CVSS:4.0/"):
		v, err := gocvss40.ParseVector(s)
		if err != nil {
			return -1
		}
		return v.Score()
	case strings.HasPrefix(s, "CVSS:3.1/"):
		v, err := gocvss31.ParseVector(s)
		if err != nil {
			return -1
		}
		return v.BaseScore()
	case strings.HasPrefix(s, "CVSS:3.0/"):
		v, err := gocvss30.ParseVector(s)
		if err != nil {
			return -1
		}
		return v.BaseScore()
	case strings.Contains(s, ":"):
		return -1
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 10 {
		return -1
	}
	return f
}

// advisoryHighFrom is the CVSS base score from which a High advisory is a
// high finding; below it, a medium one (the tweaks plan's D2: "8.5 and
// above").
const advisoryHighFrom = 8.5

// AdvisoryGateSeverity is the severity the gate gives the finding an
// advisory makes (agentry#774; the tweaks plan's D1 and D2). A Critical
// advisory is critical and rejects the version. A High one is high from a
// CVSS base score of 8.5, medium below it, and high when it carries no
// usable score. Every other severity is the advisory's own.
//
// The advisory's own severity is what the registry stores and what the
// dependency alerts and their routing read; this rating is made where the
// finding is made, and served beside the stored one on the scan route so
// the runner applies the same rule.
func AdvisoryGateSeverity(v OSVVulnerability) Severity {
	if Severity(v.Severity) == SevHigh && v.CVSSScore != nil && *v.CVSSScore < advisoryHighFrom {
		return SevMedium
	}
	return Severity(v.Severity)
}
