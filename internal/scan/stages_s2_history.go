package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/pkg/rules"
)

// S2 history scan (§8.3: "scan full git history for secrets on git-tag
// publishes", agentry#54). The archive holds the tagged tree; a secret
// committed and later removed is not in it but is still in every clone.
// The pipeline hands S2 a patch stream of the history reachable from the
// tagged commit (Input.History) and S2 runs its native secret rules over
// the ADDED lines only — a removed line is a fix, not a finding. When the
// scanning role has no repo access the stage says so (`S2/history-not-
// scanned`, fail-open counted) rather than implying a clean history.

const (
	historyPatchCap    = 64 << 20 // bytes of patch read before stopping
	historyMaxFindings = 100
	historyMaxLine     = 16 << 10
)

var historyCommitRe = regexp.MustCompile(`^\x01([0-9a-f]{7,64})$`)

// s2History runs the history scan for git-tag sources. seen carries the
// archive scan's rule|file|line keys purely for the report's benefit: a
// secret still present at the tag is reported by the archive scan with
// its exact line, and history adds the commit that introduced it.
func s2History(ctx context.Context, in *Input) (findings []Finding, ran bool) {
	if in.Source != "git-tag" {
		return nil, false
	}
	if in.History == nil {
		return []Finding{{
			Scanner: "S2/history-not-scanned", Severity: SevInfo, Confidence: ConfLow,
			Title: "Git history not scanned for secrets",
			Detail: map[string]any{
				"reason": "the scanning role has no repository access; only the tagged tree was scanned (§8.3)",
			},
			Taxonomy: []string{"LLM03"},
		}}, false
	}
	stream, err := in.History(ctx)
	if err != nil {
		return []Finding{historyError(err)}, false
	}
	out, truncated, perr := scanHistoryPatch(io.LimitReader(stream, historyPatchCap+1))
	if cerr := stream.Close(); cerr != nil && perr == nil && !truncated {
		perr = cerr
	}
	if perr != nil {
		return append(out, historyError(perr)), true
	}
	if truncated {
		out = append(out, Finding{
			Scanner: "S2/history-truncated", Severity: SevLow, Confidence: ConfHigh,
			Title:    "Git history scan stopped at the size cap",
			Detail:   map[string]any{"capBytes": historyPatchCap, "reason": "older commits beyond the cap were not examined"},
			Taxonomy: []string{"LLM03"},
		})
	}
	return out, true
}

func historyError(err error) Finding {
	return Finding{
		Scanner: "S2/history-error", Severity: SevMedium, Confidence: ConfHigh,
		Title:    "Git history scan failed",
		Detail:   map[string]any{"error": err.Error(), "reason": "an unscanned history cannot be cleared automatically"},
		Taxonomy: []string{"LLM03"},
	}
}

// scanHistoryPatch walks a `git log -p` stream (commits introduced by
// "\x01<sha>", files by "+++ b/<path>") and applies the S2 rules to added
// lines. Hits are de-duplicated on rule + redacted match so a secret that
// rides through many commits is one finding naming the first commit.
func scanHistoryPatch(r io.Reader) (findings []Finding, truncated bool, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), historyMaxLine)
	var commit, file string
	var read int64
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		if read > historyPatchCap {
			return findings, true, nil
		}
		if m := historyCommitRe.FindStringSubmatch(line); m != nil {
			commit, file = m[1], ""
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			file = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
			if file == "/dev/null" {
				file = ""
			}
			continue
		}
		if len(line) < 2 || line[0] != '+' || strings.HasPrefix(line, "++") {
			continue
		}
		added := line[1:]
		for _, rule := range secretRules {
			loc := rule.re.FindStringSubmatch(added)
			if loc == nil {
				continue
			}
			cand := loc[0]
			if rule.group > 0 && rule.group < len(loc) {
				cand = loc[rule.group]
			}
			if rule.entropyMin > 0 && rules.ShannonEntropy([]byte(cand)) < rule.entropyMin {
				continue
			}
			key := rule.id + "|" + redact(cand)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(findings) >= historyMaxFindings {
				return findings, true, nil
			}
			findings = append(findings, Finding{
				Scanner: "S2/history-" + rule.id, Severity: rule.severity, Confidence: ConfHigh,
				Title:    "Secret in git history: " + rule.id,
				FilePath: file,
				Excerpt:  redact(added),
				Detail: map[string]any{
					"rule": rule.id, "commit": commit,
					"reason": "the secret is in every clone of the repository even if a later commit removed it; rotate it",
				},
				Taxonomy: []string{"LLM03"},
			})
		}
	}
	if serr := sc.Err(); serr != nil {
		if serr == bufio.ErrTooLong {
			return findings, false, fmt.Errorf("history patch line longer than %s bytes", strconv.Itoa(historyMaxLine))
		}
		return findings, false, serr
	}
	return findings, false, nil
}
