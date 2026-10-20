package scan

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/blaktron/agentry/pkg/rules"
)

// S2 history scan (scan full git history for secrets on git-tag
// publishes). The archive holds the tagged tree; a secret
// committed and later removed is not in it but is still in every clone.
// The pipeline hands S2 a patch stream of the history reachable from the
// tagged commit (Input.History) and S2 runs its native secret rules over
// the ADDED lines only — a removed line is a fix, not a finding. When the
// scanning role has no repo access the stage says so (`S2/history-not-
// scanned`, fail-open counted) rather than implying a clean history.

const (
	historyPatchCap = 64 << 20 // bytes of patch read before stopping
	// historyMaxFindings is how many history findings a report lists. The
	// scan reads on past it and keeps the most severe, so findings in newer
	// commits cannot push an older, worse one off the report.
	historyMaxFindings = 100
	// historyMaxSeen bounds the set of secrets the scan remembers once the
	// report is full: past it, a secret that is not listed is no longer
	// remembered, and a repeat of it may be counted again as not shown.
	historyMaxSeen = 1 << 16
	historyMaxLine = 16 << 10
)

var historyCommitRe = regexp.MustCompile(`^\x01([0-9a-f]{7,64})$`)

// privateKeyRule is the secret rule that matches only a PEM private key's
// BEGIN line. Every key's BEGIN line is alike, so the history scan reads the
// key's body, the added text up to its END line, and tells keys apart by
// that instead.
const privateKeyRule = "private-key"

var (
	// privateKeyBeginRe is the private-key rule's own pattern.
	privateKeyBeginRe = secretRuleRe(privateKeyRule)
	privateKeyEndRe   = regexp.MustCompile(`-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
	// keyBodyNoise is what is dropped from a key's body before it is
	// compared: line breaks, escaped line breaks, quotes and indentation
	// differ between copies of one key, the base64 text does not.
	keyBodyNoise = regexp.MustCompile(`\\[nr]|[^A-Za-z0-9+/=]`)
)

// historyMaxKeyBody bounds how much of a private key's body the history
// scan holds while it reads to the END line: a 4096-bit RSA key is about
// 3 KiB.
const historyMaxKeyBody = 16 << 10

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
				"reason": "the scanning role has no repository access; only the tagged tree was scanned",
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
			Scanner: scannerHistoryTruncated, Severity: SevMedium, Confidence: ConfHigh,
			Title:    "Git history scan stopped at the size cap",
			Detail:   map[string]any{"capBytes": historyPatchCap, "reason": "older commits beyond the cap were not examined, and an unscanned history cannot be cleared automatically"},
			Taxonomy: []string{"LLM03"},
		})
	}
	return out, true
}

// scannerHistoryTruncated is S2's finding when the history scan stopped at
// the size cap: older commits went unread, so the gate forces review on it.
const scannerHistoryTruncated = "S2/history-truncated"

// scannerHistoryFindingLimit is S2's finding when a history held more
// secrets than the report lists. Every commit was read and the most severe
// findings are listed, so the gate weighs the worst of them; this one only
// says how many more there were.
const scannerHistoryFindingLimit = "S2/history-finding-limit"

// scannerHistoryError is S2's finding when a tag's history could not be
// scanned; the gate forces review on it.
const scannerHistoryError = "S2/history-error"

func historyError(err error) Finding {
	return Finding{
		Scanner: scannerHistoryError, Severity: SevMedium, Confidence: ConfHigh,
		Title:    "Git history scan failed",
		Detail:   map[string]any{"error": err.Error(), "reason": "an unscanned history cannot be cleared automatically"},
		Taxonomy: []string{"LLM03"},
	}
}

// scanHistoryPatch walks a `git log -p` stream (commits introduced by
// "\x01<sha>", files by "+++ b/<path>") and applies the S2 rules to added
// lines. Hits are de-duplicated on the rule and the secret itself, so a
// secret that rides through many commits is one finding naming the first
// commit the stream shows, and every different secret is a finding of its
// own: the publisher has to rotate each one. The report lists at most
// historyMaxFindings; past that the scan still reads every commit and keeps
// the most severe, adding a finding that says how many it left off. Only
// the size cap stops it early, which it reports as truncated. The seen set holds each secret
// only as an HMAC under a key made for this call, so no secret text, and
// nothing that could be matched against one, outlives the call.
func scanHistoryPatch(r io.Reader) (findings []Finding, truncated bool, err error) {
	var salt [32]byte
	_, _ = rand.Read(salt[:]) // never fails
	mac := hmac.New(sha256.New, salt[:])
	secretKey := func(ruleID, cand string) string {
		mac.Reset()
		mac.Write([]byte(cand))
		return ruleID + "|" + string(mac.Sum(nil))
	}
	seen := map[string]bool{}
	// least is the index of the least severe listed finding once the list
	// is full; notShown counts the findings left off it.
	least, notShown, forgot := -1, 0, false
	// add lists a finding unless its secret was already seen. Once the list
	// holds historyMaxFindings, a finding more severe than the least severe
	// listed one takes its place, and every finding left off is counted.
	add := func(key string, f Finding) {
		if seen[key] {
			return
		}
		if len(findings) < historyMaxFindings {
			seen[key] = true
			findings = append(findings, f)
			return
		}
		notShown++
		if least < 0 {
			least = leastSevere(findings)
		}
		if severityRank(f.Severity) > severityRank(findings[least].Severity) {
			seen[key] = true
			findings[least] = f
			least = leastSevere(findings)
			return
		}
		if len(seen) < historyMaxSeen {
			seen[key] = true
		} else {
			forgot = true
		}
	}
	// done adds the finding-limit finding when any were left off.
	done := func() []Finding {
		if notShown == 0 {
			return findings
		}
		return append(findings, Finding{
			Scanner: scannerHistoryFindingLimit, Severity: SevLow, Confidence: ConfHigh,
			Title: "Git history holds more possible secrets than the report lists",
			Detail: map[string]any{
				"maxFindings": historyMaxFindings, "notShown": notShown, "notShownMayRepeat": forgot,
				"reason": "every commit was read and the most severe findings are listed; rotate every secret the history holds, not only the listed ones",
			},
			Taxonomy: []string{"LLM03"},
		})
	}
	// key is the private key whose body is still being read: its finding
	// is added once the END line, or the end of the added block, says
	// which key it is.
	var key *pendingKey
	closeKey := func() {
		if key == nil {
			return
		}
		k := key
		key = nil
		add(secretKey(privateKeyRule, keyBodyNoise.ReplaceAllString(k.body.String(), "")), k.finding)
	}
	// readKey takes the part of text that belongs to the open key's body
	// and closes the key at its END line, at another key's BEGIN line, or
	// once the body passes historyMaxKeyBody.
	readKey := func(text string) {
		if key == nil {
			return
		}
		cut, done := len(text), false
		if loc := privateKeyEndRe.FindStringIndex(text); loc != nil {
			cut, done = loc[0], true
		}
		if loc := privateKeyBeginRe.FindStringIndex(text); loc != nil && loc[0] < cut {
			cut, done = loc[0], true
		}
		key.body.WriteString(text[:cut])
		if done || key.body.Len() > historyMaxKeyBody {
			closeKey()
		}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), historyMaxLine)
	var commit, file string
	inHunk := false // past a file's "@@" line: every line is content until the next file or commit
	var read int64
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		if read > historyPatchCap {
			closeKey()
			return done(), true, nil
		}
		if m := historyCommitRe.FindStringSubmatch(line); m != nil {
			closeKey()
			commit, file, inHunk = m[1], "", false
			continue
		}
		if strings.HasPrefix(line, "diff --git ") {
			closeKey()
			inHunk = false
			continue
		}
		if !inHunk {
			// A file's header: only "+++ " names the file, and nothing here
			// is content. An added line whose own text begins "++ " looks
			// the same, which is why the header is read only before "@@".
			if strings.HasPrefix(line, "+++ ") {
				file = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
				if file == "/dev/null" {
					file = ""
				}
			}
			inHunk = strings.HasPrefix(line, "@@")
			continue
		}
		// Inside a hunk every line that starts with "+" is added content,
		// whatever its own first character ("++" from a committed patch or
		// a Markdown "+ " item included). Any other line ends the block of
		// added lines a key's body is read from.
		if len(line) < 2 || line[0] != '+' {
			closeKey()
			continue
		}
		added := line[1:]
		readKey(added)
		for _, rule := range secretRules {
			// Every match on the line: two different keys on one line are
			// two secrets to rotate.
			for _, loc := range rule.re.FindAllStringSubmatchIndex(added, -1) {
				start, end := loc[0], loc[1]
				if g := rule.group; g > 0 && 2*g+1 < len(loc) && loc[2*g] >= 0 {
					start, end = loc[2*g], loc[2*g+1]
				}
				cand := added[start:end]
				if rule.entropyMin > 0 && rules.ShannonEntropy([]byte(cand)) < rule.entropyMin {
					continue
				}
				f := Finding{
					Scanner: "S2/history-" + rule.id, Severity: rule.severity, Confidence: ConfHigh,
					Title:    "Possible secret in git history: " + rule.id,
					FilePath: file,
					Excerpt:  redact(added),
					Detail: map[string]any{
						"rule": rule.id, "commit": commit, "column": start + 1,
						"reason": "the secret is in every clone of the repository even if a later commit removed it; rotate it",
					},
					Taxonomy: []string{"LLM03"},
				}
				if rule.id == privateKeyRule {
					// A key opened earlier on this line ends here.
					closeKey()
					key = &pendingKey{finding: f}
					readKey(added[end:])
					continue
				}
				add(secretKey(rule.id, cand), f)
			}
		}
	}
	if serr := sc.Err(); serr != nil {
		if serr == bufio.ErrTooLong {
			return done(), false, fmt.Errorf("history patch line longer than %s bytes", strconv.Itoa(historyMaxLine))
		}
		return done(), false, serr
	}
	closeKey()
	return done(), false, nil
}

// leastSevere is the index of the least severe of findings, the last of
// them on a tie.
func leastSevere(findings []Finding) int {
	least := 0
	for i := range findings {
		if severityRank(findings[i].Severity) <= severityRank(findings[least].Severity) {
			least = i
		}
	}
	return least
}

// pendingKey is a private key the history scan has found the BEGIN line
// of and is reading the body of.
type pendingKey struct {
	finding Finding
	body    strings.Builder
}

// secretRuleRe is the pattern of the secret rule with the given id.
func secretRuleRe(id string) *regexp.Regexp {
	for _, rule := range secretRules {
		if rule.id == id {
			return rule.re
		}
	}
	panic("scan: no secret rule " + id)
}
