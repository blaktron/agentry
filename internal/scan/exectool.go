package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// External scanner tools (§8.3: gitleaks for S2, opengrep for S6). DEV-006
// shipped the native detectors with these as the production upgrade; the
// adapters here exec the real binary against the extracted archive and fold
// its report into the stage's findings (agentry#40). Rules of the road:
//
//   - The tool is optional. A nil adapter means "native only"; a configured
//     adapter whose binary is missing is a startup error, not a silent skip.
//   - Tool failure is visible. A non-zero exit, a timeout or unparseable
//     output produces one `<stage>/tool-error` finding (medium) so the report
//     says "gitleaks did not run" rather than "no secrets".
//   - Output is bounded (8 MiB) and the tool runs with a scrubbed environment
//     in the archive directory — never against the git repo, never with the
//     server's credentials in its environment.
//   - Findings the native rules already produced at the same file:line are
//     not duplicated; the tool's hit is recorded as corroboration instead.

const (
	execToolDefaultTimeout = 2 * time.Minute
	execToolOutputCap      = 8 << 20
	execToolMaxFindings    = 500
)

// ExecTool describes one external binary.
type ExecTool struct {
	// Bin is the binary path. ResolveExecTool turns "auto" into a PATH lookup.
	Bin string
	// Rules is the rules file/dir for tools that take one (opengrep).
	Rules string
	// Timeout bounds one invocation; 0 means execToolDefaultTimeout.
	Timeout time.Duration
}

// ResolveExecTool validates a configured tool: "" → nil (disabled), "auto"
// → PATH lookup, else the path must exist and be executable.
func ResolveExecTool(name, bin, rules string, timeout time.Duration) (*ExecTool, error) {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return nil, nil
	}
	if bin == "auto" {
		p, err := exec.LookPath(name)
		if err != nil {
			return nil, fmt.Errorf("scan: %s: not on PATH (set AGENTRY_SCAN_%s_BIN to a path or unset it)", name, strings.ToUpper(name))
		}
		bin = p
	}
	st, err := os.Stat(bin)
	if err != nil {
		return nil, fmt.Errorf("scan: %s: %w", name, err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("scan: %s: %s is not an executable file", name, bin)
	}
	if rules != "" {
		if _, err := os.Stat(rules); err != nil {
			return nil, fmt.Errorf("scan: %s rules: %w", name, err)
		}
	}
	return &ExecTool{Bin: bin, Rules: rules, Timeout: timeout}, nil
}

// run execs the tool in dir with a scrubbed environment and returns stdout.
// stderr rides in the error.
func (t *ExecTool) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = execToolDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.Bin, args...) //nolint:gosec // operator-configured binary, fixed argv
	cmd.Dir = dir
	home, err := os.MkdirTemp("", "agentry-tool-home-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"TMPDIR=" + home,
		"XDG_CACHE_HOME=" + home,
		"LANG=C.UTF-8",
		"NO_COLOR=1",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: execToolOutputCap}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("timed out after %s", timeout)
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return stdout.Bytes(), &execExit{code: ee.ExitCode(), stderr: strings.TrimSpace(stderr.String())}
		}
		return nil, runErr
	}
	return stdout.Bytes(), nil
}

// execExit is a non-zero exit with the tool's stderr, so callers that treat
// "findings present" exit codes as success can tell them apart from crashes.
type execExit struct {
	code   int
	stderr string
}

func (e *execExit) Error() string {
	if e.stderr == "" {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return fmt.Sprintf("exit status %d: %s", e.code, firstLine(e.stderr))
}

type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.w.Len() >= l.n {
		return len(p), nil // drop silently; the cap is the point
	}
	room := l.n - l.w.Len()
	if len(p) > room {
		_, _ = l.w.Write(p[:room])
		return len(p), nil
	}
	return l.w.Write(p)
}

func toolErrorFinding(stage, tool string, err error) Finding {
	return Finding{
		Scanner: stage + "/tool-error", Severity: SevMedium, Confidence: ConfHigh,
		Title:    tool + " did not complete",
		Detail:   map[string]any{"tool": tool, "error": err.Error()},
		Taxonomy: []string{"LLM03"},
	}
}

// relPath normalizes a tool-reported path to the archive-relative form the
// rest of the report uses.
func relPath(dir, p string) string {
	p = filepath.ToSlash(strings.TrimSpace(p))
	if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") && filepath.IsAbs(p) {
		p = filepath.ToSlash(rel)
	}
	return strings.TrimPrefix(p, "./")
}

// ---- gitleaks (S2) --------------------------------------------------------

// gitleaksFinding is the subset of gitleaks' JSON report S2 consumes.
type gitleaksFinding struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	Match       string  `json:"Match"`
	Entropy     float64 `json:"Entropy"`
	Tags        []string
}

// runGitleaks scans dir with gitleaks and returns S2 findings. `seen` holds
// the native rules' file|line keys; a gitleaks hit on the same line
// corroborates rather than duplicates.
func runGitleaks(ctx context.Context, t *ExecTool, dir string, seen map[string]bool) []Finding {
	report, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return []Finding{toolErrorFinding("S2", "gitleaks", err)}
	}
	_ = report.Close()
	defer func() { _ = os.Remove(report.Name()) }()

	// `detect --no-git` reads the tree as files (the archive is not a repo);
	// --exit-code 0 keeps "leaks found" from reading as a crash.
	_, err = t.run(ctx, dir, "detect", "--no-git", "--source", ".", "--no-banner",
		"--exit-code", "0", "--report-format", "json", "--report-path", report.Name())
	if err != nil {
		return []Finding{toolErrorFinding("S2", "gitleaks", err)}
	}
	raw, err := os.ReadFile(report.Name())
	if err != nil {
		return []Finding{toolErrorFinding("S2", "gitleaks", err)}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var hits []gitleaksFinding
	if err := json.Unmarshal(raw, &hits); err != nil {
		return []Finding{toolErrorFinding("S2", "gitleaks", fmt.Errorf("report: %w", err))}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		if hits[i].StartLine != hits[j].StartLine {
			return hits[i].StartLine < hits[j].StartLine
		}
		return hits[i].RuleID < hits[j].RuleID
	})
	var out []Finding
	for _, h := range hits {
		if len(out) >= execToolMaxFindings {
			break
		}
		path := relPath(dir, h.File)
		key := path + "|" + fmt.Sprint(h.StartLine)
		detail := map[string]any{"tool": "gitleaks", "rule": h.RuleID, "entropy": h.Entropy}
		if seen[key] {
			detail["corroborates"] = true
		}
		end := h.EndLine
		if end < h.StartLine {
			end = h.StartLine
		}
		out = append(out, Finding{
			Scanner: "S2/gitleaks-" + sanitizeRuleID(h.RuleID), Severity: SevHigh, Confidence: ConfHigh,
			Title:    "Possible secret (gitleaks): " + firstNonEmpty(h.Description, h.RuleID),
			FilePath: path, LineStart: h.StartLine, LineEnd: end,
			Excerpt:  redact(h.Match),
			Detail:   detail,
			Taxonomy: []string{"LLM03"},
		})
	}
	return out
}

// ---- opengrep (S6) --------------------------------------------------------

// opengrepReport is the subset of the semgrep-compatible JSON report S6
// consumes.
type opengrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string         `json:"message"`
			Severity string         `json:"severity"`
			Lines    string         `json:"lines"`
			Metadata map[string]any `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"errors"`
}

// runOpengrep scans dir with opengrep against t.Rules. A rule whose
// metadata carries `capability` (network | exec | fs-write | env | eval |
// fs-read) is a capability detector: its hits join the native detections and
// go through the same declared-vs-detected compare, so an undeclared one
// surfaces as the usual `S6/undeclared-<cap>` finding. Other rules surface as
// `S6/opengrep-<rule>` with the rule's own severity.
func runOpengrep(ctx context.Context, t *ExecTool, dir string) ([]Finding, map[string][]detection) {
	out, err := t.run(ctx, dir, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
		"--config", t.Rules, ".")
	var ee *execExit
	// opengrep exits 1 when findings exist; only other non-zero codes are
	// failures.
	findingsExit := errors.As(err, &ee) && ee.code == 1 && len(bytes.TrimSpace(out)) > 0
	if err != nil && !findingsExit {
		return []Finding{toolErrorFinding("S6", "opengrep", err)}, nil
	}
	var rep opengrepReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return []Finding{toolErrorFinding("S6", "opengrep", fmt.Errorf("report: %w", err))}, nil
	}
	sort.SliceStable(rep.Results, func(i, j int) bool {
		a, b := rep.Results[i], rep.Results[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Start.Line != b.Start.Line {
			return a.Start.Line < b.Start.Line
		}
		return a.CheckID < b.CheckID
	})
	var findings []Finding
	detected := map[string][]detection{}
	for _, r := range rep.Results {
		path := relPath(dir, r.Path)
		capTok, _ := r.Extra.Metadata["capability"].(string)
		capTok = strings.ToLower(strings.TrimSpace(capTok))
		if capTok != "" {
			detected[capTok] = append(detected[capTok], detection{file: path, line: r.Start.Line})
			continue
		}
		if len(findings) >= execToolMaxFindings {
			continue
		}
		sev := SevMedium
		switch strings.ToUpper(r.Extra.Severity) {
		case "ERROR", "CRITICAL", "HIGH":
			sev = SevHigh
		case "INFO", "LOW":
			sev = SevLow
		}
		findings = append(findings, Finding{
			Scanner: "S6/opengrep-" + sanitizeRuleID(shortCheckID(r.CheckID)), Severity: sev, Confidence: ConfMedium,
			Title:    firstNonEmpty(firstLine(r.Extra.Message), r.CheckID),
			FilePath: path, LineStart: r.Start.Line, LineEnd: r.End.Line,
			Excerpt:  firstLine(r.Extra.Lines),
			Detail:   map[string]any{"tool": "opengrep", "rule": r.CheckID},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	for _, e := range rep.Errors {
		if strings.EqualFold(e.Level, "error") {
			findings = append(findings, toolErrorFinding("S6", "opengrep", errors.New(firstLine(e.Message))))
			break
		}
	}
	return findings, detected
}

// shortCheckID keeps the last path segment of a semgrep-style check id
// ("rules.agentry.net.raw-socket" → "raw-socket").
func shortCheckID(id string) string {
	if i := strings.LastIndex(id, "."); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// sanitizeRuleID keeps finding ids to the [a-z0-9-] vocabulary the report
// consumers and the §8.6 policy matcher expect.
func sanitizeRuleID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "rule"
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
