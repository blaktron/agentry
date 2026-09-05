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

// External scanner tools (§8.3: gitleaks for S2). DEV-006
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
	// Rules is the rules file/dir for tools that take one; none do today.
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

// gitleaksErrorFinding records that the one external tool left, gitleaks
// (S2), did not complete; the native detectors still ran.
func gitleaksErrorFinding(err error) Finding {
	const stage, tool = "S2", "gitleaks"
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
		return []Finding{gitleaksErrorFinding(err)}
	}
	_ = report.Close()
	defer func() { _ = os.Remove(report.Name()) }()

	// `detect --no-git` reads the tree as files (the archive is not a repo);
	// --exit-code 0 keeps "leaks found" from reading as a crash.
	_, err = t.run(ctx, dir, "detect", "--no-git", "--source", ".", "--no-banner",
		"--exit-code", "0", "--report-format", "json", "--report-path", report.Name())
	if err != nil {
		return []Finding{gitleaksErrorFinding(err)}
	}
	raw, err := os.ReadFile(report.Name())
	if err != nil {
		return []Finding{gitleaksErrorFinding(err)}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var hits []gitleaksFinding
	if err := json.Unmarshal(raw, &hits); err != nil {
		return []Finding{gitleaksErrorFinding(fmt.Errorf("report: %w", err))}
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

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
