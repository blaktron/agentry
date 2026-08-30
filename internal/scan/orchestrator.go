package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/pkg/rules"
)

// Orchestrator runs the scanner DAG (§8.2): S1 first (builds the inventory),
// then S2–S9 in parallel, then S10 assembles the report and computes the
// gate. Each stage has a timeout and fails closed (§7 timeout rule): a stage
// error becomes an S0/pipeline-error finding that forces review, never a
// silent pass.
type Orchestrator struct {
	bundle *rules.Bundle
	judge  JudgeProvider
	log    *slog.Logger
	// stageTimeout bounds one stage; scanTimeout bounds the whole run.
	stageTimeout time.Duration
	scanTimeout  time.Duration
	// mx records §16.2 per-stage durations and the ScanStageRuns/
	// ScanStageErrors pair the §16.3 error-rate page alarm divides. nil is a
	// working no-op.
	mx *metrics.Metrics
}

// SetMetrics wires the §16.2 instrument set.
func (o *Orchestrator) SetMetrics(m *metrics.Metrics) { o.mx = m }

// NewOrchestrator builds the orchestrator with the loaded ruleset and judge.
func NewOrchestrator(bundle *rules.Bundle, judge JudgeProvider, log *slog.Logger) *Orchestrator {
	if log == nil {
		log = slog.Default()
	}
	if judge == nil {
		judge = NoneProvider{}
	}
	return &Orchestrator{
		bundle: bundle, judge: judge, log: log,
		stageTimeout: 5 * time.Minute,
		scanTimeout:  30 * time.Minute, // §7: scanning > 30 min ⇒ error → review
	}
}

// RunParams configures one scan run.
type RunParams struct {
	Input  Input
	Policy Policy
	Public bool
	// NamespaceIsOrg routes review to the org queue (§8.6). Personal-namespace
	// agents have no org, so their reviews belong to the platform queue —
	// routing them to "org" produced an item with a NULL org_id that appeared
	// in neither queue listing and that nobody could decide.
	NamespaceIsOrg bool
	// PopularAgentNames + AgentName feed S8.
	PopularAgentNames []string
	AgentName         string
	// Resume carries stage results already known for this run: stages a
	// previous attempt completed (§8.2 idempotency, keyed by scan run and
	// scanner) or answered from the §8.7 results cache. Their findings are
	// folded in as though the stages had just run, so the report and the gate
	// see the complete set.
	Resume Resume
	// OnStage, when set, is called once per stage that actually executes,
	// before the run finishes. The pipeline uses it to persist stage results
	// incrementally so a retry does not re-run — or duplicate — them. It may
	// be called concurrently.
	OnStage func(StageResult)
}

// Resume describes work this run does not have to repeat.
type Resume struct {
	// Skip names stages whose results are already known. S1 is never
	// skippable: it builds the file inventory every other stage reads.
	Skip map[string]bool
	// Findings are the skipped stages' findings.
	Findings []Finding
}

func (r Resume) skips(id string) bool {
	if id == "S1" || len(r.Skip) == 0 {
		return false
	}
	return r.Skip[id]
}

// CacheableStages are the deterministic scanners a rescan may answer from the
// results cache keyed (digest, scanner, ruleset) — §8.7. S1 always runs (it
// is the inventory), S5 is the judge (re-adjudicated only on major bumps),
// S9 depends on the previous published version rather than on these bytes.
func CacheableStages() []string { return []string{"S2", "S3S4", "S6", "S7", "S8"} }

// Report is the S10 canonical report (§8.3 S10). Field order is fixed and
// slices are sorted so ReportDigest is reproducible.
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Findings      []Finding `json:"findings"`
	StageErrors   []string  `json:"stageErrors"`
	JudgeModel    string    `json:"judgeModel"`
	// Decision is the gate outcome.
	Decision GateDecision `json:"decision"`
}

// RunResult bundles the report with its digest and the effective judge model.
type RunResult struct {
	Report       Report
	ReportDigest string // sha256 of canonical report JSON
	Findings     []Finding
	Decision     GateDecision
	JudgeModel   string
	// JudgePromptHash identifies the rubric/prompt version S5 adjudicated
	// with (§8.4.4: recorded per run for reproducibility and appeals).
	JudgePromptHash string
	// Fatal is set when the run could not produce a usable result at all —
	// today, only a report that will not serialize, which would otherwise
	// yield an empty report digest and carry that emptiness into a SIGNED
	// attestation. The caller must not publish on a fatal run.
	Fatal error
	// Ran lists the stages that actually executed (skipped ones excluded).
	Ran []StageResult
	// Skipped names the stages whose results came from Resume rather than
	// from running them: §8.7 results-cache hits, or stages a previous
	// attempt at this run had already completed.
	Skipped []string
}

// Run executes the full pipeline synchronously (§8.2). The worker calls this
// from a queue handler; tests call it directly. Idempotency at the DB layer
// is handled by the caller (scan_stage_results keys); Run itself is pure
// over its Input.
func (o *Orchestrator) Run(ctx context.Context, p RunParams) RunResult {
	ctx, cancel := context.WithTimeout(ctx, o.scanTimeout)
	defer cancel()

	sc := stageContext{ctx: ctx, bundle: o.bundle, judge: o.judge, log: o.log}
	in := &p.Input

	// Stages already answered (a previous attempt, or the §8.7 cache) come in
	// first so the report, S9's escalation input and the gate all see the
	// complete finding set — a resumed run must decide exactly as a fresh one.
	allFindings := append([]Finding{}, p.Resume.Findings...)
	var stageErrs []string
	var ran []StageResult
	var skipped []string
	var ranMu sync.Mutex

	record := func(res StageResult) {
		ranMu.Lock()
		ran = append(ran, res)
		ranMu.Unlock()
		if p.OnStage != nil {
			p.OnStage(res)
		}
	}
	// exec runs a stage unless its result is already known.
	exec := func(st Stage) StageResult {
		if p.Resume.skips(st.ID()) {
			ranMu.Lock()
			skipped = append(skipped, st.ID())
			ranMu.Unlock()
			return StageResult{Scanner: st.ID(), Skipped: true}
		}
		res := o.runStage(sc, st, in)
		record(res)
		return res
	}

	// S1 first — it populates in.Files for everyone else, so it always runs.
	s1 := o.runStage(sc, S1Inventory{}, in)
	record(s1)
	allFindings = append(allFindings, s1.Findings...)
	if s1.Err != nil {
		stageErrs = append(stageErrs, "S1: "+s1.Err.Error())
	}

	// S2–S8 in parallel (S9 needs the others' findings; run it after).
	parallel := []Stage{
		S2Secrets{},
		S3S4Content{},
		S5Judge{},
		S6Capabilities{},
		S7Dependencies{},
		S8Metadata{PopularAgentNames: p.PopularAgentNames, AgentName: p.AgentName},
	}
	results := make([]StageResult, len(parallel))
	var wg sync.WaitGroup
	for i, st := range parallel {
		wg.Add(1)
		go func(i int, st Stage) {
			defer wg.Done()
			results[i] = exec(st)
		}(i, st)
	}
	wg.Wait()

	judgeForcesReview := o.judge.RequiresHumanReview()
	judgePromptHash := ""
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
		if r.Scanner == "S5" && r.PromptHash != "" {
			judgePromptHash = r.PromptHash
		}
		if r.Err != nil {
			stageErrs = append(stageErrs, r.Scanner+": "+r.Err.Error())
			judgeForcesReview = judgeForcesReview || r.Scanner == "S5"
		}
	}

	// S9 last (reads the accumulated findings to escalate).
	s9 := exec(S9ReleaseDiff{CurrentFindings: allFindings})
	allFindings = append(allFindings, s9.Findings...)
	if s9.Err != nil {
		stageErrs = append(stageErrs, "S9: "+s9.Err.Error())
	}

	// Any stage error ⇒ fail closed with a pipeline-error finding (§7).
	if len(stageErrs) > 0 {
		allFindings = append(allFindings, Finding{
			Scanner: "S0/pipeline-error", Severity: SevMedium, Confidence: ConfHigh,
			Title:  "Pipeline stage error — routed to human review",
			Detail: map[string]any{"errors": stageErrs},
		})
		judgeForcesReview = true
	}

	// S10 — assemble the canonical report and compute the gate.
	sortFindings(allFindings)
	decl := declaredCaps(in.ManifestJSON)
	decision := Evaluate(GateInput{
		Findings:             allFindings,
		Policy:               p.Policy,
		JudgeForcesReview:    judgeForcesReview,
		DeclaredCapabilities: decl,
		WildcardEgress:       egressSet(in.ManifestJSON)["*"],
		Public:               p.Public,
		NamespaceIsOrg:       p.NamespaceIsOrg,
	})

	report := Report{
		SchemaVersion: "1",
		Findings:      allFindings,
		StageErrors:   stageErrs,
		JudgeModel:    o.judge.Name(),
		Decision:      decision,
	}
	digest, digestErr := reportDigest(report)
	out := RunResult{
		Report: report, ReportDigest: digest,
		Findings: allFindings, Decision: decision, JudgeModel: o.judge.Name(),
		JudgePromptHash: judgePromptHash, Ran: ran, Skipped: skipped,
	}
	if digestErr != nil {
		// The digest is the subject of the DSSE attestation (§8.8). An empty
		// one must never reach a signature, so this ends the run rather than
		// degrading it: the caller fails the version toward review.
		o.log.Error("scan: report digest", "err", digestErr)
		out.Fatal = digestErr
	}
	return out
}

// runStage applies a per-stage timeout and converts a panic into a stage
// error (fail closed, never crash the worker).
func (o *Orchestrator) runStage(sc stageContext, st Stage, in *Input) (res StageResult) {
	stageCtx, cancel := context.WithTimeout(sc.ctx, o.stageTimeout)
	defer cancel()
	inner := sc
	inner.ctx = stageCtx

	// §16.2 stage telemetry. Deferred on the named return so the timeout path
	// below is measured too — a stage that hangs is exactly the one the
	// error-rate alarm needs to hear about.
	start := time.Now()
	defer func() {
		o.mx.RecordScanStage(sc.ctx, st.ID(), time.Since(start), len(res.Findings), res.Err)
	}()

	done := make(chan StageResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				pe := panicErr(st.ID(), r)
				// A panicking scanner is a bug in OUR code reached by
				// attacker-supplied bytes; the stack is the only way to find
				// it, and it must not be the thing we throw away.
				o.log.Error("scan: stage panic", "stage", st.ID(),
					"panic", r, "stack", string(pe.stack))
				done <- StageResult{Scanner: st.ID(), Err: pe}
			}
		}()
		done <- st.Run(inner, in)
	}()
	select {
	case res = <-done:
		return res
	case <-stageCtx.Done():
		return StageResult{Scanner: st.ID(), Err: stageCtx.Err()}
	}
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Scanner != f[j].Scanner {
			return f[i].Scanner < f[j].Scanner
		}
		if f[i].FilePath != f[j].FilePath {
			return f[i].FilePath < f[j].FilePath
		}
		return f[i].LineStart < f[j].LineStart
	})
}

// reportDigest computes the sha256 over canonical report JSON (§8.3 S10;
// goes into the attestation, §8.8). A marshal failure is returned, never
// swallowed into an empty digest: the digest is what the signature commits
// to, so "" would attest to nothing at all.
func reportDigest(r Report) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("scan: canonical report: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// panicError carries what a recovered stage panic actually said, plus the
// stack. Discarding the value left "panic in stage" as the sole evidence of
// a crash reachable from untrusted package content.
type panicError struct {
	stage string
	value any
	stack []byte
}

func (e panicError) Error() string {
	return fmt.Sprintf("panic in stage %s: %v", e.stage, e.value)
}

// Value returns the recovered panic value (tests, diagnostics).
func (e panicError) Value() any { return e.value }

func panicErr(stage string, v any) panicError {
	return panicError{stage: stage, value: v, stack: debug.Stack()}
}
