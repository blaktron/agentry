package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
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
}

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
	// PopularAgentNames + AgentName feed S8.
	PopularAgentNames []string
	AgentName         string
}

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

	var allFindings []Finding
	var stageErrs []string

	// S1 first — it populates in.Files for everyone else.
	s1 := o.runStage(sc, S1Inventory{}, in)
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
			results[i] = o.runStage(sc, st, in)
		}(i, st)
	}
	wg.Wait()

	judgeForcesReview := o.judge.RequiresHumanReview()
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
		if r.Err != nil {
			stageErrs = append(stageErrs, r.Scanner+": "+r.Err.Error())
			judgeForcesReview = judgeForcesReview || r.Scanner == "S5"
		}
	}

	// S9 last (reads the accumulated findings to escalate).
	s9 := o.runStage(sc, S9ReleaseDiff{CurrentFindings: allFindings}, in)
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
	})

	report := Report{
		SchemaVersion: "1",
		Findings:      allFindings,
		StageErrors:   stageErrs,
		JudgeModel:    o.judge.Name(),
		Decision:      decision,
	}
	digest := reportDigest(report)
	return RunResult{
		Report: report, ReportDigest: digest,
		Findings: allFindings, Decision: decision, JudgeModel: o.judge.Name(),
	}
}

// runStage applies a per-stage timeout and converts a panic into a stage
// error (fail closed, never crash the worker).
func (o *Orchestrator) runStage(sc stageContext, st Stage, in *Input) (res StageResult) {
	stageCtx, cancel := context.WithTimeout(sc.ctx, o.stageTimeout)
	defer cancel()
	inner := sc
	inner.ctx = stageCtx

	done := make(chan StageResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- StageResult{Scanner: st.ID(), Err: panicErr(r)}
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
// goes into the attestation, §8.8).
func reportDigest(r Report) string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type panicError struct{ v any }

func (e panicError) Error() string { return "panic in stage" }

func panicErr(v any) error { return panicError{v: v} }
