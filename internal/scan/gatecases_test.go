package scan

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/gatecases"
)

// TestGateCases runs every case of the gate's published table
// (pkg/gatecases, agentry#776) against Evaluate. A change to the gate that
// moves an outcome fails here until the table follows, and the table is what
// a client restating the gate's rule tests itself against.
func TestGateCases(t *testing.T) {
	table := loadGateCases(t)
	for _, c := range table.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := Evaluate(gateInputOf(t, table, c))
			if string(got.Outcome) != c.Want.Outcome || got.Queue != c.Want.Queue {
				t.Fatalf("got %s/%q, the table says %s/%q (%s)", got.Outcome, got.Queue, c.Want.Outcome, c.Want.Queue, got.Reason)
			}
			if got.branch != c.Branch {
				t.Fatalf("decided by %q, the table says %q (%s)", got.branch, c.Branch, got.Reason)
			}
		})
	}
}

// TestGateCasesBaselineIsTheRegistrysBaseline holds the table's baseline to
// the compiled-in platform baseline, so a moved threshold fails until the
// table's baseline, and the cases decided under it, follow.
func TestGateCasesBaselineIsTheRegistrysBaseline(t *testing.T) {
	table := loadGateCases(t)
	got, err := json.Marshal(policyOf(t, table.Baseline))
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(DefaultBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("the table's baseline is %s, the registry's %s", got, want)
	}
}

// TestGateCasesCoverEveryBranch is the coverage check: every return in
// Evaluate names its branch, and every branch is reached by a case. A new
// branch, or a return that names none, fails here until the table has it.
func TestGateCasesCoverEveryBranch(t *testing.T) {
	branches := evaluateBranches(t)
	reached := map[string]bool{}
	for _, c := range loadGateCases(t).Cases {
		reached[c.Branch] = true
	}
	for _, b := range branches {
		if !reached[b] {
			t.Errorf("no case in pkg/gatecases reaches the gate's branch %q", b)
		}
	}
}

// TestGateCasesCoverTheGrid checks the cases the issue names beyond the
// branches: each severity against each maxAutoPublishSeverity, a
// low-confidence finding that does not gate alone, both queues, and every
// finding that says content could not be scanned.
func TestGateCasesCoverTheGrid(t *testing.T) {
	table := loadGateCases(t)
	sevs := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	grid := map[[2]Severity]bool{}
	queues := map[string]bool{}
	unread := map[string]bool{}
	lowConfidenceAlone := false
	for _, c := range table.Cases {
		queues[c.Want.Queue] = true
		for _, f := range c.Findings {
			if couldNotScanScanners[f.Scanner] && c.Branch == branchCouldNotScan {
				unread[f.Scanner] = true
			}
		}
		threshold := Severity(table.PolicyOf(c).MaxAutoPublishSeverity)
		if c.Policy != nil && len(c.Findings) == 1 && plain(c) {
			if f := c.Findings[0]; f.Confidence != string(ConfLow) {
				grid[[2]Severity{Severity(f.Severity), threshold}] = true
			}
		}
		for _, f := range c.Findings {
			if f.Confidence == string(ConfLow) && severityRank(Severity(f.Severity)) > severityRank(threshold) &&
				c.Want.Outcome == gatecases.OutcomePublished && plain(c) {
				lowConfidenceAlone = true
			}
		}
	}
	for _, s := range sevs {
		for _, th := range sevs {
			if !grid[[2]Severity{s, th}] {
				t.Errorf("no case puts a single %s finding against maxAutoPublishSeverity %s", s, th)
			}
		}
	}
	if !lowConfidenceAlone {
		t.Error("no case shows a low-confidence finding above the threshold that does not gate alone")
	}
	for _, q := range []string{"platform", "org"} {
		if !queues[q] {
			t.Errorf("no case sends a version to the %s queue", q)
		}
	}
	for s := range couldNotScanScanners {
		if !unread[s] {
			t.Errorf("no case holds %s as content that could not be scanned", s)
		}
	}
}

// plain is a case with no flag and no requireHumanReview beyond "never".
func plain(c gatecases.Case) bool {
	never := c.Policy == nil || len(c.Policy.RequireHumanReview) == 0 || string(c.Policy.RequireHumanReview) == `"never"`
	return never && !c.WildcardEgress && !c.JudgeForcesReview && len(c.DeclaredCapabilities) == 0 && !c.Public && !c.NamespaceIsOrg
}

func loadGateCases(t *testing.T) gatecases.Table {
	t.Helper()
	table, err := gatecases.Load()
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// policyOf passes a table policy through ParsePolicy, so the table holds
// only policies the registry would accept.
func policyOf(t *testing.T, p gatecases.Policy) Policy {
	t.Helper()
	doc, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := ParsePolicy(doc)
	if err != nil {
		t.Fatalf("the table's policy %s: %v", doc, err)
	}
	return pol
}

func gateInputOf(t *testing.T, table gatecases.Table, c gatecases.Case) GateInput {
	t.Helper()
	in := GateInput{
		Policy:               policyOf(t, table.PolicyOf(c)),
		JudgeForcesReview:    c.JudgeForcesReview,
		DeclaredCapabilities: map[string]bool{},
		WildcardEgress:       c.WildcardEgress,
		Public:               c.Public,
		NamespaceIsOrg:       c.NamespaceIsOrg,
	}
	for _, cap := range c.DeclaredCapabilities {
		in.DeclaredCapabilities[cap] = true
	}
	for _, f := range c.Findings {
		in.Findings = append(in.Findings, Finding{
			Scanner: f.Scanner, Severity: Severity(f.Severity), Confidence: Confidence(f.Confidence), Title: f.Scanner,
		})
	}
	return in
}

// evaluateBranches reads gate.go and returns the branch each return in
// Evaluate names, failing on a return that names none.
func evaluateBranches(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "gate.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{}
	var evaluate *ast.FuncDecl
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == "Evaluate" && d.Recv == nil {
				evaluate = d
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && strings.HasPrefix(name.Name, "branch") {
						consts[name.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
		}
	}
	if evaluate == nil {
		t.Fatal("no Evaluate in gate.go")
	}
	set := map[string]bool{}
	ast.Inspect(evaluate.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		var named []string
		ast.Inspect(ret, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok {
				if v, ok := consts[id.Name]; ok {
					named = append(named, v)
				}
			}
			return true
		})
		if len(named) != 1 {
			t.Errorf("the return at %s names %d branches, want one", fset.Position(ret.Pos()), len(named))
			return true
		}
		set[named[0]] = true
		return true
	})
	var out []string
	for b := range set {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}
