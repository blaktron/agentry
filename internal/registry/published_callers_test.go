package registry

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// publishCallers lists every function in the module that asks the state
// machine for an edge into published, or for an edge whose target it does not
// name (a variable), and why that call has passed a gate. The state machine's
// edge table says which edges exist; this list says who may take one.
//
// A function appears here as "path/to/file.go:Func" and carries the gate its
// call has passed. A new caller fails the test until someone reads it and adds
// it with its reason; an entry whose call is gone fails too, so the list never
// outlives the code it describes.
var publishCallers = map[string]string{
	"internal/scan/pipeline.go:publishUnderLock": "takes a scan's result and refuses any verdict but publish; a submission, " +
		"the redo of the review queue and a reinstate's new scan all publish through it",
	"internal/scan/pipeline.go:DecideReview": "a reviewer's decision on a pending review item; the target is the one the " +
		"reviewer chose and the item is closed in the same transaction",
	"internal/scan/pipeline.go:PublishApproved": "publishes a version whose review item a reviewer approved, from needs_review",
	"internal/registry/versions.go:publishUnscanned": "the one edge that skips the gate, open only to a version an organization " +
		"administrator admitted unscanned on a private agent of the organization's (TestNoPathToPublishedSkipsTheGateForAPublicAgent)",
	"internal/registry/versions.go:Transition":     "forwards its caller's target; its callers are listed here when they name published",
	"internal/registry/versions.go:transitionWith": "forwards its caller's target; its callers are listed here when they name published",
	"internal/api/handlers_org_lifecycle.go:retireOrgContent": "the target is yanked or rejected, set by the switch above the call; " +
		"it never names published",
}

// transitionTargetArg is the index of the target-status argument of each state
// machine entry point.
var transitionTargetArg = map[string]int{
	"Transition":     2, // (ctx, id, to, reason, event)
	"TransitionWith": 2, // (ctx, id, to, reason, event, cause)
	"TransitionFrom": 3, // (ctx, id, from, to, reason, event, cause)
	"TransitionInTx": 3, // (ctx, q, id, to, reason, event)
}

// TestEveryCallerOfAnEdgeIntoPublishedPassedAGate is the invariant behind "no
// path to published skips the gate", stated for callers. TestStateMachineEdges
// fixes which edges the table allows; this test finds every call in the module
// that takes an edge into published, or takes an edge whose target is not a
// constant, and requires it to be one the gate or a person stands behind.
func TestEveryCallerOfAnEdgeIntoPublishedPassedAGate(t *testing.T) {
	root := moduleRoot(t)
	found := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return filepath.SkipDir
				}
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					idx, ok := transitionTargetArg[sel.Sel.Name]
					if !ok || len(call.Args) <= idx || !takesAnEdgeIntoPublished(call.Args[idx]) {
						return true
					}
					found[filepath.ToSlash(rel)+":"+fn.Name.Name] = true
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var unlisted, stale []string
	for k := range found {
		if _, ok := publishCallers[k]; !ok {
			unlisted = append(unlisted, k)
		}
	}
	for k := range publishCallers {
		if !found[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(unlisted)
	sort.Strings(stale)
	for _, k := range unlisted {
		t.Errorf("%s takes an edge into published (or one with a target it does not name) and is not in publishCallers: "+
			"it needs a gate verdict or a reviewer's decision behind it, and an entry saying which", k)
	}
	for _, k := range stale {
		t.Errorf("publishCallers lists %s, which no longer takes such an edge; remove the entry", k)
	}
}

// takesAnEdgeIntoPublished says whether a target argument is the published
// status or an expression that is not a status constant, so could be.
func takesAnEdgeIntoPublished(arg ast.Expr) bool {
	var name string
	switch a := arg.(type) {
	case *ast.Ident:
		name = a.Name
	case *ast.SelectorExpr:
		name = a.Sel.Name
	default:
		return true
	}
	if name == "StatusPublished" {
		return true
	}
	return !strings.HasPrefix(name, "Status")
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test file")
		}
		dir = parent
	}
}
