package manifest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestRulesMatchReportedIDs holds Rules() to the code: every rule id the
// package's sources report (the first argument of errf/warnf, or Rule in
// an Issue literal) is listed, and every listed rule is reported somewhere.
func TestRulesMatchReportedIDs(t *testing.T) {
	reported := reportedRuleIDs(t)
	listed := map[string]bool{}
	for _, r := range Rules() {
		if listed[r.ID] {
			t.Errorf("Rules() lists %s twice", r.ID)
		}
		listed[r.ID] = true
		if r.Title == "" {
			t.Errorf("Rules() gives %s no title", r.ID)
		}
		if !reported[r.ID] {
			t.Errorf("Rules() lists %s, but no Issue in the package reports it", r.ID)
		}
	}
	for id := range reported {
		if !listed[id] {
			t.Errorf("an Issue reports %s, but Rules() does not list it", id)
		}
	}
}

func TestRulesIsACopy(t *testing.T) {
	r := Rules()
	r[0].ID = "X"
	if Rules()[0].ID != "V1" {
		t.Fatal("mutating the result of Rules() changed the package's list")
	}
}

// reportedRuleIDs parses the package's non-test sources and returns the
// rule ids they report. A rule given as anything but a string literal
// fails the test, since it could not be checked.
func reportedRuleIDs(t *testing.T) map[string]bool {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	fset := token.NewFileSet()
	ids := map[string]bool{}
	literal := func(e ast.Expr, where string) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Errorf("%s: rule id is not a string literal", where)
			return
		}
		id, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		ids[id] = true
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p) //nolint:gosec // the package's own sources
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			// errf and warnf themselves pass their rule parameter through.
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && (fn.Name.Name == "errf" || fn.Name.Name == "warnf") {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if ok && (sel.Sel.Name == "errf" || sel.Sel.Name == "warnf") && len(n.Args) > 0 {
						literal(n.Args[0], fset.Position(n.Pos()).String())
					}
				case *ast.CompositeLit:
					if id, ok := n.Type.(*ast.Ident); ok && id.Name == "Issue" {
						for _, el := range n.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Rule" {
									literal(kv.Value, fset.Position(kv.Pos()).String())
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	if len(ids) == 0 {
		t.Fatal("found no reported rule ids; the scan is broken")
	}
	return ids
}
