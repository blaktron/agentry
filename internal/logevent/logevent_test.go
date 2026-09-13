package logevent_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/logevent"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test")
		}
		dir = parent
	}
}

// The catalog is complete in both directions: every `event` the code emits
// is a catalogued constant (no string literal reaches a line), and every
// catalogued name is documented on the contract page, with the audit
// mirror's prefix.
func TestCatalogIsCompleteAndDocumented(t *testing.T) {
	root := moduleRoot(t)
	known := map[string]bool{}
	for _, e := range logevent.All {
		if e == "" || strings.ToLower(string(e)) != string(e) || strings.Contains(string(e), " ") {
			t.Errorf("%q is not a dotted lowercase name", e)
		}
		if known[string(e)] {
			t.Errorf("%q listed twice", e)
		}
		known[string(e)] = true
	}

	// Every string literal passed as the value of an "event" attribute
	// anywhere in the non-test Go source must be a catalogued name.
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == "vendor" || n == "prototype" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for i := 0; i+1 < len(call.Args); i++ {
				k, ok := call.Args[i].(*ast.BasicLit)
				if !ok || k.Kind != token.STRING || k.Value != `"event"` {
					continue
				}
				if v, ok := call.Args[i+1].(*ast.BasicLit); ok && v.Kind == token.STRING {
					name := strings.Trim(v.Value, "`\"")
					if !known[name] && !strings.HasPrefix(name, logevent.AuditPrefix) {
						t.Errorf("%s: event %q is not in the catalog", fset.Position(v.Pos()), name)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	doc, err := os.ReadFile(filepath.Join(root, "docs", "logging.md"))
	if err != nil {
		t.Fatalf("the contract page must exist: %v", err)
	}
	for _, e := range logevent.All {
		if !strings.Contains(string(doc), "`"+string(e)+"`") {
			t.Errorf("docs/logging.md does not document `%s`", e)
		}
	}
	if !strings.Contains(string(doc), "`"+logevent.AuditPrefix+"<action>`") {
		t.Errorf("docs/logging.md does not document the audit mirror's `%s<action>` names", logevent.AuditPrefix)
	}
}

func TestAttr(t *testing.T) {
	a := logevent.GateVerdict.Attr()
	if a.Key != "event" || a.Value.String() != "gate.verdict" {
		t.Fatalf("Attr = %v", a)
	}
	if logevent.Audit("user.login") != "audit.user.login" {
		t.Fatal("Audit prefix")
	}
}
