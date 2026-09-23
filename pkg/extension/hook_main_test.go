package extension

import (
	"os"
	"testing"

	"github.com/blaktron/agentry/internal/gitsrv"
)

// TestMain doubles as the git hook shim: the git role runs its pre-receive
// hook once at startup (agentry#495), and in a test the executable it runs
// is this test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "hook" && os.Args[2] == "pre-receive" {
		os.Exit(gitsrv.RunPreReceiveHook(os.Stdin, os.Stderr))
	}
	os.Exit(m.Run())
}
