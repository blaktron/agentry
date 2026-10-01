// Command ruleset-digest prints the semantic version and the digest of a rule
// bundle directory, computed by the loader the server records it with, so a
// ruleset_releases row can be checked against the bundle a ruleset/v<semver>
// tag holds (agentry#772; pkg/ruleset/README.md). With no argument it reads
// ./rules.
package main

import (
	"fmt"
	"os"

	"github.com/blaktron/agentry/pkg/rules"
)

func main() {
	dir := "rules"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	// The server loads the embedded copy at its root ("."), and the digest
	// mixes in each file's path, so the directory is opened as the root here.
	b, err := rules.LoadBundle(os.DirFS(dir), ".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ruleset-digest:", err)
		os.Exit(1)
	}
	fmt.Printf("%s %s\n", b.Version(), b.Digest())
}
