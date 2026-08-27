// agentry is the developer CLI (§11). M0 ships the skeleton (version, help);
// commands land with WG-F (M3).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "agentry",
		Short:         "Agentry CLI — develop, validate, publish, and install single-purpose agents",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
