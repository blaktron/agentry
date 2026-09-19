// Command dbexec runs SQL statements against the acceptance database, one
// per argument, for the acceptance scripts that need a fact the API never
// exposes — an address marked verified, since the verification token never
// leaves the server (docs/logging.md). It reads AGENTRY_TEST_DATABASE_URL,
// else AGENTRY_DATABASE_URL, and needs no psql on the machine: the scripts
// already have a Go toolchain (scripts/acceptance/ui.sh).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dbexec <sql> [<sql>...]")
		os.Exit(2)
	}
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("AGENTRY_DATABASE_URL")
	}
	if url == "" {
		fmt.Fprintln(os.Stderr, "dbexec: set AGENTRY_TEST_DATABASE_URL or AGENTRY_DATABASE_URL")
		os.Exit(2)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dbexec:", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, stmt := range os.Args[1:] {
		tag, err := conn.Exec(ctx, stmt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dbexec:", err)
			os.Exit(1)
		}
		fmt.Println(tag.String())
	}
}
