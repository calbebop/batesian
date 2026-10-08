// Batesian is an adversarial red-team CLI for AI agent protocols.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/calbebop/batesian/internal/cli"
	"github.com/calbebop/batesian/internal/report"
)

// Release builds inject version metadata with -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version, commit, date)

	// Signals cancel in-flight work so cleanup can run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", report.EscapeTerminal(err.Error()))
		stop()
		os.Exit(1)
	}
}
