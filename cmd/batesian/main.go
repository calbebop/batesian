// Batesian is an adversarial red-team CLI for AI agent protocols.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/calbebop/batesian/internal/cli"
)

// Version variables are injected at build time by goreleaser via -ldflags.
// Defaults make `go run ./cmd/batesian` display useful information in development.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version, commit, date)

	// Interrupt and SIGTERM cancel the context cobra hands to every command,
	// which propagates into executor HTTP requests and the engine's
	// between-rules checks: a Ctrl+C now unwinds in-flight work and runs the
	// cleanup defers (OOB listeners especially) instead of killing the
	// process with ports still bound. The second signal restores immediate
	// termination for an operator who wants out regardless.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		stop()
		os.Exit(1)
	}
}
