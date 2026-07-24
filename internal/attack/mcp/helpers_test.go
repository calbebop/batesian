package mcp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// testOpts returns the default execution options used across MCP executor tests:
// a short per-request timeout and no auth/OOB configuration.
func testOpts() attack.Options {
	return attack.Options{TimeoutSeconds: 5}
}

// assertInconclusive runs an executor against target and fails the test unless it
// returned attack.ErrInconclusive. Used for the "not a testable MCP endpoint"
// case: the rule must signal that it could not test (skipped), not report a
// clean pass that is indistinguishable from "tested, nothing found".
func assertInconclusive(t *testing.T, exec attack.Executor, target string, opts attack.Options) {
	t.Helper()
	_, err := exec.Execute(context.Background(), target, opts)
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive (not a testable MCP endpoint), got err=%v", err)
	}
}
