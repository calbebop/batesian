package mcp_test

import "github.com/calbebop/batesian/internal/attack"

// testOpts returns the default execution options used across MCP executor tests:
// a short per-request timeout and no auth/OOB configuration.
func testOpts() attack.Options {
	return attack.Options{TimeoutSeconds: 5}
}
