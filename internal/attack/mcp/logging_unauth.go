package mcp

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// LoggingUnauthExecutor probes whether the MCP logging/setLevel method is
// reachable without authentication (rule mcp-logging-unauth-001).
//
// logging/setLevel sets the server's minimum log verbosity; servers that support
// it advertise the "logging" capability. The MCP spec's Security section requires
// implementations to "control log access". logging/setLevel is state-changing: an
// anonymous caller who can set the level can flood logs at debug (cost/DoS, and
// burying attack traces in noise) or suppress them at emergency (hiding malicious
// activity from operators), so an unauthenticated setLevel is an access-control
// failure.
//
// SAFETY: the probe sends a deliberately INVALID level string, so a compliant
// server answers -32602 (invalid params) and changes nothing. The rule never
// alters the server's real log verbosity.
type LoggingUnauthExecutor struct {
	rule attack.RuleContext
}

// register the executor for the mcp-logging-unauth attack type.
func init() {
	attack.Register("mcp-logging-unauth", func(rc attack.RuleContext) attack.Executor { return NewLoggingUnauthExecutor(rc) })
}

// NewLoggingUnauthExecutor creates an executor for mcp-logging-unauth.
func NewLoggingUnauthExecutor(r attack.RuleContext) *LoggingUnauthExecutor {
	return &LoggingUnauthExecutor{rule: r}
}

func (e *LoggingUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token - the rule tests whether logging/setLevel
	// is reachable WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		// Not reachable as a legacy MCP server; inconclusive carries the reason
		// when the target turned out to be a modern-era server.
		return nil, inconclusive(err)
	}

	// Skip servers that do not advertise the logging capability; probing them would
	// produce meaningless noise. Read from the captured handshake object rather than
	// substring-matching the body.
	if !session.ServerSupports("logging") {
		return nil, nil
	}

	// Send logging/setLevel with an INVALID level so nothing is actually changed.
	// A compliant server rejects it with -32602 (invalid params) per the spec; a
	// server enforcing auth rejects at the auth layer first (401/403 or auth error).
	bogusLevel := "batesian-invalid-" + vars.RandID
	resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "logging/setLevel",
		"params":  map[string]interface{}{"level": bogusLevel},
	})
	verdict, body := classifyProbe(resp, err)
	if verdict != probeAnswered {
		if verdict == probeRejected {
			// An auth status, or a JSON-RPC error at a non-2xx: the surface is
			// closed or absent, which is a genuine clean result.
			return nil, nil
		}
		// Nothing was established. The request failed, or the reply carried no
		// protocol-level verdict, so reporting this surface clean would claim it
		// is secure when it was never tested.
		return nil, attack.ErrInconclusive
	}

	reachable, reason := setLevelDispatchReachable(body)
	if !reachable {
		return nil, nil
	}

	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP logging/setLevel reachable without authentication",
		Description: fmt.Sprintf(
			"logging/setLevel at %s dispatched an unauthenticated request (probed with an invalid level, "+
				"so the server's real log verbosity was not changed). The MCP spec requires servers to "+
				"control log access; an anonymous caller can set the minimum log level, flooding logs at "+
				"debug (cost/DoS and burying attack traces) or suppressing them at emergency (hiding "+
				"malicious activity from operators).", session.Endpoint),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprobe level (invalid): %s\n%s", resp.StatusCode, session.Endpoint, bogusLevel, reason),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}, nil
}

// setLevelDispatchReachable reports whether a logging/setLevel response for an
// invalid level shows the handler was reached without auth. The caller has
// already excluded HTTP 401/403 (returning early on a non-2xx status), so any
// HTTP-2xx result, or any JSON-RPC error that is not "method not found" and not
// auth-flavored, means the request was processed past the auth layer. The shared
// classifier handles the auth-flavored and not-found exclusions; the reason is
// used as finding evidence.
func setLevelDispatchReachable(body map[string]interface{}) (bool, string) {
	switch sig, code := classifyDispatch(body); sig {
	case dispatchResult:
		return true, "logging/setLevel returned a result envelope for an unauthenticated request, so it was dispatched without auth"
	case dispatchError:
		return true, fmt.Sprintf(
			"JSON-RPC error %d returned for an invalid level, so logging/setLevel was dispatched past the auth layer without credentials", code)
	}
	return false, ""
}
