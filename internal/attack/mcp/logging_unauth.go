package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
		return nil, nil // not an MCP server
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
	if err != nil || !resp.IsSuccess() {
		return nil, nil // auth gate (401/403) or unreachable
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, nil
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
// already excluded HTTP 401/403 (returning early on a non-2xx status), and MCP
// auth rejections are normally at the HTTP layer, so any HTTP-200 JSON-RPC error
// here means the request was processed past the auth layer - the server validated
// (and rejected) the level. Different servers surface an invalid level with
// different codes (the spec says -32602, but some return -32603 from an internal
// validation path), so the rule accepts any error except a genuine "method not
// found" or an auth-flavored error, plus any result envelope. The returned reason
// is used as finding evidence.
func setLevelDispatchReachable(body map[string]interface{}) (bool, string) {
	if errObj, ok := body["error"].(map[string]interface{}); ok {
		code, _ := errObj["code"].(float64)
		msg, _ := errObj["message"].(string)
		if int(code) == -32601 {
			return false, "" // method not found despite the advertised capability
		}
		if isAuthFlavoredError(msg) {
			return false, "" // auth enforced via a JSON-RPC error
		}
		return true, fmt.Sprintf(
			"JSON-RPC error %d returned for an invalid level, so logging/setLevel was dispatched past the auth layer without credentials", int(code))
	}
	if _, ok := body["result"]; ok {
		return true, "logging/setLevel returned a result envelope for an unauthenticated request, so it was dispatched without auth"
	}
	return false, ""
}

// isAuthFlavoredError reports whether a JSON-RPC error message indicates an
// authentication/authorization rejection rather than a request-processing error.
// MCP auth rejections are normally HTTP 401/403, so this only guards the uncommon
// case of a server that signals auth failure through a 200 JSON-RPC error.
func isAuthFlavoredError(msg string) bool {
	m := strings.ToLower(msg)
	for _, kw := range []string{"unauthor", "forbidden", "authentic", "permission", "access denied", "not allowed", "invalid token", "missing token"} {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}
