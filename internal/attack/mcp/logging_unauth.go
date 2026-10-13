package mcp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

// LoggingUnauthExecutor probes the legacy logging/setLevel method without auth.
// It sends an invalid level to avoid changing server state.
type LoggingUnauthExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-logging-unauth", func(rc attack.RuleContext) attack.Executor { return NewLoggingUnauthExecutor(rc) })
}

// NewLoggingUnauthExecutor creates an executor for mcp-logging-unauth.
func NewLoggingUnauthExecutor(r attack.RuleContext) *LoggingUnauthExecutor {
	return &LoggingUnauthExecutor{rule: r}
}

func (e *LoggingUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// This rule tests anonymous access.
	client := attack.NewUnauthHTTPClient(opts, vars)

	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, inconclusive(err)
	}

	if !session.ServerSupports("logging") {
		return nil, nil
	}

	bogusLevel := "batesian-invalid-" + vars.RandID
	resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "logging/setLevel",
		"params":  map[string]interface{}{"level": bogusLevel},
	})
	verdict, body := classifyProbe(resp, err, 3)
	if verdict != probeAnswered {
		if err == nil && resp != nil &&
			(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return nil, nil
		}
		if err == nil && resp != nil {
			if rejected, ok := parseResponseBody(resp.Body); ok && matchesRPCID(rejected, 3) && validRPCError(rejected) {
				errObj := rejected["error"].(map[string]interface{})
				code := rpcErrorCode(errObj["code"])
				message := errObj["message"].(string)
				if code == -32601 || authFlavoredError(code, message) {
					return nil, nil
				}
			}
		}
		return nil, fmt.Errorf("%w: MCP handshake succeeded at %s, but logging/setLevel returned no authorization verdict",
			attack.ErrInconclusive, session.Endpoint)
	}
	if errObj, ok := body["error"].(map[string]interface{}); ok {
		code := rpcErrorCode(errObj["code"])
		message, _ := errObj["message"].(string)
		if authFlavoredError(code, message) {
			return nil, nil
		}
		if code == -32601 {
			return nil, nil
		}
	}

	signal, reason := setLevelDispatchReachable(body)
	if signal == dispatchNone {
		return nil, fmt.Errorf("%w: MCP handshake succeeded at %s, but logging/setLevel returned no authorization verdict",
			attack.ErrInconclusive, session.Endpoint)
	}
	confidence := attack.ConfirmedExploit
	title := "MCP logging/setLevel returned a result without authentication"
	description := fmt.Sprintf("logging/setLevel at %s returned a result for an anonymous request with an invalid level. The probe did not verify that a valid log-level change would be accepted.", session.Endpoint)
	if signal == dispatchError {
		confidence = attack.RiskIndicator
		title = "MCP logging/setLevel returned a non-authentication error to an anonymous request"
		description = fmt.Sprintf("logging/setLevel at %s returned a non-authentication JSON-RPC error for an anonymous request. The error may have come from validation before method dispatch; log-level control was not demonstrated.", session.Endpoint)
	}

	return []attack.Finding{{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    "medium",
		Confidence:  confidence,
		Title:       title,
		Description: description,
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprobe level (invalid): %s\n%s", resp.StatusCode, session.Endpoint, bogusLevel, reason),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}, nil
}

func setLevelDispatchReachable(body map[string]interface{}) (dispatchSignal, string) {
	switch sig, code := classifyDispatch(body); sig {
	case dispatchResult:
		return dispatchResult, "logging/setLevel returned a result envelope to an anonymous request"
	case dispatchError:
		return dispatchError, fmt.Sprintf("JSON-RPC error %d returned for an invalid level; dispatch was not verified", code)
	}
	return dispatchNone, ""
}
