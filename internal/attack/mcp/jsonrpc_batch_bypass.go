package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// BatchBypassExecutor tests whether an MCP server's authentication can be bypassed
// by wrapping a request in a JSON-RPC batch array (rule mcp-jsonrpc-batch-bypass-001).
//
// The classic JSON-RPC batch bypass: an auth/method gate inspects the top-level
// request object (e.g. "allow initialize, require auth for everything else" keyed
// on body.method). A JSON-RPC batch is an array, so it has no top-level method;
// the gate's check does not fire, and the array is handed to the dispatcher, which
// executes each element. An attacker reaches a gated method by array-wrapping it.
//
// Detection sends the IDENTICAL request twice, differing only in batch wrapping:
//   - Control: the request as a plain JSON-RPC object, unauthenticated.
//   - Test:    the same request as a one-element batch array, unauthenticated.
//
// A CONFIRMED finding is raised only when the control is rejected (the gate holds
// for a single object) but the batch is processed and returns a result (the gate
// is bypassed). If both are rejected, or the server rejects the array outright
// (the compliant behaviour: batching was removed in MCP revision 2025-06-18), no
// finding is raised. Two gate shapes are probed: an HTTP/auth gate on initialize,
// and a per-method gate on tools/resources/prompts list when initialize is open.
//
// SAFETY: the rule only sends initialize and *list (enumeration) methods. It never
// invokes a tool, sends a message, or mutates state.
type BatchBypassExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-jsonrpc-batch-bypass", func(rc attack.RuleContext) attack.Executor {
		return NewBatchBypassExecutor(rc)
	})
}

func NewBatchBypassExecutor(r attack.RuleContext) *BatchBypassExecutor {
	return &BatchBypassExecutor{rule: r}
}

func (e *BatchBypassExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately unauthenticated: the rule tests whether a batch slips past the
	// server's auth gate. Injecting opts.Token would mask the bypass.
	client := attack.NewUnauthHTTPClient(opts, vars)

	return probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		return e.probeEndpoint(ctx, client, ep)
	})
}

// probeEndpoint runs the bypass check against a single candidate endpoint.
func (e *BatchBypassExecutor) probeEndpoint(ctx context.Context, client *attack.HTTPClient, ep string) ([]attack.Finding, bool) {
	initObj := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		// 2025-03-26 is the last revision that supports batching; initialize at that
		// version so a legacy server engages its batch path.
		"method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	}

	ctrl, err := client.POST(ctx, ep, nil, initObj)
	if err != nil {
		return nil, false // endpoint unreachable
	}

	switch {
	case isAuthRejection(ctrl):
		// The server gates initialize itself. Does a one-element batch slip past?
		test, err := client.POST(ctx, ep, nil, []interface{}{initObj})
		if err != nil {
			return nil, true
		}
		if test.IsSuccess() && batchHasResult(test.Body) && bodyLooksMCP(test.Body) {
			detail := fmt.Sprintf(
				"single initialize: HTTP %d (rejected, unauthenticated)\n"+
					"batch [initialize]: HTTP %d (processed, returned an MCP initialize result)",
				ctrl.StatusCode, test.StatusCode)
			return e.finding(ep, "initialize", detail), true
		}
		return nil, true

	case isMCPInitialize(ctrl):
		// initialize is open; look for a per-method gate that the batch bypasses.
		session := mcpSession{Endpoint: ep, SessionID: ctrl.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(ctrl.Body), RawInit: ctrl.Body}
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})
		return e.probeMethodGate(ctx, client, session), true

	default:
		return nil, false // not an MCP endpoint
	}
}

// probeMethodGate looks for a list method that is auth-gated for a single request
// but reachable when batch-wrapped. It only tests capabilities the server actually
// advertised, so it never probes methods the server does not implement.
func (e *BatchBypassExecutor) probeMethodGate(ctx context.Context, client *attack.HTTPClient, session mcpSession) []attack.Finding {
	candidates := []struct{ capability, method string }{
		{"tools", "tools/list"},
		{"resources", "resources/list"},
		{"prompts", "prompts/list"},
	}
	for _, c := range candidates {
		if !session.ServerSupports(c.capability) {
			continue
		}
		obj := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  c.method,
			"params":  map[string]interface{}{},
		}
		ctrl, err := client.POST(ctx, session.Endpoint, session.header(), obj)
		if err != nil {
			continue
		}
		// Only a gated method is a bypass target: if the single request already
		// succeeds, there is no auth to bypass (that is mcp-tools-unauth territory).
		if !isAuthRejection(ctrl) {
			continue
		}
		test, err := client.POST(ctx, session.Endpoint, session.header(), []interface{}{obj})
		if err != nil {
			continue
		}
		if test.IsSuccess() && batchHasResult(test.Body) {
			detail := fmt.Sprintf(
				"single %s: HTTP %d (rejected, unauthenticated)\n"+
					"batch [%s]: HTTP %d (processed, returned a result)",
				c.method, ctrl.StatusCode, c.method, test.StatusCode)
			return e.finding(session.Endpoint, c.method, detail)
		}
	}
	return nil
}

func (e *BatchBypassExecutor) finding(ep, method, detail string) []attack.Finding {
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP authentication bypassed by JSON-RPC batch wrapping",
		Description: fmt.Sprintf(
			"At %s, the JSON-RPC method %q was rejected without credentials when sent as a plain request "+
				"object, but the identical request was processed when wrapped in a one-element JSON-RPC batch "+
				"array. Authentication is enforced on single requests yet bypassed for batches, so an attacker "+
				"reaches gated methods by array-wrapping them (CWE-288, authentication bypass via an alternate "+
				"channel). JSON-RPC batching was removed in MCP revision 2025-06-18, so a server still "+
				"processing batches is also non-compliant with current revisions.", ep, method),
		Evidence:    fmt.Sprintf("endpoint: %s\ngated method: %s\n%s", ep, method, detail),
		Remediation: e.rule.Remediation,
		TargetURL:   ep,
	}}
}

// isAuthRejection reports whether a response is an authentication/authorization
// rejection: an HTTP 401/403, or a JSON-RPC error carrying auth semantics (some
// servers answer 200 with an error envelope). A non-auth rejection (parse error,
// invalid request) is deliberately not counted, so the rule never attributes an
// unrelated failure to an auth bypass.
func isAuthRejection(resp *attack.Response) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	var obj struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &obj); err != nil || obj.Error == nil {
		return false
	}
	// authFlavoredError is this package's shared predicate. The inline list here
	// diverged from it, notably by including bare "token", which the canonical list
	// excludes so a validation message like "unexpected token" cannot pass as an
	// auth refusal and trigger a bypass attempt against an ungated method.
	return authFlavoredError(obj.Error.Code, obj.Error.Message)
}

// isMCPInitialize reports whether a response is a completed MCP initialize
// result. The JSON-level oracle, not a substring over the raw body: an error
// envelope whose message quotes the field names is not a handshake, and this
// rule derives which methods to probe from ServerSupports parsing that body.
func isMCPInitialize(resp *attack.Response) bool {
	return resp.IsSuccess() && initializeSucceeded(resp.Body)
}

// batchHasResult reports whether body is a JSON-RPC batch response (a JSON array)
// in which at least one element carries a result (and no error). A non-array body
// means the server did not process the input as a batch, so it is not a bypass.
func batchHasResult(body []byte) bool {
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return false
	}
	for _, el := range arr {
		_, hasErr := el["error"]
		_, hasRes := el["result"]
		if hasRes && !hasErr {
			return true
		}
	}
	return false
}

// bodyLooksMCP reports whether body resembles an MCP initialize result, used to
// confirm the bypassed initialize batch reached a real MCP server rather than an
// unrelated endpoint that happens to return 401 then 200.
func bodyLooksMCP(body []byte) bool {
	s := string(body)
	return strings.Contains(s, `"protocolVersion"`) || strings.Contains(s, `"serverInfo"`)
}
