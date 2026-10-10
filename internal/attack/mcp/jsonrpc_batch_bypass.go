package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// BatchBypassExecutor compares unauthenticated single and batch requests for MCP
// initialize and advertised list methods. It never invokes tools or mutates state.
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

	var incomplete error
	findings, err := probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		result, reached, probeErr := e.probeEndpoint(ctx, client, ep)
		if reached {
			incomplete = probeErr
		}
		return result, reached
	})
	if len(findings) != 0 || err != nil {
		return findings, err
	}
	return nil, incomplete
}

// probeEndpoint runs the bypass check against a single candidate endpoint.
func (e *BatchBypassExecutor) probeEndpoint(ctx context.Context, client *attack.HTTPClient, ep string) ([]attack.Finding, bool, error) {
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
	if err != nil || ctrl == nil {
		return nil, false, nil // endpoint unreachable
	}
	if ctrl.StatusCode == 429 || ctrl.StatusCode >= 500 {
		return nil, false, nil
	}

	switch {
	case isAuthRejection(ctrl):
		// The server gates initialize itself. Does a one-element batch slip past?
		test, err := client.POST(ctx, ep, nil, []interface{}{initObj})
		if err != nil || test == nil {
			return nil, true, fmt.Errorf("%w: initialize batch request failed", attack.ErrInconclusive)
		}
		if test.IsSuccess() && batchInitializeSucceeded(test.Body, 1) {
			detail := fmt.Sprintf(
				"single initialize: HTTP %d (rejected, unauthenticated)\n"+
					"batch [initialize]: HTTP %d (processed, returned an MCP initialize result)",
				ctrl.StatusCode, test.StatusCode)
			return e.finding(ep, "initialize", detail), true, nil
		}
		if ambiguousMCPBatchResponse(test, 1) {
			return nil, true, fmt.Errorf("%w: initialize batch response was not judged", attack.ErrInconclusive)
		}
		return nil, true, nil

	case isMCPInitialize(ctrl):
		// initialize is open; look for a per-method gate that the batch bypasses.
		session := mcpSession{Endpoint: ep, SessionID: ctrl.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(ctrl.Body), RawInit: ctrl.Body}
		initialized, err := client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})
		if err != nil || initialized == nil || !initialized.IsSuccess() {
			return nil, true, fmt.Errorf("%w: initialized notification failed", attack.ErrInconclusive)
		}
		findings, err := e.probeMethodGate(ctx, client, session)
		return findings, true, err

	default:
		return nil, false, nil // not an MCP endpoint
	}
}

// probeMethodGate looks for a list method that is auth-gated for a single request
// but reachable when batch-wrapped. It only tests capabilities the server actually
// advertised, so it never probes methods the server does not implement.
func (e *BatchBypassExecutor) probeMethodGate(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]attack.Finding, error) {
	candidates := []struct{ capability, method string }{
		{"tools", "tools/list"},
		{"resources", "resources/list"},
		{"prompts", "prompts/list"},
	}
	var incomplete []string
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
		if err != nil || ctrl == nil {
			incomplete = append(incomplete, c.method+" control request failed")
			continue
		}
		if ambiguousMCPSingleResponse(ctrl, 2) {
			incomplete = append(incomplete, c.method+" control response was not judged")
			continue
		}
		// Only a gated method is a bypass target: if the single request already
		// succeeds, there is no auth boundary to bypass.
		if !isAuthRejection(ctrl) {
			continue
		}
		test, err := client.POST(ctx, session.Endpoint, session.header(), []interface{}{obj})
		if err != nil || test == nil {
			incomplete = append(incomplete, c.method+" batch request failed")
			continue
		}
		if test.IsSuccess() && batchListSucceeded(test.Body, 2, c.capability) {
			detail := fmt.Sprintf(
				"single %s: HTTP %d (rejected, unauthenticated)\n"+
					"batch [%s]: HTTP %d (processed, returned a result)",
				c.method, ctrl.StatusCode, c.method, test.StatusCode)
			return e.finding(session.Endpoint, c.method, detail), nil
		}
		if ambiguousMCPBatchResponse(test, 2) {
			incomplete = append(incomplete, c.method+" batch response was not judged")
		}
	}
	if len(incomplete) != 0 {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return nil, nil
}

func ambiguousMCPSingleResponse(resp *attack.Response, requestID int) bool {
	if resp.StatusCode == 429 || resp.StatusCode >= 500 || resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}
	if !resp.IsSuccess() || isAuthRejection(resp) {
		return false
	}
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	return json.Unmarshal(resp.Body, &response) != nil || response.JSONRPC != "2.0" ||
		response.ID != requestID || len(response.Result) == 0 && len(response.Error) == 0
}

func ambiguousMCPBatchResponse(resp *attack.Response, requestID int) bool {
	if resp.StatusCode == 429 || resp.StatusCode >= 500 || resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}
	if !resp.IsSuccess() {
		return false
	}
	type rpcResponse struct {
		ID    json.RawMessage `json:"id"`
		Error json.RawMessage `json:"error"`
	}
	var responses []rpcResponse
	if json.Unmarshal(resp.Body, &responses) != nil {
		var response rpcResponse
		return json.Unmarshal(resp.Body, &response) != nil ||
			!mcpBatchRejectedError(response.ID, response.Error, requestID)
	}
	for _, response := range responses {
		if mcpBatchRejectedError(response.ID, response.Error, requestID) {
			return false
		}
	}
	return true
}

func mcpBatchRejectedError(rawID, rawError json.RawMessage, requestID int) bool {
	if string(rawID) != "null" {
		var id int
		if json.Unmarshal(rawID, &id) != nil || id != requestID {
			return false
		}
	}
	var rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	return json.Unmarshal(rawError, &rpcErr) == nil &&
		(authFlavoredError(rpcErr.Code, rpcErr.Message) || rpcErr.Code >= -32700 && rpcErr.Code <= -32600)
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

// batchResult returns the result correlated to the probe request.
func batchResult(body []byte, expectedID int) (json.RawMessage, bool) {
	var arr []struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, false
	}
	for _, el := range arr {
		var responseID int
		if el.JSONRPC != "2.0" || json.Unmarshal(el.ID, &responseID) != nil || responseID != expectedID {
			continue
		}
		if len(el.Result) != 0 && string(el.Result) != "null" && len(el.Error) == 0 {
			return el.Result, true
		}
	}
	return nil, false
}

func batchInitializeSucceeded(body []byte, expectedID int) bool {
	result, ok := batchResult(body, expectedID)
	if !ok {
		return false
	}
	var init struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if json.Unmarshal(result, &init) != nil || init.ProtocolVersion == "" || init.ServerInfo.Name == "" || init.ServerInfo.Version == "" {
		return false
	}
	var capabilities map[string]json.RawMessage
	return json.Unmarshal(init.Capabilities, &capabilities) == nil && capabilities != nil
}

func batchListSucceeded(body []byte, expectedID int, field string) bool {
	result, ok := batchResult(body, expectedID)
	if !ok {
		return false
	}
	var lists map[string]json.RawMessage
	if json.Unmarshal(result, &lists) != nil {
		return false
	}
	rawItems := lists[field]
	if len(rawItems) == 0 || string(rawItems) == "null" {
		return false
	}
	var items []json.RawMessage
	return json.Unmarshal(rawItems, &items) == nil
}
