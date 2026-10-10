package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// BatchBypassExecutor compares unauthenticated GetTask requests with the same
// requests wrapped in a batch. A finding requires an auth refusal followed by a
// correlated task response. The probes only read a nonexistent task ID.
type BatchBypassExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-jsonrpc-batch-bypass", func(rc attack.RuleContext) attack.Executor {
		return NewBatchBypassExecutor(rc)
	})
}

func NewBatchBypassExecutor(r attack.RuleContext) *BatchBypassExecutor {
	return &BatchBypassExecutor{rule: r}
}

func (e *BatchBypassExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately unauthenticated: the rule tests whether a batch slips past the
	// server's auth gate. Injecting opts.Token would mask the bypass.
	client := attack.NewUnauthHTTPClient(opts, vars)
	endpoint, ok := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	bogusTask := "batesian-nonexistent-" + vars.RandID

	// Two protocol shapes, tried in order: A2A v1.0 (PascalCase method, A2A-Version
	// header) then the v0.3 slash-method fallback. For each, the control and test
	// use the IDENTICAL request object so the only variable is batch wrapping.
	shapes := []struct {
		label   string
		headers map[string]string
		obj     map[string]interface{}
	}{
		{
			label:   "v1.0 GetTask",
			headers: map[string]string{"A2A-Version": "1.0"},
			obj: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-batch-" + vars.RandID,
				"method":  "GetTask",
				"params":  map[string]interface{}{"id": bogusTask, "historyLength": 1},
			},
		},
		{
			label:   "v0.3 tasks/get",
			headers: nil,
			obj: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-batch-" + vars.RandID,
				"method":  "tasks/get",
				"params":  map[string]interface{}{"id": bogusTask, "historyLength": 1},
			},
		},
	}

	var incomplete []string
	for _, s := range shapes {
		ctrl, err := client.POST(ctx, endpoint, s.headers, s.obj)
		if err != nil || ctrl == nil {
			incomplete = append(incomplete, s.label+" control request failed")
			continue
		}
		requestID, _ := s.obj["id"].(string)
		if ctrl.StatusCode == 429 || ctrl.StatusCode >= 500 {
			incomplete = append(incomplete, s.label+" control response was not judged")
			continue
		}
		// An HTTP auth gate must reject the single request, otherwise there is no
		// authentication to bypass for this shape.
		if !isA2AAuthRejection(ctrl) {
			if ambiguousBatchResponse(ctrl, requestID, false) {
				incomplete = append(incomplete, s.label+" control response was not judged")
			}
			continue
		}
		test, err := client.POST(ctx, endpoint, s.headers, []interface{}{s.obj})
		if err != nil || test == nil {
			incomplete = append(incomplete, s.label+" batch request failed")
			continue
		}
		if test.IsSuccess() && a2aBatchDispatched(test.Body, requestID) {
			return e.finding(endpoint, s.label, ctrl, test), nil
		}
		if ambiguousBatchResponse(test, requestID, true) {
			incomplete = append(incomplete, s.label+" batch response was not judged")
		}
	}
	if len(incomplete) != 0 {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return nil, nil
}

func ambiguousBatchResponse(resp *attack.Response, requestID string, batch bool) bool {
	if resp.StatusCode == 429 || resp.StatusCode >= 500 || resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}
	if !resp.IsSuccess() {
		return false
	}
	if batch {
		return !a2aBatchRejected(resp.Body, requestID)
	}
	return !a2aSingleAnswered(resp.Body, requestID)
}

func a2aSingleAnswered(body []byte, requestID string) bool {
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	return json.Unmarshal(body, &response) == nil && response.JSONRPC == "2.0" &&
		response.ID == requestID && (len(response.Result) != 0 || len(response.Error) != 0)
}

func a2aBatchRejected(body []byte, requestID string) bool {
	type rpcResponse struct {
		ID    json.RawMessage `json:"id"`
		Error json.RawMessage `json:"error"`
	}
	var responses []rpcResponse
	if json.Unmarshal(body, &responses) != nil {
		var response rpcResponse
		return json.Unmarshal(body, &response) == nil && a2aRejectedError(response.ID, response.Error, requestID)
	}
	for _, response := range responses {
		if a2aRejectedError(response.ID, response.Error, requestID) {
			return true
		}
	}
	return false
}

func a2aRejectedError(rawID, rawError json.RawMessage, requestID string) bool {
	if string(rawID) != "null" {
		var id string
		if json.Unmarshal(rawID, &id) != nil || id != requestID {
			return false
		}
	}
	var rpcErr struct {
		Code int `json:"code"`
	}
	return json.Unmarshal(rawError, &rpcErr) == nil &&
		(errMessageIsAuthRaw(rawError) || rpcErr.Code >= -32700 && rpcErr.Code <= -32600)
}

func (e *BatchBypassExecutor) finding(endpoint, shape string, ctrl, test *attack.Response) []attack.Finding {
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A authentication bypassed by JSON-RPC batch wrapping",
		Description: fmt.Sprintf(
			"At %s, a single unauthenticated JSON-RPC request was rejected at the HTTP layer, but the "+
				"identical request wrapped in a one-element JSON-RPC batch array reached the dispatcher and "+
				"was processed. A2A enforces authentication at the transport, yet the batch slipped past it, "+
				"so an attacker reaches authenticated methods by array-wrapping them (CWE-288, authentication "+
				"bypass via an alternate channel). A2A does not define batching, so a server should reject a "+
				"JSON-RPC array rather than dispatch it unauthenticated.", endpoint),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nshape: %s\nsingle request: HTTP %d (rejected, unauthenticated)\n"+
				"batch [request]: HTTP %d (processed)\n%s",
			endpoint, shape, ctrl.StatusCode, test.StatusCode, snippet(test.Body, 400)),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}}
}

// isA2AAuthRejection reports whether a response is an A2A authentication rejection.
// A2A enforces auth at the HTTP layer, so the primary signal is HTTP 401/403; a
// JSON-RPC error envelope whose message reads as an auth failure is also accepted
// for servers that wrap the rejection at 200. A2A application errors (TaskNotFound
// at -32001, method-not-found, invalid params) are deliberately NOT counted.
func isA2AAuthRejection(resp *attack.Response) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	return errMessageIsAuth(resp.Body)
}

// a2aBatchDispatched requires a response correlated to the task probe.
func a2aBatchDispatched(body []byte, expectedID string) bool {
	var arr []struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &arr); err != nil {
		return false
	}
	for _, el := range arr {
		var responseID string
		if el.JSONRPC != "2.0" || json.Unmarshal(el.ID, &responseID) != nil || responseID != expectedID {
			continue
		}
		if len(el.Result) != 0 && string(el.Result) != "null" && len(el.Error) == 0 {
			var task struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(el.Result, &task) == nil && task.ID != "" {
				return true
			}
		}
		var responseError struct {
			Code int `json:"code"`
		}
		if len(el.Result) == 0 && json.Unmarshal(el.Error, &responseError) == nil &&
			responseError.Code == -32001 && !errMessageIsAuthRaw(el.Error) {
			return true
		}
	}
	return false
}

func errMessageIsAuth(body []byte) bool {
	var obj struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &obj); err != nil || len(obj.Error) == 0 {
		return false
	}
	return errMessageIsAuthRaw(obj.Error)
}

func errMessageIsAuthRaw(rawErr json.RawMessage) bool {
	var e struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rawErr, &e); err != nil {
		return false
	}
	// A2A defines no numeric auth error code, so this is message-based. The list
	// lives in internal/attack: the copy that used to be here omitted "authoriz",
	// "access denied" and "login", so a batch refused with "Not authorized" was read
	// as dispatched and the rule accused a correctly secured agent of a bypass.
	return attack.AuthFlavoredMessage(e.Message)
}
