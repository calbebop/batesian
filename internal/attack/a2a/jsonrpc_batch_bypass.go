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

	// Each control and batch test use the same request ID and method.
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
				"id":      "batesian-batch-" + vars.RandID + "-v1",
				"method":  "GetTask",
				"params":  map[string]interface{}{"id": bogusTask, "historyLength": 1},
			},
		},
		{
			label:   "v0.3 tasks/get",
			headers: nil,
			obj: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-batch-" + vars.RandID + "-v03",
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
		if ctrl.StatusCode == 408 || ctrl.StatusCode == 429 || ctrl.StatusCode >= 500 {
			incomplete = append(incomplete, s.label+" control response was not judged")
			continue
		}
		if ctrl.IsSuccess() && !a2aSingleAnswered(ctrl.Body, requestID) {
			incomplete = append(incomplete, s.label+" control response was not judged")
			continue
		}
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
		evidence := batchNoDispatch
		if test.IsSuccess() {
			evidence = a2aBatchDispatched(test.Body, requestID)
		}
		if evidence != batchNoDispatch {
			if len(incomplete) != 0 {
				return e.finding(endpoint, s.label, ctrl, test, evidence), fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
			}
			return e.finding(endpoint, s.label, ctrl, test, evidence), nil
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
	if resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500 ||
		resp.StatusCode >= 300 && resp.StatusCode < 400 {
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
	_, _, _, valid := discoveryResponse(body, requestID)
	return valid
}

func a2aBatchRejected(body []byte, requestID string) bool {
	type rpcResponse struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   json.RawMessage `json:"error"`
	}
	var responses []rpcResponse
	if json.Unmarshal(body, &responses) != nil {
		var response rpcResponse
		return json.Unmarshal(body, &response) == nil &&
			a2aRejectedError(response.JSONRPC, response.ID, response.Error, requestID)
	}
	return len(responses) == 1 &&
		a2aRejectedError(responses[0].JSONRPC, responses[0].ID, responses[0].Error, requestID)
}

func a2aRejectedError(version string, rawID, rawError json.RawMessage, requestID string) bool {
	if version != "2.0" {
		return false
	}
	if string(rawID) != "null" {
		var id string
		if json.Unmarshal(rawID, &id) != nil || id != requestID {
			return false
		}
	}
	var rpcErr struct {
		Code    *int    `json:"code"`
		Message *string `json:"message"`
	}
	if json.Unmarshal(rawError, &rpcErr) != nil || rpcErr.Code == nil || rpcErr.Message == nil {
		return false
	}
	return errMessageIsAuthRaw(rawError) || *rpcErr.Code == -32700 ||
		*rpcErr.Code >= -32602 && *rpcErr.Code <= -32600
}

func (e *BatchBypassExecutor) finding(endpoint, shape string, ctrl, test *attack.Response,
	evidence batchDispatchEvidence) []attack.Finding {
	refusal := "HTTP authentication refusal"
	if ctrl.IsSuccess() {
		refusal = "correlated JSON-RPC authentication error"
	}
	severity := "medium"
	confidence := attack.RiskIndicator
	title := "A2A batch changed the authentication outcome"
	description := fmt.Sprintf(
		"At %s, a single unauthenticated GetTask request was refused, while the same request in a "+
			"one-element batch returned TaskNotFound. A2A also uses TaskNotFound for inaccessible tasks, "+
			"so this difference does not prove unauthorized access. Check that single and batch "+
			"requests receive the same authentication and authorization checks.", endpoint)
	if evidence == batchTaskReturned {
		severity = "high"
		confidence = attack.ConfirmedExploit
		title = "A2A authentication bypassed by JSON-RPC batch wrapping"
		description = fmt.Sprintf(
			"At %s, a single unauthenticated GetTask request was refused, but the same request "+
				"in a one-element batch returned a task object. Apply the same authentication and "+
				"authorization checks to single and batch requests (CWE-288).", endpoint)
	}
	return []attack.Finding{{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Description: description,
		Evidence: fmt.Sprintf(
			"endpoint: %s\nshape: %s\nsingle request: HTTP %d (%s)\n"+
				"batch [request]: HTTP %d (%s)\n%s",
			endpoint, shape, ctrl.StatusCode, refusal, test.StatusCode, evidence, snippet(test.Body, 400)),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}}
}

// isA2AAuthRejection accepts HTTP 401/403 or an auth error on a successful response.
func isA2AAuthRejection(resp *attack.Response) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	return resp.IsSuccess() && errMessageIsAuth(resp.Body)
}

type batchDispatchEvidence string

const (
	batchNoDispatch   batchDispatchEvidence = ""
	batchTaskNotFound batchDispatchEvidence = "TaskNotFound"
	batchTaskReturned batchDispatchEvidence = "task returned"
)

// a2aBatchDispatched requires a response correlated to the task probe.
func a2aBatchDispatched(body []byte, expectedID string) batchDispatchEvidence {
	var arr []struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &arr); err != nil || len(arr) != 1 {
		return batchNoDispatch
	}
	for _, el := range arr {
		var responseID string
		if el.JSONRPC != "2.0" || json.Unmarshal(el.ID, &responseID) != nil || responseID != expectedID {
			continue
		}
		if len(el.Result) != 0 && string(el.Result) != "null" && len(el.Error) == 0 {
			var task struct {
				ID        string `json:"id"`
				ContextID string `json:"contextId"`
				Status    struct {
					State string `json:"state"`
				} `json:"status"`
			}
			if json.Unmarshal(el.Result, &task) == nil && task.ID != "" && task.ContextID != "" && task.Status.State != "" {
				return batchTaskReturned
			}
		}
		var responseError struct {
			Code    *int    `json:"code"`
			Message *string `json:"message"`
		}
		if len(el.Result) == 0 && json.Unmarshal(el.Error, &responseError) == nil &&
			responseError.Code != nil && *responseError.Code == -32001 && responseError.Message != nil &&
			!errMessageIsAuthRaw(el.Error) {
			return batchTaskNotFound
		}
	}
	return batchNoDispatch
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
	// A2A has no numeric auth error code; use the shared message vocabulary.
	return attack.AuthFlavoredMessage(e.Message)
}
