package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskCancelIDORExecutor checks cancellation of a throwaway task by anonymous
// and non-owning callers.
type TaskCancelIDORExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-task-cancel-idor", func(rc attack.RuleContext) attack.Executor {
		return NewTaskCancelIDORExecutor(rc)
	})
}

func NewTaskCancelIDORExecutor(r attack.RuleContext) *TaskCancelIDORExecutor {
	return &TaskCancelIDORExecutor{rule: r}
}

type cancelOutcome int

const (
	cancelOther cancelOutcome = iota
	cancelDenied
	cancelCanceled
	cancelAbsent
)

type cancelProbe struct {
	outcome    cancelOutcome
	method     string
	incomplete bool
}

type taskStateRead struct {
	state      string
	seen       bool
	incomplete bool
}

func (e *TaskCancelIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
	a, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))
	var rpcErr error
	if ok {
		findings, err := e.probeJSONRPC(ctx, endpoint, vars.RandID, a, b, clientA, clientB, unauthClient)
		if len(findings) != 0 {
			return findings, err
		}
		rpcErr = err
	} else {
		rpcErr = advertisedJSONRPCUnavailable(ctx, unauthClient, vars.BaseURL)
	}
	findings, restErr, restTested := e.probeREST(ctx, vars.BaseURL, vars.RandID,
		a, b, clientA, clientB, unauthClient)
	if len(findings) != 0 {
		return findings, errors.Join(rpcErr, restErr)
	}
	if restErr != nil {
		return nil, errors.Join(rpcErr, restErr)
	}
	if rpcErr != nil {
		return nil, rpcErr
	}
	if !ok && !restTested {
		return nil, attack.ErrInconclusive
	}
	return nil, nil
}

func (e *TaskCancelIDORExecutor) probeJSONRPC(ctx context.Context, endpoint, randID string,
	a, b attack.Principal, clientA, clientB, unauthClient *attack.HTTPClient) ([]attack.Finding, error) {
	// Create and read back a live task owned by A.
	taskID, obs := e.createTask(ctx, clientA, endpoint, a, randID)
	if taskID == "" {
		return nil, obs.err()
	}
	partial := obs.partialErr()
	baseline := e.readTaskState(ctx, clientA, endpoint, a.Headers, taskID, randID, "baseline")
	if baseline.incomplete {
		partial = errors.Join(partial, fmt.Errorf("%w: the owner task baseline read was incomplete", attack.ErrInconclusive))
	}
	if !baseline.seen || !activeTaskState(baseline.state) {
		return nil, errors.Join(partial, fmt.Errorf("%w: owner task %s was not confirmed in a cancelable state", attack.ErrInconclusive, taskID))
	}

	anon := e.cancelTask(ctx, unauthClient, clientA, endpoint, nil, a.Headers, taskID, randID, "anonymous")
	if anon.incomplete {
		partial = errors.Join(partial, fmt.Errorf("%w: anonymous cancellation had an unjudged reply or readback", attack.ErrInconclusive))
	}
	switch anon.outcome {
	case cancelCanceled:
		return []attack.Finding{e.unauthFinding(endpoint, a, taskID, baseline.state, anon.method)}, partial
	case cancelOther:
		return nil, errors.Join(partial, fmt.Errorf("%w: anonymous cancellation of task %s was not conclusively denied", attack.ErrInconclusive, taskID))
	}
	preBState := e.readTaskState(ctx, clientA, endpoint, a.Headers, taskID, randID, "before-cross")
	if preBState.incomplete {
		partial = errors.Join(partial, fmt.Errorf("%w: the pre-cross-principal task read was incomplete", attack.ErrInconclusive))
	}
	if !preBState.seen || !activeTaskState(preBState.state) {
		return nil, errors.Join(partial, fmt.Errorf("%w: owner task %s was no longer live before the cross-principal cancel", attack.ErrInconclusive, taskID))
	}

	wrongOwner := e.cancelTask(ctx, clientB, clientA, endpoint, b.Headers, a.Headers, taskID, randID, "cross")
	if wrongOwner.incomplete {
		partial = errors.Join(partial, fmt.Errorf("%w: cross-principal cancellation had an unjudged reply or readback", attack.ErrInconclusive))
	}
	switch wrongOwner.outcome {
	case cancelCanceled:
		return []attack.Finding{e.idorFinding(endpoint, a, b, taskID, preBState.state, wrongOwner.method)}, partial
	case cancelDenied, cancelAbsent:
		return nil, partial
	}
	return nil, errors.Join(partial, fmt.Errorf("%w: cancellation of task %s was not confirmed or denied on every available method", attack.ErrInconclusive, taskID))
}

// createTask tries both wire shapes and retains their setup outcomes.
func (e *TaskCancelIDORExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (string, setupObservation) {
	var obs setupObservation
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		v1Headers[k] = v
	}
	requestID := "batesian-cancel-create-" + p.Name + "-" + randID
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian cancel probe " + randID}},
				"messageId": "batesian-cancel-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		requestID += "-v03"
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian cancel probe " + randID}},
					"messageId": "batesian-cancel-" + p.Name + "-" + randID,
				},
			},
		})
	}
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		return "", obs
	}
	taskID, _ := extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
	}
	return taskID, obs
}

// cancelTask checks both wire names and confirms changes with an owner read.
func (e *TaskCancelIDORExecutor) cancelTask(ctx context.Context, c, owner *attack.HTTPClient, endpoint string,
	extraHeaders, ownerHeaders map[string]string, taskID, randID, phase string) cancelProbe {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	shapes := []struct {
		method  string
		headers map[string]string
	}{
		{"CancelTask", v1Headers},
		{"tasks/cancel", extraHeaders},
	}
	unsupported := 0
	denied := 0
	uncertain := false
	priorUncertain := false
	for _, s := range shapes {
		requestID := "batesian-cancel-" + randID + "-" + phase + "-" + s.method
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID},
		})
		var code int
		var hasErr, valid bool
		if err == nil && resp != nil {
			_, code, hasErr, valid = discoveryResponse(resp.Body, requestID)
		}
		read := e.readTaskState(ctx, owner, endpoint, ownerHeaders, taskID, randID, phase+"-"+s.method)
		if read.seen && isCanceledState(read.state) {
			if err == nil && resp != nil && resp.IsSuccess() && valid && !hasErr &&
				bodyShowsCanceled(resp.Body, taskID) && !priorUncertain {
				return cancelProbe{outcome: cancelCanceled, method: s.method, incomplete: read.incomplete}
			}
			return cancelProbe{outcome: cancelOther, incomplete: true}
		}
		if !read.seen || read.incomplete {
			uncertain = true
			priorUncertain = true
		}
		if err != nil || resp == nil {
			uncertain = true
			priorUncertain = true
			continue
		}
		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= http.StatusInternalServerError {
			uncertain = true
			priorUncertain = true
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			denied++
			continue
		}
		if !valid {
			uncertain = true
			priorUncertain = true
			continue
		}
		if hasErr {
			switch code {
			case jsonRPCMethodNotFound, a2aUnsupportedOperation:
				unsupported++
			case -32001: // TaskNotFound can conceal an unauthorized task.
				denied++
			default:
				if errMessageIsAuth(resp.Body) {
					denied++
				} else {
					uncertain = true
					priorUncertain = true
				}
			}
		} else {
			uncertain = true
			priorUncertain = true
		}
	}
	if !uncertain && unsupported == len(shapes) {
		return cancelProbe{outcome: cancelAbsent}
	}
	if !uncertain && denied > 0 && denied+unsupported == len(shapes) {
		return cancelProbe{outcome: cancelDenied}
	}
	return cancelProbe{outcome: cancelOther, incomplete: uncertain}
}

// readTaskState checks both read methods and prefers a canceled observation.
func (e *TaskCancelIDORExecutor) readTaskState(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, randID, phase string) taskStateRead {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	shapes := []struct {
		method  string
		headers map[string]string
	}{
		{"GetTask", v1Headers},
		{"tasks/get", extraHeaders},
	}
	var read taskStateRead
	for _, s := range shapes {
		requestID := "batesian-cancel-get-" + randID + "-" + phase + "-" + s.method
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID, "historyLength": 1},
		})
		if err != nil || resp == nil {
			read.incomplete = true
			continue
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			continue
		}
		if !resp.IsSuccess() {
			read.incomplete = true
			continue
		}
		_, code, hasErr, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			read.incomplete = true
			continue
		}
		if hasErr {
			if code != jsonRPCMethodNotFound && code != a2aUnsupportedOperation {
				read.incomplete = true
			}
			continue
		}
		current, matched := taskStateForID(resp.Body, taskID)
		if !matched || current == "" {
			read.incomplete = true
			continue
		}
		if isCanceledState(current) {
			read.state = current
			read.seen = true
			return read
		}
		if !read.seen {
			read.state = current
			read.seen = true
		}
	}
	return read
}

func taskStateForID(body []byte, taskID string) (string, bool) {
	type task struct {
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	var envelope struct {
		Result *struct {
			task
			Task *task `json:"task"`
		} `json:"result"`
	}
	if taskID == "" || json.Unmarshal(body, &envelope) != nil || envelope.Result == nil {
		return "", false
	}
	if envelope.Result.Task != nil {
		candidate := envelope.Result.Task
		if candidate.ID == taskID {
			return candidate.Status.State, true
		}
		return "", false
	}
	candidate := envelope.Result.task
	if candidate.ID == taskID {
		return candidate.Status.State, true
	}
	return "", false
}

func bodyShowsCanceled(body []byte, taskID string) bool {
	state, matched := taskStateForID(body, taskID)
	return matched && isCanceledState(state)
}

func isCanceledState(state string) bool {
	switch state {
	case "canceled", "TASK_STATE_CANCELED", "TASK_STATE_CANCELLED":
		return true
	}
	return false
}

func activeTaskState(state string) bool {
	switch state {
	case "submitted", "working", "input-required", "auth-required",
		"TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED":
		return true
	}
	return false
}

func (e *TaskCancelIDORExecutor) unauthFinding(endpoint string, owner attack.Principal, taskID, baseline, method string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.RiskIndicator,
		Title:      "A2A task cancellation accepted without authentication",
		Description: fmt.Sprintf(
			"An unauthenticated %s request canceled owner task %s at %s. The owner read-back changed from %s to canceled. The observation alone does not establish whether anonymous cancellation is forbidden.",
			method, taskID, endpoint, baseline),
		Evidence: fmt.Sprintf("endpoint: %s\ntask: %s\nmethod: %s\nowner state: %s -> canceled\ncaller: anonymous",
			endpoint, taskID, method, baseline),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Access:      &attack.AccessObservation{Operation: attack.A2ATasksCancel, Caller: "anonymous", Owner: owner.Name, OwnerTenant: owner.Tenant},
	}
}

func (e *TaskCancelIDORExecutor) idorFinding(endpoint string, owner, attacker attack.Principal, taskID, baseline, method string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.RiskIndicator,
		Title:      "A2A task canceled by a non-owning principal",
		Description: fmt.Sprintf(
			"Principal %q canceled task %s created by principal %q through %s. The owner read-back changed from %s to canceled. The observation alone does not establish whether these principals may share task access.",
			attacker.Name, taskID, owner.Name, method, baseline),
		Evidence: fmt.Sprintf(
			"owner: %s (tenant %s)\nattacker: %s (tenant %s)\ntask: %s\nmethod: %s\n"+
				"owner state: %s -> canceled",
			owner.Name, owner.Tenant, attacker.Name, attacker.Tenant, taskID, method, baseline),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Access: &attack.AccessObservation{
			Operation: attack.A2ATasksCancel, Caller: attacker.Name, CallerTenant: attacker.Tenant,
			Owner: owner.Name, OwnerTenant: owner.Tenant,
		},
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create task " + taskID, Outcome: "task owned by " + owner.Name},
			{Hop: 2, Principal: attacker.Name, Action: method + " task " + taskID + " as a different principal", Outcome: "GRANTED - task canceled by non-owner"},
		},
	}
}
