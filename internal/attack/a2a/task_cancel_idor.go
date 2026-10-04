package a2a

import (
	"context"
	"encoding/json"
	"fmt"

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
	outcome cancelOutcome
	method  string
}

func (e *TaskCancelIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
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
			return findings, nil
		}
		rpcErr = err
	}
	findings, restErr, restTested := e.probeREST(ctx, vars.BaseURL, vars.RandID,
		a, b, clientA, clientB, unauthClient)
	if len(findings) != 0 {
		return findings, nil
	}
	if restErr != nil {
		return nil, restErr
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
	baseline, seen := e.readTaskState(ctx, clientA, endpoint, a.Headers, taskID, randID)
	if !seen || !activeTaskState(baseline) {
		return nil, fmt.Errorf("%w: owner task %s was not confirmed in a cancelable state", attack.ErrInconclusive, taskID)
	}

	anon := e.cancelTask(ctx, unauthClient, clientA, endpoint, nil, a.Headers, taskID, randID)
	switch anon.outcome {
	case cancelCanceled:
		return []attack.Finding{e.unauthFinding(endpoint, taskID, baseline, anon.method)}, nil
	case cancelAbsent:
		return nil, nil
	case cancelOther:
		return nil, fmt.Errorf("%w: anonymous cancellation of task %s was not conclusively denied", attack.ErrInconclusive, taskID)
	}
	preBState, seen := e.readTaskState(ctx, clientA, endpoint, a.Headers, taskID, randID)
	if !seen || !activeTaskState(preBState) {
		return nil, fmt.Errorf("%w: owner task %s was no longer live before the cross-principal cancel", attack.ErrInconclusive, taskID)
	}

	wrongOwner := e.cancelTask(ctx, clientB, clientA, endpoint, b.Headers, a.Headers, taskID, randID)
	switch wrongOwner.outcome {
	case cancelCanceled:
		return []attack.Finding{e.idorFinding(endpoint, a, b, taskID, preBState, wrongOwner.method)}, nil
	case cancelDenied:
		return nil, nil
	}
	return nil, fmt.Errorf("%w: cancellation of task %s was not confirmed or denied on every available method", attack.ErrInconclusive, taskID)
}

// createTask creates a task as the given principal, trying the A2A v1.0 shape
// first and falling back to the v0.3 slash-method shape. Returns the created task
// id, or empty if creation was not accepted.
// The observation is returned so a caller that got no task can say why. Both wires
// are classified, because losing the first would let a v1.0-only agent that refuses
// for auth reasons look like an agent with no task surface: the v0.3 fallback
// answers -32601, and that maps to a clean result.
func (e *TaskCancelIDORExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (string, setupObservation) {
	var obs setupObservation
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-cancel-create-" + p.Name + "-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian cancel probe " + randID}},
				"messageId": "batesian-cancel-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !resp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cancel-create-" + p.Name + "-" + randID,
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
	if err != nil || !resp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
		return "", obs
	}
	taskID, _ := extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
	}
	return taskID, obs
}

// cancelTask checks both wire names and confirms changes with an owner read.
func (e *TaskCancelIDORExecutor) cancelTask(ctx context.Context, c, owner *attack.HTTPClient, endpoint string,
	extraHeaders, ownerHeaders map[string]string, taskID, randID string) cancelProbe {
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
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cancel-" + randID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID},
		})
		state, seen := e.readTaskState(ctx, owner, endpoint, ownerHeaders, taskID, randID)
		if seen && isCanceledState(state) {
			method := s.method
			if priorUncertain {
				method = "CancelTask or tasks/cancel"
			}
			return cancelProbe{outcome: cancelCanceled, method: method}
		}
		if !seen {
			uncertain = true
		}
		if err != nil || resp == nil {
			uncertain = true
			priorUncertain = true
			continue
		}
		if isA2AAuthRejection(resp) {
			denied++
			continue
		}
		if resp.IsAccepted() {
			uncertain = true
			priorUncertain = true
			continue
		}
		if code, hasErr := jsonRPCErrorCode(resp.Body); hasErr {
			switch code {
			case jsonRPCMethodNotFound, a2aUnsupportedOperation:
				unsupported++
			case -32001: // TaskNotFound can conceal an unauthorized task.
				denied++
			default:
				uncertain = true
				priorUncertain = true
			}
		} else {
			uncertain = true
			priorUncertain = true
		}
	}
	if unsupported == len(shapes) {
		return cancelProbe{outcome: cancelAbsent}
	}
	if !uncertain && denied > 0 && denied+unsupported == len(shapes) {
		return cancelProbe{outcome: cancelDenied}
	}
	return cancelProbe{outcome: cancelOther}
}

// readTaskState checks both read methods and prefers a canceled observation.
func (e *TaskCancelIDORExecutor) readTaskState(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, randID string) (string, bool) {
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
	var state string
	for _, s := range shapes {
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cancel-get-" + randID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID, "historyLength": 1},
		})
		if err != nil || resp == nil || !resp.IsAccepted() {
			continue
		}
		current, matched := taskStateForID(resp.Body, taskID)
		if !matched || current == "" {
			continue
		}
		if isCanceledState(current) {
			return current, true
		}
		if state == "" {
			state = current
		}
	}
	return state, state != ""
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

func (e *TaskCancelIDORExecutor) unauthFinding(endpoint, taskID, baseline, method string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task cancellation accepted without authentication",
		Description: fmt.Sprintf(
			"An unauthenticated %s request canceled owner task %s at %s. The owner read-back changed from %s to canceled.",
			method, taskID, endpoint, baseline),
		Evidence: fmt.Sprintf("endpoint: %s\ntask: %s\nmethod: %s\nowner state: %s -> canceled\ncaller: anonymous",
			endpoint, taskID, method, baseline),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskCancelIDORExecutor) idorFinding(endpoint string, owner, attacker attack.Principal, taskID, baseline, method string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task canceled by a non-owning principal (IDOR)",
		Description: fmt.Sprintf(
			"Principal %q canceled task %s owned by principal %q through %s. The owner read-back changed from %s to canceled.",
			attacker.Name, taskID, owner.Name, method, baseline),
		Evidence: fmt.Sprintf(
			"owner: %s (tenant %s)\nattacker: %s (tenant %s)\ntask: %s\nmethod: %s\n"+
				"owner state: %s -> canceled",
			owner.Name, owner.Tenant, attacker.Name, attacker.Tenant, taskID, method, baseline),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create task " + taskID, Outcome: "task owned by " + owner.Name},
			{Hop: 2, Principal: attacker.Name, Action: method + " task " + taskID + " as a different principal", Outcome: "GRANTED - task canceled by non-owner"},
		},
	}
}
