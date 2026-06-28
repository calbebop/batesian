package a2a

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskCancelIDORExecutor tests whether an A2A server scopes task cancellation to
// the task's owner (rule a2a-task-cancel-idor-001).
//
// CancelTask (v1.0) / tasks/cancel (v0.3) terminates a task. The spec requires
// servers to "implement appropriate authorization scoping to ensure clients can
// only access authorized tasks", so cancellation must be bound to the owning
// principal. This rule covers the cancel verb specifically: it is a separate
// handler from reading (a2a-task-idor-001) or continuing (a2a-delegation-
// integrity-001) a task and can be left unprotected independently.
//
// It reports two distinct, confirmed failures:
//   - Unauthenticated cancellation: an anonymous cancel terminates the task
//     (CWE-862, missing authentication on a state-changing operation).
//   - Cross-principal cancellation: a non-owning authenticated principal cancels
//     another principal's task (CWE-639, broken object-level authorization),
//     reported only after an unauthenticated-cancel discriminator proves the
//     server does enforce auth, and a read-back as the owner confirms the task
//     is now canceled.
//
// SAFETY: the rule creates its own throwaway task and cancels that; it never
// cancels a pre-existing task. It is deliberately standalone (it does not consume
// shared blackboard tasks that other rules may still need).
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

// cancelOutcome classifies a single cancellation attempt.
type cancelOutcome int

const (
	cancelOther        cancelOutcome = iota // application error: not found / not cancelable / unknown method
	cancelAuthRejected                      // rejected at the auth layer (HTTP 401/403 or an auth error)
	cancelCanceled                          // accepted: the task is now canceled
)

func (e *TaskCancelIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	if len(opts.Principals) < 2 {
		return nil, nil
	}
	a, b := opts.Principals[0], opts.Principals[1]
	if a.Token == b.Token {
		return nil, nil // same identity cannot demonstrate a cross-principal cancel
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	// Step 1: create a cancelable task owned by A.
	taskID := e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	if taskID == "" {
		return nil, nil // not a responsive A2A server, or no task could be created
	}

	// Step 2: discriminator. Attempt to cancel A's task with no credentials.
	switch e.cancelTask(ctx, unauthClient, endpoint, nil, taskID, vars.RandID) {
	case cancelCanceled:
		// No authentication on the cancel handler at all.
		return []attack.Finding{e.unauthFinding(endpoint, taskID)}, nil
	case cancelAuthRejected:
		// Auth is enforced; a successful cancel by a non-owner is now a true IDOR.
	default:
		// The task is not cancelable (already terminal) or the server hid it, so the
		// cancel surface cannot be exercised cleanly. No finding.
		return nil, nil
	}

	// Step 3: cancel A's task as the WRONG principal B.
	if e.cancelTask(ctx, clientB, endpoint, b.Headers, taskID, vars.RandID) != cancelCanceled {
		return nil, nil // cancellation is bound to the owner
	}

	// Step 4: read the task back as the owner A to confirm the cancel persisted.
	if !e.taskIsCanceled(ctx, clientA, endpoint, a.Headers, taskID, vars.RandID) {
		return nil, nil // could not confirm the task is actually canceled
	}

	return []attack.Finding{e.idorFinding(endpoint, a, b, taskID)}, nil
}

// createTask creates a task as the given principal, trying the A2A v1.0 shape
// first and falling back to the v0.3 slash-method shape. Returns the created task
// id, or empty if creation was not accepted.
func (e *TaskCancelIDORExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string, p attack.Principal, randID string) string {
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
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
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
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		return ""
	}
	taskID, _ := extractTaskContext(resp.Body)
	return taskID
}

// cancelTask attempts to cancel taskID over the given client and classifies the
// result. It tries the v1.0 CancelTask shape then the v0.3 tasks/cancel shape, so
// a server that does not implement one (answering method-not-found) is still
// exercised via the other.
func (e *TaskCancelIDORExecutor) cancelTask(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, randID string) cancelOutcome {
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
	for _, s := range shapes {
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cancel-" + randID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID},
		})
		if err != nil {
			continue
		}
		if isA2AAuthRejection(resp) {
			return cancelAuthRejected
		}
		if resp.IsSuccess() && !isJSONRPCError(resp.Body) && bodyShowsCanceled(resp.Body) {
			return cancelCanceled
		}
		// Otherwise an application error (not cancelable / not found / unknown
		// method): try the next shape.
	}
	return cancelOther
}

// taskIsCanceled reads the task back (GetTask v1.0, then tasks/get v0.3) and
// reports whether its state is canceled.
func (e *TaskCancelIDORExecutor) taskIsCanceled(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, randID string) bool {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-cancel-get-" + randID,
		"method":  "GetTask",
		"params":  map[string]interface{}{"id": taskID, "historyLength": 1},
	})
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cancel-get-" + randID,
			"method":  "tasks/get",
			"params":  map[string]interface{}{"id": taskID, "historyLength": 1},
		})
	}
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		return false
	}
	return bodyShowsCanceled(resp.Body)
}

// bodyShowsCanceled reports whether a task body's state is canceled, covering the
// v0.3 string ("canceled") and the v1.0 proto enum ("TASK_STATE_CANCELED"). It
// will not match "TaskNotCancelableError" (a different word, "cancelable").
func bodyShowsCanceled(body []byte) bool {
	s := string(body)
	return strings.Contains(s, `"canceled"`) || strings.Contains(s, "CANCELED")
}

func (e *TaskCancelIDORExecutor) unauthFinding(endpoint, taskID string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task cancellation accepted without authentication",
		Description: fmt.Sprintf(
			"An unauthenticated cancel request terminated task %s at %s. Cancellation is a "+
				"state-changing operation that must require authentication; an anonymous caller can "+
				"cancel any task whose id they learn or guess, disrupting other principals' work.",
			taskID, endpoint),
		Evidence:    fmt.Sprintf("endpoint: %s\ntask: %s\nunauthenticated cancel: accepted (task canceled)", endpoint, taskID),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskCancelIDORExecutor) idorFinding(endpoint string, owner, attacker attack.Principal, taskID string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task canceled by a non-owning principal (IDOR)",
		Description: fmt.Sprintf(
			"Principal %q canceled task %s owned by principal %q. The server rejected an "+
				"unauthenticated cancel of the same task (so authentication is enforced), yet allowed a "+
				"different authenticated principal to cancel it, and a read-back as the owner confirms "+
				"the task is now canceled. Cancellation is not bound to the owning principal, so any "+
				"authenticated caller can terminate another principal's tasks.",
			attacker.Name, taskID, owner.Name),
		Evidence: fmt.Sprintf(
			"owner: %s (tenant %s)\nattacker: %s (tenant %s)\ntask: %s\n"+
				"unauthenticated cancel: rejected (auth enforced)\nwrong-principal cancel: accepted\n"+
				"owner read-back: task state is canceled",
			owner.Name, owner.Tenant, attacker.Name, attacker.Tenant, taskID),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create task " + taskID, Outcome: "task owned by " + owner.Name},
			{Hop: 2, Principal: attacker.Name, Action: "cancel task " + taskID + " as a different principal", Outcome: "GRANTED - task canceled by non-owner"},
		},
	}
}
