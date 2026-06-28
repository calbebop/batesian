package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// DelegationIntegrityExecutor tests whether an A2A server keeps a delegated /
// multi-hop task bound to its owning principal, so a DIFFERENT authenticated
// principal cannot continue it (rule a2a-delegation-integrity-001).
//
// It is the first CHAINED CONSUMER rule: it declares Requires(ArtifactTaskID)
// and prefers to reuse a task-id another rule already created this scan
// (published to the Blackboard with its owning principal), which exercises the
// engine's producer->consumer ordering. Run standalone it falls back to creating
// its own delegator task. Either way it then attempts to continue that task as
// the wrong principal and confirms the break only when the server allows it,
// after an unauthenticated-continuation discriminator rules out a no-auth server.
type DelegationIntegrityExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-delegation-integrity", func(rc attack.RuleContext) attack.Executor {
		return NewDelegationIntegrityExecutor(rc)
	})
}

func NewDelegationIntegrityExecutor(r attack.RuleContext) *DelegationIntegrityExecutor {
	return &DelegationIntegrityExecutor{rule: r}
}

// Produces declares no published artifacts - this rule is a pure consumer.
func (e *DelegationIntegrityExecutor) Produces() []attack.ArtifactKind { return nil }

// Requires declares that this rule consumes an A2A task-id produced upstream.
func (e *DelegationIntegrityExecutor) Requires() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactTaskID}
}

// Execute satisfies attack.Executor by running the chained logic against a
// throwaway blackboard, so the rule still works outside the engine.
func (e *DelegationIntegrityExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

// ExecuteChained runs the delegation chain-of-custody check.
func (e *DelegationIntegrityExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	if len(opts.Principals) < 2 {
		return nil, nil
	}
	a, b := opts.Principals[0], opts.Principals[1]
	if a.Token == b.Token {
		return nil, nil // same identity cannot demonstrate a wrong-principal continuation
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	// Step 1: obtain a task owned by delegator A. Prefer an upstream artifact
	// (true cross-rule chaining); otherwise create one as A.
	taskID, contextID, consumed := e.consumeOwnedTask(bb, a)
	if taskID == "" {
		taskID, contextID, _ = e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	}
	if taskID == "" {
		return nil, nil // could not establish a delegator-owned task
	}

	// Step 2: discriminator. An unauthenticated continuation of A's task must be
	// rejected; if it succeeds, the server enforces no auth at all (task-idor
	// territory), not a delegation-binding break.
	if e.continueTask(ctx, unauthClient, endpoint, nil, taskID, contextID, vars.RandID) {
		return nil, nil
	}

	// Step 3: continue A's task as the WRONG principal B.
	if !e.continueTask(ctx, clientB, endpoint, b.Headers, taskID, contextID, vars.RandID) {
		return nil, nil // delegation binding holds
	}

	return []attack.Finding{e.finding(endpoint, a, b, taskID, contextID, consumed)}, nil
}

// consumeOwnedTask looks for an upstream task-id artifact owned by principal a.
// It returns the task/context IDs and true when one was consumed from the
// blackboard (as opposed to created locally later).
func (e *DelegationIntegrityExecutor) consumeOwnedTask(bb *attack.Blackboard, a attack.Principal) (taskID, contextID string, consumed bool) {
	for _, art := range bb.ByKind(attack.ArtifactTaskID) {
		if art.Value == "" || art.Principal != a.Name {
			continue
		}
		return art.Value, art.Meta["contextId"], true
	}
	return "", "", false
}

// createTask creates a task as the given principal, trying the A2A v1.0 shape
// first and falling back to the v0.3 slash-method shape. Returns the created
// task/context IDs and whether creation was accepted.
func (e *DelegationIntegrityExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string, p attack.Principal, randID string) (taskID, contextID string, accepted bool) {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-deleg-create-" + p.Name + "-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian delegation probe " + randID}},
				"messageId": "batesian-deleg-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-deleg-create-" + p.Name + "-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian delegation probe " + randID}},
					"messageId": "batesian-deleg-" + p.Name + "-" + randID,
				},
			},
		})
	}
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		return "", "", false
	}
	taskID, contextID = extractTaskContext(resp.Body)
	return taskID, contextID, taskID != ""
}

// continueTask sends a follow-up message that references an existing task/context
// (a delegated continuation) over the given client plus any principal headers,
// and reports whether the server accepted it (advanced the task) rather than
// rejecting it as not owned by the caller.
func (e *DelegationIntegrityExecutor) continueTask(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, contextID, randID string) bool {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-deleg-cont-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian delegation continuation " + randID}},
				"messageId": "batesian-deleg-cont-" + randID,
				"taskId":    taskID,
				"contextId": contextID,
			},
		},
	})
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-deleg-cont-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian delegation continuation " + randID}},
					"messageId": "batesian-deleg-cont-" + randID,
					"taskId":    taskID,
					"contextId": contextID,
				},
			},
		})
	}
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		return false
	}
	// The continuation landed on A's task only if the result still references it.
	return resp.ContainsAny(taskID, contextID, `"contextId"`)
}

// finding builds the confirmed delegation chain-of-custody break.
func (e *DelegationIntegrityExecutor) finding(endpoint string, owner, attacker attack.Principal, taskID, contextID string, consumed bool) attack.Finding {
	origin := "created during this scan as the delegator"
	hop1Action := "create/own delegated task " + taskID
	if consumed {
		origin = "reused from an upstream rule's blackboard artifact (cross-rule chain)"
		hop1Action = "own delegated task " + taskID + " (consumed from blackboard)"
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A delegated task continued by the wrong principal (broken chain-of-custody)",
		Description: fmt.Sprintf(
			"Principal %q continued task %s (contextId %s) that is owned by principal %q, by "+
				"sending a follow-up message referencing the task with its own credentials. The "+
				"server advanced the delegated task for a principal that does not own it, while "+
				"rejecting the same continuation when unauthenticated. The delegated hop is not "+
				"re-bound to the owning principal, so any authenticated caller can hijack or "+
				"advance another principal's multi-hop task. Owner task origin: %s.",
			attacker.Name, taskID, contextID, owner.Name, origin),
		Evidence: fmt.Sprintf(
			"owner: %s (tenant %s)\nattacker: %s (tenant %s)\ntask: %s\ncontextId: %s\n"+
				"task origin: %s\nunauthenticated continuation: rejected (auth enforced)\n"+
				"wrong-principal continuation: accepted",
			owner.Name, owner.Tenant, attacker.Name, attacker.Tenant, taskID, contextID, origin),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: hop1Action, Outcome: "task owned by " + owner.Name + ", awaiting continuation"},
			{Hop: 2, Principal: attacker.Name, Action: "continue task " + taskID + " as a different principal", Outcome: "GRANTED - wrong principal advanced the delegated step"},
		},
	}
}
