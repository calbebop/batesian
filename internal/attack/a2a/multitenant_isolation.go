package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// MultiTenantIsolationExecutor tests whether an authenticated A2A server enforces
// a TENANT boundary on task lookup (rule a2a-multitenant-isolation-001).
//
// Unlike a2a-task-idor-001 (which tests anonymous access), this is a stateful,
// multi-principal chained check: with two VALID but distinct identities it
// confirms that one tenant cannot read the other tenant's task. It implements
// attack.ChainExecutor and publishes the tokens and created task IDs to the
// shared Blackboard so downstream chained rules can build on them.
type MultiTenantIsolationExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-multitenant-isolation", func(rc attack.RuleContext) attack.Executor {
		return NewMultiTenantIsolationExecutor(rc)
	})
}

func NewMultiTenantIsolationExecutor(r attack.RuleContext) *MultiTenantIsolationExecutor {
	return &MultiTenantIsolationExecutor{rule: r}
}

// Produces declares the artifact kinds this rule may publish.
func (e *MultiTenantIsolationExecutor) Produces() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactToken, attack.ArtifactTaskID}
}

// Requires declares no upstream dependencies - this rule is a producer.
func (e *MultiTenantIsolationExecutor) Requires() []attack.ArtifactKind { return nil }

// Execute satisfies attack.Executor by running the chained logic against a
// throwaway blackboard, so the rule still works if invoked outside the engine.
func (e *MultiTenantIsolationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

// ExecuteChained runs the multi-tenant isolation check.
func (e *MultiTenantIsolationExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	// Precondition: need two valid, distinguishable principals.
	if len(opts.Principals) < 2 {
		return nil, nil
	}
	a, b := opts.Principals[0], opts.Principals[1]
	if a.Token == b.Token {
		// Same (or both-empty) credentials cannot demonstrate isolation between
		// two distinct tenants.
		return nil, nil
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, _ := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)

	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	// Step 1: each principal creates its own task. Both must succeed to prove two
	// valid, distinct identities.
	taskA, ctxA, okA := e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	taskB, ctxB, okB := e.createTask(ctx, clientB, endpoint, b, vars.RandID)
	if !okA || !okB {
		return nil, nil
	}
	bb.Publish(attack.Artifact{Kind: attack.ArtifactToken, Value: a.Token, Principal: a.Name, Producer: e.rule.ID})
	bb.Publish(attack.Artifact{Kind: attack.ArtifactToken, Value: b.Token, Principal: b.Name, Producer: e.rule.ID})
	bb.Publish(attack.Artifact{Kind: attack.ArtifactTaskID, Value: taskA, Principal: a.Name, Producer: e.rule.ID, Meta: map[string]string{"contextId": ctxA}})
	bb.Publish(attack.Artifact{Kind: attack.ArtifactTaskID, Value: taskB, Principal: b.Name, Producer: e.rule.ID, Meta: map[string]string{"contextId": ctxB}})

	// Step 2: open-server discriminator. If an UNAUTHENTICATED read of A's task
	// succeeds, the server enforces no auth at all - not a tenant-isolation
	// breach (owned by a2a-task-idor-001). Suppress.
	if e.readTask(ctx, unauthClient, endpoint, nil, taskA, ctxA, vars.RandID) {
		return nil, nil
	}

	// Step 3: cross-tenant reads in both directions.
	var findings []attack.Finding
	if e.readTask(ctx, clientB, endpoint, b.Headers, taskA, ctxA, vars.RandID) {
		findings = append(findings, e.finding(endpoint, b, a, taskA, ctxA))
	}
	if e.readTask(ctx, clientA, endpoint, a.Headers, taskB, ctxB, vars.RandID) {
		findings = append(findings, e.finding(endpoint, a, b, taskB, ctxB))
	}
	return findings, nil
}

// createTask issues a SendMessage create as the given principal, trying the A2A
// v1.0 PascalCase shape first and falling back to the v0.3 slash-method shape.
// It returns the created task/context IDs and whether the creation was accepted.
func (e *MultiTenantIsolationExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string, p attack.Principal, randID string) (taskID, contextID string, accepted bool) {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-mt-create-" + p.Name + "-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian mt probe " + p.Name + " " + randID}},
				"messageId": "batesian-mt-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		slashHeaders := map[string]string{}
		for k, v := range p.Headers {
			slashHeaders[k] = v
		}
		resp, err = c.POST(ctx, endpoint, slashHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-mt-create-" + p.Name + "-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian mt probe " + p.Name + " " + randID}},
					"messageId": "batesian-mt-" + p.Name + "-" + randID,
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

// readTask attempts a GetTask for taskID over the given client (carrying its own
// token) plus any extra principal headers. It reports whether the task content
// was successfully returned (success, no JSON-RPC error, and the body references
// the task/context).
func (e *MultiTenantIsolationExecutor) readTask(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, contextID, randID string) bool {
	headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-mt-get-" + randID,
		"method":  "GetTask",
		"params":  map[string]interface{}{"id": taskID, "historyLength": 10},
	})
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		// Fall back to the v0.3 slash-method shape.
		resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-mt-get-" + randID,
			"method":  "tasks/get",
			"params":  map[string]interface{}{"id": taskID, "historyLength": 10},
		})
	}
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		return false
	}
	return resp.ContainsAny(`"history"`, `"contextId"`, taskID, contextID)
}

// finding builds the confirmed cross-tenant isolation breach finding. reader is
// the principal that performed the unauthorized read; owner owns the leaked task.
func (e *MultiTenantIsolationExecutor) finding(endpoint string, reader, owner attack.Principal, taskID, contextID string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task readable across tenant boundary by an authenticated principal",
		Description: fmt.Sprintf(
			"Principal %q (tenant %q) successfully read task %s (contextId %s) created by "+
				"principal %q (tenant %q), using only its own valid credentials. Task lookup "+
				"is authenticated but not bound to the owning tenant, so any tenant can read "+
				"another tenant's conversation history, tool outputs, and embedded context "+
				"given a task ID.",
			reader.Name, reader.Tenant, taskID, contextID, owner.Name, owner.Tenant),
		Evidence: fmt.Sprintf(
			"reader: %s (tenant %s)\nowner: %s (tenant %s)\ntask: %s\ncontextId: %s\n"+
				"unauthenticated read: rejected (auth enforced)\ncross-tenant GetTask: granted",
			reader.Name, reader.Tenant, owner.Name, owner.Tenant, taskID, contextID),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "authenticate and create task " + taskID, Outcome: "task created (owner " + owner.Tenant + ")"},
			{Hop: 2, Principal: reader.Name, Action: "authenticate as a different tenant", Outcome: "valid distinct credentials confirmed"},
			{Hop: 3, Principal: reader.Name, Action: "GetTask " + taskID + " (cross-tenant)", Outcome: "GRANTED - read another tenant's task"},
		},
	}
}

// principalClient builds an HTTP client that authenticates as the given
// principal (its bearer token is injected on every request).
func principalClient(opts attack.Options, vars attack.Vars, p attack.Principal) *attack.HTTPClient {
	o := opts
	o.Token = p.Token
	return attack.NewHTTPClient(o, vars)
}
