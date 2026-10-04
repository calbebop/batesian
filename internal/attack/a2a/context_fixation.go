package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	// Two distinct identities are this rule's premise; without them it cannot run.
	// See twoPrincipals: all five cross-principal rules used to report clean here,
	// so a scan with no --principal flags called 29 percent of the A2A set secure
	// without sending a packet.
	a, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
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
	ownerMarker := "batesian ctx-fix probe " + vars.RandID
	ownerSend := e.sendUnderContext(ctx, clientA, endpoint, a.Headers, fixedCtx,
		ownerMarker, vars.RandID+"-owner", "sending a message as principal "+a.Name)
	if ownerSend.taskID == "" {
		return nil, ownerSend.obs.err()
	}
	if ownerSend.contextID == "" {
		return nil, fmt.Errorf("%w: the owner's task response omitted its contextId",
			attack.ErrInconclusive)
	}
	if ownerSend.contextID != fixedCtx {
		// The server minted its own contextId rather than honouring the client's, which
		// is the secure behaviour and a real tested result.
		return nil, nil
	}
	bb.Publish(attack.Artifact{Kind: attack.ArtifactContextID, Value: fixedCtx, Principal: a.Name, Producer: e.rule.ID})

	// Step 2: open-server discriminator. An unauthenticated message under the
	// fixed context must be rejected; if it is accepted, the server enforces no
	// auth at all (not fixation).
	anonSend := e.sendUnderContext(ctx, unauthClient, endpoint, nil, fixedCtx,
		"batesian anon "+vars.RandID, vars.RandID+"-anon", "sending an unauthenticated message")
	if anonSend.accepted {
		return nil, nil
	}
	if !anonSend.denied[ownerSend.wire-1] {
		return nil, fmt.Errorf("%w: anonymous message under the fixed context was not conclusively rejected as unauthorized",
			attack.ErrInconclusive)
	}

	// Step 3: as victim B, send a secret marker under the SAME fixed context.
	victimSend := e.sendUnderContext(ctx, clientB, endpoint, b.Headers, fixedCtx, marker, vars.RandID+"-victim",
		"sending the victim's message as principal "+b.Name)
	if victimSend.taskID == "" {
		if err := victimSend.obs.err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: the victim could not create a task under the fixed context",
			attack.ErrInconclusive)
	}
	if victimSend.contextID != fixedCtx {
		return nil, fmt.Errorf("%w: the victim's task did not confirm the fixed contextId",
			attack.ErrInconclusive)
	}
	if !anonSend.denied[victimSend.wire-1] {
		return nil, fmt.Errorf("%w: anonymous continuation was not rejected on the victim's message wire",
			attack.ErrInconclusive)
	}

	// Step 4: as A, read the context back. Confirmed only if A can see B's marker.
	// A read that never happened is not evidence of isolation: a marker "not
	// found" in a history that was never fetched says nothing about the merge.
	// a2a-artifact-tamper-001 reports the identical unreadable-read-back as not
	// tested; this step used to return clean.
	read, contains, readObs := e.taskHistoryContains(ctx, clientA, endpoint, a.Headers, ownerSend.taskID, marker, vars.RandID+"-victim")
	if !read {
		if err := readObs.err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: no task-history read method returned the owner's task",
			attack.ErrInconclusive)
	}
	if !contains {
		ownRead, ownFound, _ := e.taskHistoryContains(ctx, clientA, endpoint, a.Headers,
			ownerSend.taskID, ownerMarker, vars.RandID+"-owner")
		if !ownRead || !ownFound {
			return nil, fmt.Errorf("%w: the owner's task history did not include its own probe message",
				attack.ErrInconclusive)
		}
		return nil, nil // the history was read; the victim's marker was not merged into A's view
	}

	return []attack.Finding{e.finding(endpoint, a, b, fixedCtx, ownerSend.taskID, victimSend.taskID)}, nil
}

type contextSendResult struct {
	taskID, contextID string
	accepted          bool
	wire              int
	denied            [2]bool
	obs               setupObservation
}

// sendUnderContext tries v1.0 and v0.3 while retaining each wire's auth result.
func (e *ContextFixationExecutor) sendUnderContext(ctx context.Context, c *attack.HTTPClient, endpoint string,
	extraHeaders map[string]string, contextID, text, randID, what string) contextSendResult {
	var result contextSendResult
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	requestID := "batesian-ctxfix-send-" + randID
	acceptReply := func(resp *attack.Response, err error) bool {
		if err != nil || resp == nil || !resp.IsSuccess() {
			return false
		}
		_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
		return valid && !hasError
	}
	authRejected := func(resp *attack.Response) bool {
		if resp == nil {
			return false
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return true
		}
		_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
		return resp.IsSuccess() && valid && hasError && attack.AuthFlavoredMessage(jsonRPCErrorMessage(resp.Body))
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
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
	result.accepted = acceptReply(resp, err)
	if result.accepted {
		result.wire = 1
	} else {
		result.denied[0] = authRejected(resp)
		result.obs.observe(classifyTaskSetup(what, endpoint, principalCredentialPresent(c, endpoint, extraHeaders), resp))
		resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
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
		result.accepted = acceptReply(resp, err)
		if result.accepted {
			result.wire = 2
		} else {
			result.denied[1] = authRejected(resp)
			result.obs.observe(classifyTaskSetup(what, endpoint, principalCredentialPresent(c, endpoint, extraHeaders), resp))
			return result
		}
	}
	result.taskID, result.contextID = extractTaskContext(resp.Body)
	if result.taskID == "" {
		result.obs.observe(classifyTaskSetup(what, endpoint, principalCredentialPresent(c, endpoint, extraHeaders), resp))
	}
	return result
}

// taskHistoryContains reads a task via GetTask (v1.0) / tasks/get (v0.3) and
// reports whether the returned history contains the given marker - i.e. the
// shared context exposed another principal's message.
//
// read is false when neither shape yielded a usable task result; obs then
// explains why (and contains is meaningless). Callers must not read a false
// contains as "marker absent" without checking read first.
func (e *ContextFixationExecutor) taskHistoryContains(ctx context.Context, c *attack.HTTPClient, endpoint string,
	extraHeaders map[string]string, taskID, marker, randID string) (read, contains bool, obs setupObservation) {
	what := "reading the task history back"
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	for _, shape := range []struct {
		method  string
		headers map[string]string
	}{
		{"GetTask", v1Headers},
		{"tasks/get", extraHeaders},
	} {
		requestID := "batesian-ctxfix-get-" + randID + "-" + shape.method
		resp, err := c.POST(ctx, endpoint, shape.headers, map[string]interface{}{
			"jsonrpc": "2.0", "id": requestID, "method": shape.method,
			"params": map[string]interface{}{"id": taskID, "historyLength": 50},
		})
		if err == nil && resp != nil && resp.IsSuccess() {
			readable, found := contextTaskHistoryHasText(resp.Body, requestID, taskID, marker)
			read = read || readable
			if found {
				return true, true, setupObservation{}
			}
			if !readable {
				obs.observe(setupObservation{setupOtherRefusal,
					fmt.Sprintf("%s at %s did not return task %s with a usable history", what, endpoint, taskID)})
			}
			continue
		}
		obs.observe(classifyTaskSetup(what, endpoint, principalCredentialPresent(c, endpoint, extraHeaders), resp))
	}
	return read, false, obs
}

func contextTaskHistoryHasText(body []byte, requestID, taskID, marker string) (readable, found bool) {
	var reply struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Result  json.RawMessage `json:"result"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.JSONRPC != "2.0" || reply.ID != requestID {
		return false, false
	}
	type task struct {
		ID      string          `json:"id"`
		History json.RawMessage `json:"history"`
	}
	var result struct {
		task
		Task *task `json:"task"`
	}
	if json.Unmarshal(reply.Result, &result) != nil {
		return false, false
	}
	candidates := []task{result.task}
	if result.Task != nil {
		candidates = append(candidates, *result.Task)
	}
	for _, candidate := range candidates {
		if candidate.ID != taskID {
			continue
		}
		var history []struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		}
		if json.Unmarshal(candidate.History, &history) != nil || history == nil {
			continue
		}
		readable = true
		for _, message := range history {
			for _, part := range message.Parts {
				if strings.Contains(part.Text, marker) {
					return true, true
				}
			}
		}
	}
	return readable, false
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
