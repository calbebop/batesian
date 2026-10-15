package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// DelegationIntegrityExecutor checks for cross-principal task input.
type DelegationIntegrityExecutor struct {
	rule attack.RuleContext
}

type continuationOutcome uint8

const (
	continuationUnobserved continuationOutcome = iota
	continuationUnsupported
	continuationDenied
	continuationAccepted
)

func init() {
	attack.Register("a2a-delegation-integrity", func(rc attack.RuleContext) attack.Executor {
		return NewDelegationIntegrityExecutor(rc)
	})
}

func NewDelegationIntegrityExecutor(r attack.RuleContext) *DelegationIntegrityExecutor {
	return &DelegationIntegrityExecutor{rule: r}
}

func (e *DelegationIntegrityExecutor) Produces() []attack.ArtifactKind { return nil }

func (e *DelegationIntegrityExecutor) Requires() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactTaskID}
}

func (e *DelegationIntegrityExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

func (e *DelegationIntegrityExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) (findings []attack.Finding, err error) {
	// Cross-principal checks require two identities.
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

	// Reuse an owner task when available.
	taskID, contextID, consumed := e.consumeOwnedTask(bb, a)
	var obs setupObservation
	if taskID == "" {
		taskID, contextID, _, obs = e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	}
	if taskID == "" {
		// No owner task means the boundary was not tested.
		return nil, obs.err()
	}
	var incomplete error
	defer func() { err = errors.Join(err, incomplete) }()
	if !consumed {
		incomplete = errors.Join(incomplete, obs.partialErr())
	}

	// Exclude endpoints that persist unauthenticated continuations.
	anonymousMarker := "anon-" + vars.RandID
	anonymousOutcome := e.continueTask(ctx, unauthClient, endpoint, nil, taskID, contextID, anonymousMarker)
	_, found, err := e.waitForOwnerMarker(ctx, clientA, endpoint, a.Headers, taskID, anonymousMarker, vars.RandID)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, nil
	}
	switch anonymousOutcome {
	case continuationUnobserved:
		incomplete = errors.Join(incomplete, fmt.Errorf("%w: anonymous continuation returned no verdict", attack.ErrInconclusive))
	case continuationUnsupported:
		incomplete = errors.Join(incomplete, fmt.Errorf("%w: anonymous continuation was unsupported, so the control was not tested", attack.ErrInconclusive))
	}

	marker := "cross-" + vars.RandID
	bOutcome := e.continueTask(ctx, clientB, endpoint, b.Headers, taskID, contextID, marker)
	readable, found, err := e.waitForOwnerMarker(ctx, clientA, endpoint, a.Headers, taskID, marker, vars.RandID)
	if err != nil {
		return nil, err
	}
	if !found {
		if bOutcome != continuationDenied || !readable {
			return nil, fmt.Errorf("%w: cross-principal continuation was not found in the owner's task history", attack.ErrInconclusive)
		}
		return nil, nil
	}
	readable, found, err = e.waitForOwnerMarker(ctx, clientA, endpoint, a.Headers, taskID, anonymousMarker, vars.RandID)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, nil
	}
	if !readable {
		return nil, fmt.Errorf("%w: owner task history was unavailable on anonymous recheck", attack.ErrInconclusive)
	}
	anonymousEvidence := "denied; no stored message observed"
	switch anonymousOutcome {
	case continuationAccepted:
		anonymousEvidence = "accepted; no stored message observed"
	case continuationUnobserved:
		anonymousEvidence = "unobserved; no stored message observed"
	case continuationUnsupported:
		anonymousEvidence = "unsupported; no stored message observed"
	}
	return []attack.Finding{e.finding(endpoint, a, b, taskID, contextID, marker, anonymousEvidence, consumed)}, nil
}

// consumeOwnedTask finds an upstream task owned by A.
func (e *DelegationIntegrityExecutor) consumeOwnedTask(bb *attack.Blackboard, a attack.Principal) (taskID, contextID string, consumed bool) {
	for _, art := range bb.ByKind(attack.ArtifactTaskID) {
		if art.Value == "" || art.Principal != a.Name {
			continue
		}
		return art.Value, art.Meta["contextId"], true
	}
	return "", "", false
}

// createTask tries both wire formats and retains setup failures.
func (e *DelegationIntegrityExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (taskID, contextID string, accepted bool, obs setupObservation) {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		v1Headers[k] = v
	}
	requestID := "batesian-deleg-create-" + p.Name + "-" + randID
	observe := func(resp *attack.Response) {
		outcome := classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp)
		if resp != nil && resp.IsSuccess() {
			_, _, _, valid := discoveryResponse(resp.Body, requestID)
			if !valid {
				outcome = setupObservation{setupOtherRefusal, "task-creation reply did not match its request"}
			}
		}
		obs.observe(outcome)
	}
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian delegation probe " + randID}},
				"messageId": "batesian-deleg-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !delegationResult(resp, requestID) {
		observe(resp)
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
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
	if err != nil || !delegationResult(resp, requestID) {
		observe(resp)
		return "", "", false, obs
	}
	taskID, contextID = extractTaskContext(resp.Body)
	if taskID == "" {
		observe(resp)
	}
	return taskID, contextID, taskID != "", obs
}

func delegationResult(resp *attack.Response, requestID string) bool {
	if resp == nil || !resp.IsSuccess() {
		return false
	}
	_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	return valid && !hasError
}

// continueTask distinguishes denial from an unanswered probe.
func (e *DelegationIntegrityExecutor) continueTask(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, contextID, marker string) continuationOutcome {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extraHeaders {
		v1Headers[k] = v
	}
	requestID := "batesian-deleg-cont-" + marker
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian delegation continuation " + marker}},
				"messageId": "batesian-deleg-cont-" + marker,
				"taskId":    taskID,
				"contextId": contextID,
			},
		},
	})
	first := classifyContinuation(resp, err, requestID)
	if first == continuationAccepted {
		return first
	}
	resp, err = c.POST(ctx, endpoint, extraHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "message/send",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      "user",
				"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian delegation continuation " + marker}},
				"messageId": "batesian-deleg-cont-" + marker,
				"taskId":    taskID,
				"contextId": contextID,
			},
		},
	})
	second := classifyContinuation(resp, err, requestID)
	if second == continuationAccepted {
		return second
	}
	if first == continuationUnobserved || second == continuationUnobserved {
		return continuationUnobserved
	}
	if first == continuationDenied || second == continuationDenied {
		return continuationDenied
	}
	return continuationUnsupported
}

func classifyContinuation(resp *attack.Response, err error, requestID string) continuationOutcome {
	if err != nil || resp == nil {
		return continuationUnobserved
	}
	if delegationResult(resp, requestID) {
		return continuationAccepted
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return continuationDenied
	}
	if !resp.IsSuccess() {
		return continuationUnobserved
	}
	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &envelope) != nil || envelope.JSONRPC != "2.0" ||
		envelope.ID != requestID || envelope.Error == nil {
		return continuationUnobserved
	}
	if envelope.Error.Code == -32001 || attack.AuthFlavoredMessage(envelope.Error.Message) {
		return continuationDenied
	}
	if envelope.Error.Code == jsonRPCMethodNotFound || envelope.Error.Code == a2aUnsupportedOperation {
		return continuationUnsupported
	}
	return continuationUnobserved
}

func (e *DelegationIntegrityExecutor) waitForOwnerMarker(ctx context.Context, c *attack.HTTPClient, endpoint string, headers map[string]string, taskID, marker, randID string) (readable, found bool, err error) {
	delays := []time.Duration{0, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second}
	for attempt, delay := range delays {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return readable, false, ctx.Err()
			case <-time.After(delay):
			}
		}
		read, match := e.ownerHistoryHasMarker(ctx, c, endpoint, headers, taskID, marker, randID, attempt)
		readable = readable || read
		if match {
			return true, true, nil
		}
	}
	return readable, false, nil
}

func (e *DelegationIntegrityExecutor) ownerHistoryHasMarker(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, marker, randID string, attempt int) (readable, found bool) {
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
		requestID := fmt.Sprintf("batesian-deleg-get-%s-%d-%s", randID, attempt, shape.method)
		resp, err := c.POST(ctx, endpoint, shape.headers, map[string]interface{}{
			"jsonrpc": "2.0", "id": requestID, "method": shape.method,
			"params": map[string]interface{}{"id": taskID, "historyLength": 100},
		})
		if err == nil && resp.IsAccepted() {
			read, match := taskHistoryHasMarker(resp.Body, requestID, taskID, marker)
			readable = readable || read
			if match {
				return true, true
			}
		}
	}
	return readable, false
}

func taskHistoryHasMarker(body []byte, requestID, taskID, marker string) (readable, found bool) {
	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Result  *struct {
			ID      string          `json:"id"`
			History json.RawMessage `json:"history"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.JSONRPC != "2.0" ||
		envelope.ID != requestID || envelope.Result == nil || envelope.Result.ID != taskID {
		return false, false
	}
	var history []struct {
		TaskID string          `json:"taskId"`
		Role   json.RawMessage `json:"role"`
		Parts  []struct {
			Text string `json:"text"`
		} `json:"parts"`
	}
	if json.Unmarshal(envelope.Result.History, &history) != nil || history == nil {
		return false, false
	}
	for _, message := range history {
		switch string(message.Role) {
		case `1`, `"user"`, `"USER"`, `"ROLE_USER"`:
		default:
			continue
		}
		if message.TaskID != "" && message.TaskID != taskID {
			continue
		}
		for _, part := range message.Parts {
			if part.Text == "batesian delegation continuation "+marker {
				return true, true
			}
		}
	}
	return true, false
}

// finding reports a continuation verified in the owner's task history.
func (e *DelegationIntegrityExecutor) finding(endpoint string, owner, attacker attack.Principal, taskID, contextID, marker, anonymousOutcome string, consumed bool) attack.Finding {
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
		Title:      "A2A task stores another principal's continuation",
		Description: fmt.Sprintf(
			"Principal %q sent a follow-up to task %s (contextId %s), owned by principal %q. "+
				"The unique message appeared in the owner's task history. Unauthenticated "+
				"control: %s. This confirms cross-principal input to the task; downstream "+
				"execution was not verified. Confirm whether the caller was an intended delegate. "+
				"Owner task origin: %s.",
			attacker.Name, taskID, contextID, owner.Name, anonymousOutcome, origin),
		Evidence: fmt.Sprintf(
			"owner: %s (tenant %s)\nattacker: %s (tenant %s)\ntask: %s\ncontextId: %s\n"+
				"task origin: %s\nunauthenticated continuation: %s\n"+
				"cross-principal marker in owner task history: %s",
			owner.Name, owner.Tenant, attacker.Name, attacker.Tenant, taskID, contextID, origin, anonymousOutcome, marker),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: hop1Action, Outcome: "task owned by " + owner.Name + ", awaiting continuation"},
			{Hop: 2, Principal: attacker.Name, Action: "continue task " + taskID + " as a different principal", Outcome: "GRANTED - message stored in owner task history"},
		},
	}
}
