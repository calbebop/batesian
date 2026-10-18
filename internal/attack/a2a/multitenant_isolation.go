package a2a

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// MultiTenantIsolationExecutor checks cross-tenant task reads and publishes
// created tasks for chained rules.
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
	ctx = withTenantRouting(ctx)
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

// ExecuteChained runs the multi-tenant isolation check.
func (e *MultiTenantIsolationExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	// Cross-tenant reads require distinct principals and tenant labels.
	a, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Tenant) == "" || strings.TrimSpace(b.Tenant) == "" ||
		strings.TrimSpace(a.Tenant) == strings.TrimSpace(b.Tenant) {
		return nil, fmt.Errorf("%w: principals %q and %q need distinct, nonempty tenant labels for a cross-tenant check",
			attack.ErrInconclusive, a.Name, b.Name)
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	// Each principal creates a task with unique content.
	taskA, ctxA, okA, obsA := e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	taskB, ctxB, okB, obsB := e.createTask(ctx, clientB, endpoint, b, vars.RandID)
	if !okA || !okB {
		// Both tasks are required for the comparison.
		obs := obsA
		obs.observe(obsB)
		return nil, obs.err()
	}
	setupErr := errors.Join(obsA.partialErr(), obsB.partialErr())
	bb.Publish(attack.Artifact{Kind: attack.ArtifactToken, Value: a.Token, Principal: a.Name, Producer: e.rule.ID})
	bb.Publish(attack.Artifact{Kind: attack.ArtifactToken, Value: b.Token, Principal: b.Name, Producer: e.rule.ID})
	bb.Publish(attack.Artifact{Kind: attack.ArtifactTaskID, Value: taskA, Principal: a.Name, Producer: e.rule.ID, Meta: map[string]string{"contextId": ctxA}})
	bb.Publish(attack.Artifact{Kind: attack.ArtifactTaskID, Value: taskB, Principal: b.Name, Producer: e.rule.ID, Meta: map[string]string{"contextId": ctxB}})

	markerA := "batesian mt probe " + a.Name + " " + vars.RandID
	markerB := "batesian mt probe " + b.Name + " " + vars.RandID
	// Anonymous disclosure belongs to the task IDOR rule.
	anonA := e.readTask(ctx, unauthClient, endpoint, nil, taskA, markerA, vars.RandID, "anon-a")
	anonB := e.readTask(ctx, unauthClient, endpoint, nil, taskB, markerB, vars.RandID, "anon-b")

	// Check both directions for the owner's probe content.
	var findings []attack.Finding
	readA := e.readTask(ctx, clientB, endpoint, b.Headers, taskA, markerA, vars.RandID, "cross-a")
	if readA.location != "" && anonA.location == "" && !anonA.unknown && (anonA.denied || anonA.matched) {
		findings = append(findings, e.finding(endpoint, b, a, taskA, markerA, readA))
	}
	readB := e.readTask(ctx, clientA, endpoint, a.Headers, taskB, markerB, vars.RandID, "cross-b")
	if readB.location != "" && anonB.location == "" && !anonB.unknown && (anonB.denied || anonB.matched) {
		findings = append(findings, e.finding(endpoint, a, b, taskB, markerB, readB))
	}
	var missing []string
	for _, check := range []struct {
		name  string
		read  tenantRead
		cross bool
	}{
		{"anonymous read of A", anonA, false}, {"anonymous read of B", anonB, false},
		{"B reading A", readA, true}, {"A reading B", readB, true},
	} {
		if check.read.unknown || (check.cross && check.read.matched && check.read.location == "") ||
			(!check.read.denied && !check.read.matched && check.read.location == "") {
			missing = append(missing, check.name)
		}
	}
	if len(missing) > 0 {
		return findings, errors.Join(setupErr, fmt.Errorf("%w: task reads did not establish all comparisons: %s",
			attack.ErrInconclusive, strings.Join(missing, ", ")))
	}
	return findings, setupErr
}

// createTask tries v1 and v0.3 and keeps setup diagnostics from both.
func (e *MultiTenantIsolationExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (taskID, contextID string, accepted bool, obs setupObservation) {
	v1Headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		v1Headers[k] = v
	}
	requestID := "batesian-mt-create-" + p.Name + "-" + randID
	resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian mt probe " + p.Name + " " + randID}},
				"messageId": "batesian-mt-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		slashHeaders := map[string]string{}
		for k, v := range p.Headers {
			slashHeaders[k] = v
		}
		requestID += "-v03"
		resp, err = c.POST(ctx, endpoint, slashHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
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
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		return "", "", false, obs
	}
	taskID, contextID = extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
	}
	return taskID, contextID, taskID != "", obs
}

type tenantRead struct {
	method   string
	location string
	response string
	matched  bool
	denied   bool
	unknown  bool
}

// readTask checks both method names until owner content is found.
func (e *MultiTenantIsolationExecutor) readTask(ctx context.Context, c *attack.HTTPClient, endpoint string, extraHeaders map[string]string, taskID, marker, randID, phase string) tenantRead {
	shapes := []struct {
		method  string
		headers map[string]string
	}{
		{"GetTask", map[string]string{"A2A-Version": "1.0"}},
		{"tasks/get", extraHeaders},
	}
	for k, v := range extraHeaders {
		shapes[0].headers[k] = v
	}
	var result tenantRead
	for _, shape := range shapes {
		requestID := "batesian-mt-get-" + randID + "-" + phase + "-" + shape.method
		resp, err := c.POST(ctx, endpoint, shape.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  shape.method,
			"params":  map[string]interface{}{"id": taskID, "historyLength": 10},
		})
		if err != nil || resp == nil {
			result.unknown = true
			continue
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
			result.denied = true
			continue
		}
		if !resp.IsSuccess() {
			result.unknown = true
			continue
		}
		_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			result.unknown = true
			continue
		}
		if hasError {
			if code == -32001 || errMessageIsAuth(resp.Body) {
				result.denied = true
			} else if code != jsonRPCMethodNotFound {
				result.unknown = true
			}
			continue
		}
		location, matched := taskReadMarkerLocation(resp.Body, taskID, marker)
		result.matched = result.matched || matched
		if location != "" {
			return tenantRead{method: shape.method, location: location, response: snippet(resp.Body, 500), matched: true, unknown: result.unknown}
		}
		if !matched {
			result.unknown = true
		}
	}
	return result
}

// finding describes the owner's content observed by another tenant.
func (e *MultiTenantIsolationExecutor) finding(endpoint string, reader, owner attack.Principal, taskID, marker string, read tenantRead) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task readable across configured tenant boundary by an authenticated principal",
		Description: fmt.Sprintf(
			"Principal %q (configured tenant %q) received principal %q's (configured tenant %q) "+
				"unique probe text from task %s's %s through %s. The task content crossed the "+
				"configured tenant boundary; verify that the labels match the target's assignments.",
			reader.Name, reader.Tenant, owner.Name, owner.Tenant, taskID, read.location, read.method),
		Evidence: fmt.Sprintf(
			"reader: %s (tenant %s)\nowner: %s (tenant %s)\ntask: %s\nmethod: %s\n"+
				"owner marker: %s\nlocation: %s\nresponse: %s",
			reader.Name, reader.Tenant, owner.Name, owner.Tenant, taskID, read.method, marker, read.location, read.response),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "authenticate and create task " + taskID, Outcome: "task created (owner " + owner.Tenant + ")"},
			{Hop: 2, Principal: reader.Name, Action: "authenticate as a different tenant", Outcome: "valid distinct credentials confirmed"},
			{Hop: 3, Principal: reader.Name, Action: read.method + " " + taskID + " (cross-tenant)", Outcome: "GRANTED - read owner's probe content"},
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
