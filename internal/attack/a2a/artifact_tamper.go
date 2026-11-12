package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ArtifactTamperExecutor checks whether a continuation replaces content already
// stored on a completed task. Truncated history alone cannot prove replacement.
type ArtifactTamperExecutor struct {
	rule attack.RuleContext
}

// NewArtifactTamperExecutor creates an executor for a2a-artifact-tamper.
func init() {
	attack.Register("a2a-artifact-tamper", func(rc attack.RuleContext) attack.Executor { return NewArtifactTamperExecutor(rc) })
}

func NewArtifactTamperExecutor(r attack.RuleContext) *ArtifactTamperExecutor {
	return &ArtifactTamperExecutor{rule: r}
}

func (e *ArtifactTamperExecutor) Execute(ctx context.Context, target string, opts attack.Options) (_ []attack.Finding, err error) {
	ctx = withTenantRouting(ctx)
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoint, ok := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	originalText := "batesian-original-" + vars.RandID
	tamperedText := "batesian-tampered-" + vars.RandID

	// Step 1: create a task carrying the original marker.
	taskID, wire, ok, createErr := e.createTask(ctx, client, endpoint, originalText, vars.RandID)
	if !ok {
		// No task was created, so immutability was not tested.
		return nil, errors.Join(fmt.Errorf("%w: the agent at %s accepted no task-creating request "+
			"(SendMessage, message/send or tasks/send), so there was no task whose immutability "+
			"could be tested", attack.ErrInconclusive, endpoint), createErr)
	}
	incomplete := createErr
	defer func() { err = errors.Join(err, incomplete) }()
	baselineBody, ok, readErr := readTaskHistory(ctx, client, endpoint, wire.headers, taskID, vars, "baseline")
	incomplete = errors.Join(incomplete, readErr)
	if !ok {
		return nil, fmt.Errorf("%w: the created task's original content could not be read back",
			attack.ErrInconclusive)
	}
	baseline, ok := storedTaskContent(baselineBody, taskID)
	if !ok || !baseline.completed() {
		return nil, fmt.Errorf("%w: the created task did not expose a completed task with stored content",
			attack.ErrInconclusive)
	}
	contentKeys := baseline.fieldsContaining(originalText)
	if len(contentKeys) == 0 {
		return nil, fmt.Errorf("%w: the created task did not expose the original marker in stored content",
			attack.ErrInconclusive)
	}

	// Step 2: re-submit against the SAME task ID with different content, on the
	// wire that created it.
	tamperRequest := wire.continuePayload(taskID, tamperedText, vars.RandID)
	tamperID, _ := tamperRequest["id"].(string)
	tamperResp, sendErr := client.POST(ctx, endpoint, wire.headers, tamperRequest)
	correlated := tamperReplyCorrelated(tamperResp, tamperID)
	accepted := sendErr == nil && correlated && tamperResp.IsAccepted()
	rejected := sendErr == nil && correlated && continuationRejected(tamperResp)
	if sendErr == nil && tamperResp != nil && tamperResp.IsSuccess() && !correlated {
		incomplete = errors.Join(incomplete, fmt.Errorf("%w: task continuation reply did not match its request ID",
			attack.ErrInconclusive))
	}
	var continuation taskContent
	var hasTask bool
	if accepted {
		continuation, hasTask = storedTaskContent(tamperResp.Body, taskID)
	}

	// Read back even when the send reports an error.
	getBody, ok, readErr := readTaskHistory(ctx, client, endpoint, wire.headers, taskID, vars, "after")
	incomplete = errors.Join(incomplete, readErr)
	if !ok {
		return nil, fmt.Errorf("%w: the task was re-submitted, but reading it back "+
			"returned no task content, so whether the stored artifact changed could not be "+
			"established", attack.ErrInconclusive)
	}

	current, ok := storedTaskContent(getBody, taskID)
	if !ok {
		return nil, fmt.Errorf("%w: the task did not return a usable result after re-submission",
			attack.ErrInconclusive)
	}
	allPreserved := current.completed()
	for index, contentKey := range contentKeys {
		stored, visible := current.fields[contentKey]
		if !visible {
			allPreserved = false
			continue
		}
		hasTampered := strings.Contains(stored, tamperedText)
		hasOriginal := strings.Contains(stored, originalText)
		if hasTampered && !hasOriginal && current.completed() {
			return []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title:      "A2A completed task stored content overwritten",
				Description: "A completed task stored the original probe marker in an artifact. After a continuation, " +
					"the same artifact contained the replacement marker without the original. A reader of that task receives altered content.",
				Evidence: fmt.Sprintf(
					"Task and artifact IDs: omitted\nWire: %s\nMatched artifact: %d of %d\nBefore: original marker present\n"+
						"After: replacement marker present; original marker absent\nStored content omitted",
					wire.name, index+1, len(contentKeys)),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			}}, nil
		}
		if !hasOriginal {
			allPreserved = false
		}
	}
	if allPreserved && (rejected || (accepted && hasTask && continuation.completed())) {
		return nil, nil
	}
	if sendErr != nil {
		return nil, fmt.Errorf("%w: task continuation received no answer: %v",
			attack.ErrInconclusive, sendErr)
	}
	if tamperResp == nil {
		return nil, fmt.Errorf("%w: task continuation returned no response", attack.ErrInconclusive)
	}
	if !accepted {
		return nil, fmt.Errorf("%w: task continuation returned an unjudged response (HTTP %d)",
			attack.ErrInconclusive, tamperResp.StatusCode)
	}
	return nil, fmt.Errorf("%w: task did not show a completed replacement in its original artifacts",
		attack.ErrInconclusive)
}

func continuationRejected(resp *attack.Response) bool {
	if resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return false
	}
	message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
	if message == "" {
		return false
	}
	for _, reason := range []string{"already exists", "completed task", "task completed", "terminal state", "immutable", "cannot be restarted"} {
		if strings.Contains(message, reason) {
			return true
		}
	}
	return false
}

func tamperReplyCorrelated(resp *attack.Response, requestID string) bool {
	if resp == nil {
		return false
	}
	_, _, _, valid := discoveryResponse(resp.Body, requestID)
	return valid
}

type taskContent struct {
	state  string
	fields map[string]string
}

func (c taskContent) completed() bool {
	return strings.EqualFold(c.state, "completed") || c.state == "TASK_STATE_COMPLETED"
}

func (c taskContent) fieldsContaining(marker string) []string {
	var keys []string
	for key, value := range c.fields {
		if strings.Contains(value, marker) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func storedTaskContent(body []byte, taskID string) (taskContent, bool) {
	type storedField struct {
		Parts json.RawMessage `json:"parts"`
	}
	type artifact struct {
		ID string `json:"artifactId"`
		storedField
	}
	type task struct {
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
		Artifacts []artifact `json:"artifacts"`
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return taskContent{}, false
	}
	id, _ := taskResultContext(envelope.Result)
	if id != taskID {
		return taskContent{}, false
	}
	var result struct {
		task
		Task *task `json:"task"`
	}
	if json.Unmarshal(envelope.Result, &result) != nil {
		return taskContent{}, false
	}
	parsed := result.task
	if result.Task != nil {
		parsed = *result.Task
	}
	content := taskContent{state: parsed.Status.State, fields: make(map[string]string)}
	for _, artifact := range parsed.Artifacts {
		if artifact.ID != "" {
			if text := storedText(artifact.Parts); text != "" {
				content.fields["artifact:"+artifact.ID] = text
			}
		}
	}
	return content, true
}

func storedText(raw json.RawMessage) string {
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var text []string
	for _, part := range parts {
		if part.Text != "" {
			text = append(text, part.Text)
		}
	}
	return strings.Join(text, "\n")
}

// tamperWire is one protocol revision's shapes for creating and continuing a task.
// The revisions disagree on the method name and on where the task id goes, and a
// server answers a name it does not implement with -32601 at HTTP 200, so a
// fallback keyed on HTTP status alone never advances past the first attempt.
type tamperWire struct {
	name            string
	headers         map[string]string
	continuePayload func(taskID, text, randID string) map[string]interface{}
}

// createTask submits the original marker, trying each revision until one is
// accepted, and returns the task id together with the wire that worked.
func (e *ArtifactTamperExecutor) createTask(ctx context.Context, client *attack.HTTPClient,
	endpoint, text, randID string) (string, tamperWire, bool, error) {
	v1Headers := map[string]string{"A2A-Version": "1.0"}

	attempts := []struct {
		wire   tamperWire
		create map[string]interface{}
	}{
		{
			// v1.0: PascalCase plus the version header, and the task id rides in the
			// message rather than in params.
			wire: tamperWire{
				name:    "v1.0 SendMessage",
				headers: v1Headers,
				continuePayload: func(taskID, text, randID string) map[string]interface{} {
					return jsonRPCCall("batesian-at-"+randID+"-continue-v1", "SendMessage", map[string]interface{}{
						"message": map[string]interface{}{
							"messageId": "batesian-at-tamper-" + randID,
							"role":      "ROLE_USER",
							"taskId":    taskID,
							"parts":     []interface{}{map[string]interface{}{"text": text}},
						},
					})
				},
			},
			create: jsonRPCCall("batesian-at-"+randID+"-create-v1", "SendMessage", map[string]interface{}{
				"message": map[string]interface{}{
					"messageId": "batesian-at-create-" + randID,
					"role":      "ROLE_USER",
					"parts":     []interface{}{map[string]interface{}{"text": text}},
				},
			}),
		},
		{
			// v0.3: slash method, lowercase role, parts carry a kind.
			wire: tamperWire{
				name: "v0.3 message/send",
				continuePayload: func(taskID, text, randID string) map[string]interface{} {
					return jsonRPCCall("batesian-at-"+randID+"-continue-v03", "message/send", map[string]interface{}{
						"message": map[string]interface{}{
							"messageId": "batesian-at-tamper-" + randID,
							"role":      "user",
							"taskId":    taskID,
							"parts":     []interface{}{map[string]interface{}{"kind": "text", "text": text}},
						},
					})
				},
			},
			create: jsonRPCCall("batesian-at-"+randID+"-create-v03", "message/send", map[string]interface{}{
				"message": map[string]interface{}{
					"messageId": "batesian-at-create-" + randID,
					"role":      "user",
					"parts":     []interface{}{map[string]interface{}{"kind": "text", "text": text}},
				},
			}),
		},
		{
			// Legacy tasks/send puts the task ID in params. Keep it last.
			wire: tamperWire{
				name: "legacy tasks/send",
				continuePayload: func(taskID, text, randID string) map[string]interface{} {
					return jsonRPCCall("batesian-at-"+randID+"-continue-v02", "tasks/send", map[string]interface{}{
						"id": taskID,
						"message": map[string]interface{}{
							"role":  "user",
							"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}},
						},
					})
				},
			},
			create: jsonRPCCall("batesian-at-"+randID+"-create-v02", "tasks/send", map[string]interface{}{
				"id": "batesian-task-" + randID,
				"message": map[string]interface{}{
					"role":  "user",
					"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}},
				},
			}),
		},
	}

	var incomplete error
	credentialed := client.PresentsCredential(endpoint)
	for _, a := range attempts {
		requestID, _ := a.create["id"].(string)
		resp, err := client.POST(ctx, endpoint, a.wire.headers, a.create)
		// IsAccepted, not IsSuccess: a -32601 for a method this revision does not
		// define arrives at HTTP 200, and gating on status alone left the fallback
		// unreachable.
		if err != nil {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: %s task creation at %s received no answer: %v",
				attack.ErrInconclusive, a.wire.name, endpoint, err))
			continue
		}
		if resp != nil && resp.IsSuccess() && !tamperReplyCorrelated(resp, requestID) {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: %s task-creation reply did not match its request ID",
				attack.ErrInconclusive, a.wire.name))
			continue
		}
		if resp == nil || !resp.IsAccepted() {
			if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
				continue
			}
			outcome := classifyTaskSetup("creating a task on the "+a.wire.name+" wire", endpoint, credentialed, resp)
			if outcome.rank == setupOtherRefusal {
				incomplete = errors.Join(incomplete, fmt.Errorf("%w: %s", attack.ErrInconclusive, outcome.reason))
			}
			continue
		}
		if id, _ := extractTaskContext(resp.Body); id != "" {
			return id, a.wire, true, incomplete
		}
		outcome := classifyTaskSetup("creating a task on the "+a.wire.name+" wire", endpoint, credentialed, resp)
		incomplete = errors.Join(incomplete, fmt.Errorf("%w: %s", attack.ErrInconclusive, outcome.reason))
	}
	return "", tamperWire{}, false, incomplete
}

func jsonRPCCall(requestID, method string, params map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  method,
		"params":  params,
	}
}
