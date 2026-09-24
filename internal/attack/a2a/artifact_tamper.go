package a2a

import (
	"context"
	"encoding/json"
	"fmt"
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

func (e *ArtifactTamperExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoint, ok := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	originalText := "batesian-original-" + vars.RandID
	tamperedText := "batesian-tampered-" + vars.RandID

	// Step 1: create a task carrying the original marker.
	taskID, wire, ok := e.createTask(ctx, client, endpoint, originalText, vars.RandID)
	if !ok {
		// No task exists to tamper with, so immutability was never exercised. This
		// path used to return clean with the comment "not an A2A server", which
		// resolveA2AEndpoint has already ruled out, and which meant a stale v0.2-only
		// method name reported every real agent secure.
		return nil, fmt.Errorf("%w: the agent at %s accepted no task-creating request "+
			"(SendMessage, message/send or tasks/send), so there was no task whose immutability "+
			"could be tested", attack.ErrInconclusive, endpoint)
	}
	baselineBody, ok := readTaskHistory(ctx, client, endpoint, wire.headers, taskID, vars)
	if !ok {
		return nil, fmt.Errorf("%w: task %s was created, but its original content could not be read back",
			attack.ErrInconclusive, taskID)
	}
	baseline, ok := storedTaskContent(baselineBody, taskID)
	if !ok || !baseline.completed() {
		return nil, fmt.Errorf("%w: task %s did not expose a completed task with stored content",
			attack.ErrInconclusive, taskID)
	}
	contentKeys := baseline.fieldsContaining(originalText)
	if len(contentKeys) == 0 {
		return nil, fmt.Errorf("%w: task %s did not expose the original marker in stored content",
			attack.ErrInconclusive, taskID)
	}

	// Step 2: re-submit against the SAME task ID with different content, on the
	// wire that created it.
	tamperResp, err := client.POST(ctx, endpoint, wire.headers, wire.continuePayload(taskID, tamperedText, vars.RandID))
	if err != nil {
		return nil, fmt.Errorf("%w: task %s continuation received no answer: %v",
			attack.ErrInconclusive, taskID, err)
	}
	if !tamperResp.IsAccepted() {
		if continuationRejected(tamperResp) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: task %s continuation returned an unjudged response (HTTP %d)",
			attack.ErrInconclusive, taskID, tamperResp.StatusCode)
	}
	continuation, hasTask := storedTaskContent(tamperResp.Body, taskID)

	// Step 3: compare the same stored field after the continuation.
	getBody, ok := readTaskHistory(ctx, client, endpoint, wire.headers, taskID, vars)
	if !ok {
		return nil, fmt.Errorf("%w: task %s was re-submitted and accepted, but reading it back "+
			"returned no task content, so whether the stored artifact changed could not be "+
			"established", attack.ErrInconclusive, taskID)
	}

	current, ok := storedTaskContent(getBody, taskID)
	if !ok {
		return nil, fmt.Errorf("%w: task %s did not return a usable task after re-submission",
			attack.ErrInconclusive, taskID)
	}
	allPreserved := current.completed()
	for _, contentKey := range contentKeys {
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
				Title:      fmt.Sprintf("A2A task %q stored content overwritten", taskID),
				Description: fmt.Sprintf(
					"The completed task %q stored %q in %s. After a continuation, the same field "+
						"contains %q instead. A reader of that task receives altered content.",
					taskID, originalText, contentKey, tamperedText),
				Evidence: fmt.Sprintf(
					"Task ID: %q\nWire: %s\nContent field: %s\nBefore: %.300s\nAfter: %.300s",
					taskID, wire.name, contentKey, baseline.fields[contentKey], stored),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			}}, nil
		}
		if !hasOriginal {
			allPreserved = false
		}
	}
	if allPreserved && hasTask && continuation.completed() {
		return nil, nil
	}
	return nil, fmt.Errorf("%w: task %s did not show a completed replacement in its original artifacts",
		attack.ErrInconclusive, taskID)
}

func continuationRejected(resp *attack.Response) bool {
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
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
		State  string `json:"state"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
		Artifacts []artifact `json:"artifacts"`
	}
	var envelope struct {
		Result *struct {
			task
			Task *task `json:"task"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Result == nil {
		return taskContent{}, false
	}
	result := envelope.Result.task
	if envelope.Result.Task != nil {
		result = *envelope.Result.Task
	}
	if result.ID != taskID {
		return taskContent{}, false
	}
	content := taskContent{state: result.State, fields: make(map[string]string)}
	if result.Status.State != "" {
		content.state = result.Status.State
	}
	for _, artifact := range result.Artifacts {
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
	endpoint, text, randID string) (string, tamperWire, bool) {
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
					return jsonRPCCall("SendMessage", map[string]interface{}{
						"message": map[string]interface{}{
							"messageId": "batesian-at-tamper-" + randID,
							"role":      "ROLE_USER",
							"taskId":    taskID,
							"parts":     []interface{}{map[string]interface{}{"text": text}},
						},
					})
				},
			},
			create: jsonRPCCall("SendMessage", map[string]interface{}{
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
					return jsonRPCCall("message/send", map[string]interface{}{
						"message": map[string]interface{}{
							"messageId": "batesian-at-tamper-" + randID,
							"role":      "user",
							"taskId":    taskID,
							"parts":     []interface{}{map[string]interface{}{"kind": "text", "text": text}},
						},
					})
				},
			},
			create: jsonRPCCall("message/send", map[string]interface{}{
				"message": map[string]interface{}{
					"messageId": "batesian-at-create-" + randID,
					"role":      "user",
					"parts":     []interface{}{map[string]interface{}{"kind": "text", "text": text}},
				},
			}),
		},
		{
			// v0.2: the task id is a params field and re-submitting it IS the
			// overwrite attempt. Kept last so a modern agent never sees it.
			wire: tamperWire{
				name: "v0.2 tasks/send",
				continuePayload: func(taskID, text, randID string) map[string]interface{} {
					return jsonRPCCall("tasks/send", map[string]interface{}{
						"id": taskID,
						"message": map[string]interface{}{
							"role":  "user",
							"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}},
						},
					})
				},
			},
			create: jsonRPCCall("tasks/send", map[string]interface{}{
				"id": "batesian-task-" + randID,
				"message": map[string]interface{}{
					"role":  "user",
					"parts": []interface{}{map[string]interface{}{"type": "text", "text": text}},
				},
			}),
		},
	}

	for _, a := range attempts {
		resp, err := client.POST(ctx, endpoint, a.wire.headers, a.create)
		// IsAccepted, not IsSuccess: a -32601 for a method this revision does not
		// define arrives at HTTP 200, and gating on status alone left the fallback
		// unreachable.
		if err != nil || !resp.IsAccepted() {
			continue
		}
		var body map[string]interface{}
		_ = json.Unmarshal(resp.Body, &body)
		if id := extractTaskID(body); id != "" {
			return id, a.wire, true
		}
	}
	return "", tamperWire{}, false
}

// jsonRPCCall builds a JSON-RPC request object with a fixed id, which is all these
// probes need.
func jsonRPCCall(method string, params map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
}

// extractTaskID pulls the task ID from a tasks/send or SendMessage response.
func extractTaskID(body map[string]interface{}) string {
	result, _ := body["result"].(map[string]interface{})
	if result == nil {
		return ""
	}
	// A2A v1.0 wraps in task object
	if task, ok := result["task"].(map[string]interface{}); ok {
		if id, ok := task["id"].(string); ok {
			return id
		}
	}
	if id, ok := result["id"].(string); ok {
		return id
	}
	return ""
}
