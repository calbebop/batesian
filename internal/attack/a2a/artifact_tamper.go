package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ArtifactTamperExecutor tests whether an A2A server lets a client overwrite a
// task's stored content by re-submitting against the same task ID with different
// message content (rule a2a-artifact-tamper-001).
//
// The only sound proof is a read-back: submit original content, re-submit the SAME
// task ID with tampered content, then read the task and observe that the STORED
// content changed. The immediate echo of the tampered text proves nothing, since
// every well-behaved server echoes the message it just processed and may have
// created a separate task or ignored the duplicate ID.
//
// What counts as a finding is narrower than it looks, deliberately. REPLACEMENT is
// a finding: the read-back shows the tampered text and the original is gone, so the
// artifact was destroyed. APPENDING is not, because continuing a task by sending a
// message carrying its taskId is exactly what the v1.0 and v0.3 wires define, so an
// appended message is the protocol working. This probe uses a single principal and
// cannot distinguish a conformant continuation from an injection; reading another
// principal's task is a2a-task-idor-001 and a2a-multitenant-isolation-001 territory.
// Claiming ConfirmedExploit for an append would fire against every conformant agent
// that surfaces task history.
//
// Anything undeterminable is reported as not tested rather than as a clean pass or
// an unverified indicator: no task could be created, the task could not be read
// back, or the read-back surfaces neither marker.
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

	// Step 2: re-submit against the SAME task ID with different content, on the
	// wire that created it.
	tamperResp, err := client.POST(ctx, endpoint, wire.headers, wire.continuePayload(taskID, tamperedText, vars.RandID))
	if err != nil || !tamperResp.IsAccepted() {
		// Rejected on status or via a JSON-RPC error envelope ("task already
		// exists"): immutability enforced.
		return nil, nil
	}

	// Step 3: acceptance alone proves nothing. Read the task back.
	getBody, ok := readTaskHistory(ctx, client, endpoint, wire.headers, taskID, vars)
	if !ok {
		// The re-submission was accepted but the stored content is unknown, so
		// whether the artifact changed cannot be established either way.
		return nil, fmt.Errorf("%w: task %s was re-submitted and accepted, but reading it back "+
			"returned no task history, so whether the stored artifact changed could not be "+
			"established", attack.ErrInconclusive, taskID)
	}

	stored := string(getBody)
	hasTampered := strings.Contains(stored, tamperedText)
	hasOriginal := strings.Contains(stored, originalText)

	switch {
	case hasTampered && !hasOriginal:
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A task %q content fully overwritten - the stored task returns tampered content only",
				taskID),
			Description: fmt.Sprintf(
				"Reading task %q back returns tampered content %q and no trace of the original content "+
					"%q. The original task artifact was replaced rather than preserved. Any downstream "+
					"agent reading this task's history will process poisoned content.",
				taskID, tamperedText, originalText),
			Evidence: fmt.Sprintf(
				"Task ID: %q\nWire: %s\nOriginal text: %q (absent from the read-back)\n"+
					"Tampered text: %q (present)\nResponse: %.300s",
				taskID, wire.name, originalText, tamperedText, stored),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		}}, nil

	case hasOriginal:
		// The original survives. Whether the tampered message was appended or
		// dropped, the artifact was not destroyed, and an appended continuation is
		// conformant behaviour rather than a tampering bug.
		return nil, nil

	default:
		// Neither marker is visible, so the server does not surface message text and
		// the read-back can neither confirm nor refute an overwrite.
		return nil, fmt.Errorf("%w: task %s read back without either the original or the "+
			"tampered marker, so this agent does not surface message text and an overwrite can "+
			"be neither confirmed nor refuted", attack.ErrInconclusive, taskID)
	}
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
