package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ArtifactTamperExecutor tests whether an A2A server allows a client to
// overwrite a task's content by re-submitting tasks/send with the same
// task ID but different message content (rule a2a-artifact-tamper-001).
//
// The only sound proof of tampering is a read-back: submit original content,
// re-submit the SAME task ID with tampered content, then call tasks/get and
// observe that the STORED content changed. The immediate echo of the tampered
// text in the re-submission response proves nothing - every well-behaved server
// echoes back the message it just processed, and the server may have silently
// created a separate task or ignored the duplicate ID. Therefore:
//   - ConfirmedExploit is reported ONLY when tasks/get shows the tampered text
//     (full overwrite, or both texts = appended artifact injection).
//   - A re-submission that is accepted but cannot be verified via tasks/get is a
//     RiskIndicator, not a confirmed exploit.
//   - A re-submission rejected by status code OR a JSON-RPC error envelope
//     ("task already exists") means immutability is enforced => no finding.
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

	endpoint, _ := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	// Use a stable, recognizable task ID so the test is reproducible.
	taskID := "batesian-tamper-" + vars.RandID

	originalText := "batesian-original-content-" + vars.RandID
	tamperedText := "batesian-TAMPERED-content-" + vars.RandID

	// Step 1: submit the task with original content.
	sendPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tasks/send",
		"params": map[string]interface{}{
			"id": taskID,
			"message": map[string]interface{}{
				"role":  "user",
				"parts": []interface{}{map[string]interface{}{"type": "text", "text": originalText}},
			},
		},
	}

	sendResp, err := client.POST(ctx, endpoint, a2aHeaders, sendPayload)
	if err != nil || !sendResp.IsSuccess() {
		// Try PascalCase (v0.3 compatibility)
		sendPayload["method"] = "SendMessage"
		sendPayload["params"] = map[string]interface{}{
			"message": map[string]interface{}{
				"role":  "user",
				"parts": []interface{}{map[string]interface{}{"type": "text", "text": originalText}},
			},
		}
		sendResp, err = client.POST(ctx, endpoint, nil, sendPayload)
		if err != nil || !sendResp.IsSuccess() {
			return nil, nil // not an A2A server
		}
	}

	// Extract the task ID that the server assigned (may differ from what we sent).
	var sendBody map[string]interface{}
	_ = json.Unmarshal(sendResp.Body, &sendBody)
	assignedID := extractTaskID(sendBody)
	if assignedID == "" {
		assignedID = taskID
	}

	// Step 2: re-submit with the SAME task ID but different (tampered) content.
	tamperPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tasks/send",
		"params": map[string]interface{}{
			"id": assignedID,
			"message": map[string]interface{}{
				"role":  "user",
				"parts": []interface{}{map[string]interface{}{"type": "text", "text": tamperedText}},
			},
		},
	}

	tamperResp, err := client.POST(ctx, endpoint, a2aHeaders, tamperPayload)
	if err != nil {
		return nil, nil
	}

	// A re-submission is "accepted" only on HTTP success WITHOUT a JSON-RPC error
	// envelope. A 4xx, or a 200 carrying {"error": {...}} such as "task already
	// exists", is a rejection => immutability enforced => no finding.
	tamperAccepted := tamperResp.IsSuccess() && !isJSONRPCError(tamperResp.Body)
	if !tamperAccepted {
		return nil, nil
	}

	// Step 3: the re-submission was accepted, but acceptance alone does not prove
	// the stored task changed - the server may have created a separate task or
	// idempotently ignored the duplicate ID. Read the task back to confirm.
	getResp, getErr := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tasks/get",
		"params":  map[string]interface{}{"id": assignedID},
	})

	// Could not read the task back: report the accepted re-submission as an
	// indicator (suspicious, but the overwrite is unproven).
	if getErr != nil || getResp == nil || !getResp.IsSuccess() || isJSONRPCError(getResp.Body) {
		return []attack.Finding{e.indicator(endpoint, assignedID, tamperResp.StatusCode, tamperResp.BodyString())}, nil
	}

	getBody := getResp.BodyString()
	hasTampered := strings.Contains(getBody, tamperedText)
	hasOriginal := strings.Contains(getBody, originalText)

	switch {
	case hasTampered && !hasOriginal:
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A task %q content fully overwritten - tasks/get returns tampered content only",
				assignedID),
			Description: fmt.Sprintf(
				"tasks/get for task ID %q returns tampered content %q and no trace of the original "+
					"content %q. The original task artifact was completely replaced. "+
					"Any downstream agent reading this task's history will process poisoned content.",
				assignedID, tamperedText, originalText),
			Evidence: fmt.Sprintf(
				"Task ID: %q\nOriginal text: %q (not found in tasks/get)\nTampered text: %q (found)\nResponse: %.300s",
				assignedID, originalText, tamperedText, getBody),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		}}, nil

	case hasTampered && hasOriginal:
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A task %q has both original and tampered content - partial artifact injection",
				assignedID),
			Description: fmt.Sprintf(
				"tasks/get for task ID %q contains both the original content %q and the tampered "+
					"content %q. The re-submission appended attacker-controlled content to the task "+
					"history rather than being rejected, indicating lack of immutability enforcement.",
				assignedID, originalText, tamperedText),
			Evidence: fmt.Sprintf(
				"Task ID: %q\nBoth texts present in tasks/get response: %.300s",
				assignedID, getBody),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		}}, nil

	case hasOriginal && !hasTampered:
		// The re-submission was accepted at the transport layer, but the stored
		// task still holds the ORIGINAL content. The server preserved the
		// artifact (separate task / idempotent no-op). Not a tampering bug.
		return nil, nil

	default:
		// tasks/get succeeded but echoes neither marker (server does not surface
		// message text), so the overwrite cannot be confirmed or refuted.
		return []attack.Finding{e.indicator(endpoint, assignedID, tamperResp.StatusCode, tamperResp.BodyString())}, nil
	}
}

// indicator builds the unproven-but-suspicious RiskIndicator finding used when a
// re-submission is accepted but the overwrite cannot be confirmed via tasks/get.
func (e *ArtifactTamperExecutor) indicator(endpoint, assignedID string, status int, body string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.RiskIndicator,
		Title: fmt.Sprintf(
			"A2A tasks/send accepted re-submission for existing task ID %q (overwrite unverified)", assignedID),
		Description: fmt.Sprintf(
			"Re-submitting tasks/send with task ID %q was accepted (HTTP %d) rather than rejected as a "+
				"duplicate, but tasks/get did not surface the stored content so the overwrite could not be "+
				"confirmed. Tasks should be immutable after creation; manually verify whether content changed.",
			assignedID, status),
		Evidence: fmt.Sprintf(
			"Task ID: %q\nRe-submit HTTP %d\nResponse: %.300s",
			assignedID, status, body),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
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
