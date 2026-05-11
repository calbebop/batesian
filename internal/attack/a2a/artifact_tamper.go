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
type ArtifactTamperExecutor struct {
	rule attack.RuleContext
}

// NewArtifactTamperExecutor creates an executor for a2a-artifact-tamper.
func NewArtifactTamperExecutor(r attack.RuleContext) *ArtifactTamperExecutor {
	return &ArtifactTamperExecutor{rule: r}
}

func (e *ArtifactTamperExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoint := vars.BaseURL + "/"
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

	var findings []attack.Finding

	// A 200 response to the re-submission means the server accepted the overwrite.
	if tamperResp.IsSuccess() {
		tamperBody := tamperResp.BodyString()
		// Check if tampered text is echoed back in the response.
		if strings.Contains(tamperBody, tamperedText) {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"A2A task %q content overwritten — tampered text echoed in tasks/send response",
					assignedID),
				Description: fmt.Sprintf(
					"Re-submitting tasks/send with task ID %q and different message content succeeded. "+
						"The server returned HTTP %d and echoed the tampered content %q in the response, "+
						"confirming that task inputs are mutable after initial submission. "+
						"This enables poisoning of task history that downstream agents may read and trust.",
					assignedID, tamperResp.StatusCode, tamperedText),
				Evidence: fmt.Sprintf(
					"Task ID: %q\nOriginal text: %q\nTampered text: %q\nRe-submit HTTP %d\nResponse snippet: %.300s",
					assignedID, originalText, tamperedText, tamperResp.StatusCode, tamperBody),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
			return findings, nil
		}

		// Re-submission accepted (200) but no echo — check tasks/get to confirm.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.RiskIndicator,
			Title: fmt.Sprintf(
				"A2A tasks/send accepted re-submission for existing task ID %q", assignedID),
			Description: fmt.Sprintf(
				"Re-submitting tasks/send with task ID %q returned HTTP %d (success). "+
					"The server did not reject the duplicate task ID. "+
					"Tasks with the same ID should be immutable after creation. "+
					"Call tasks/get to verify whether the content was overwritten.",
				assignedID, tamperResp.StatusCode),
			Evidence: fmt.Sprintf(
				"Task ID: %q\nRe-submit HTTP %d\nResponse: %.300s",
				assignedID, tamperResp.StatusCode, tamperResp.BodyString()),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}

	// Step 3: call tasks/get to confirm whether stored content was overwritten.
	getResp, err := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tasks/get",
		"params":  map[string]interface{}{"id": assignedID},
	})
	if err != nil || !getResp.IsSuccess() {
		return findings, nil
	}

	getBody := getResp.BodyString()
	hasTampered := strings.Contains(getBody, tamperedText)
	hasOriginal := strings.Contains(getBody, originalText)

	if hasTampered && !hasOriginal {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A task %q content fully overwritten — tasks/get returns tampered content only",
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
		})
	} else if hasTampered && hasOriginal {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A task %q has both original and tampered content — partial artifact injection",
				assignedID),
			Description: fmt.Sprintf(
				"tasks/get for task ID %q contains both the original content %q and the tampered "+
					"content %q. The re-submission appended to the task history rather than replacing it. "+
					"Both inputs were accepted by the server, indicating lack of immutability enforcement.",
				assignedID, originalText, tamperedText),
			Evidence: fmt.Sprintf(
				"Task ID: %q\nBoth texts present in tasks/get response: %.300s",
				assignedID, getBody),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}

	return findings, nil
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
