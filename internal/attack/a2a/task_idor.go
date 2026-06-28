package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskIDORExecutor tests whether A2A task history is subject to broken
// object-level authorization (IDOR / BOLA, CWE-639) - rule a2a-task-idor-001.
//
// IDOR is specifically an authorization failure: a caller can read an object
// that belongs to a *different* principal. Detecting it requires distinguishing
// that failure from a server that simply has no authentication at all (which is
// a different, more obvious class and not what this rule claims). The executor
// therefore uses an auth-enforcement discriminator:
//
//  1. Create a task as the authenticated owner (client carries opts.Token).
//     No task id => not a responsive A2A server => skip.
//  2. Probe whether creation requires auth: send the same request with NO
//     credentials. If anonymous creation SUCCEEDS, the server enforces no auth
//     at all - that is not IDOR, so the ownership finding is suppressed.
//  3. Read the owner's task from an unauthenticated connection. Report IDOR only
//     when creation WAS auth-gated (step 2 was rejected) yet the unauthenticated
//     read still returns the task. That precisely demonstrates that the server
//     authenticates creation but does not bind task lookup to the owner.
//  4. Independently probe tasks/list (some bindings expose GET /v1/tasks) for
//     unauthenticated server-wide task disclosure.
type TaskIDORExecutor struct {
	rule attack.RuleContext
}

// NewTaskIDORExecutor creates an executor for the a2a-task-idor attack type.
func init() {
	attack.Register("a2a-task-idor", func(rc attack.RuleContext) attack.Executor { return NewTaskIDORExecutor(rc) })
}

func NewTaskIDORExecutor(r attack.RuleContext) *TaskIDORExecutor {
	return &TaskIDORExecutor{rule: r}
}

func (e *TaskIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	var findings []attack.Finding

	authedClient := attack.NewHTTPClient(opts, vars)
	// A separate Vars instance keeps the unauthenticated caller's RandID distinct,
	// reinforcing that it is a different connection with no shared session state.
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	// sendCreate issues a SendMessage create request, trying the A2A v1.0 shape
	// (PascalCase method, A2A-Version header, integer role) first and falling
	// back to the v0.3 slash-method shape for older deployments. It reports
	// whether the request was accepted (a task result was returned).
	sendCreate := func(c *attack.HTTPClient) (resp *attack.Response, accepted bool) {
		v1Headers := map[string]string{"A2A-Version": "1.0"}
		resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
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
		if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
			resp, err = c.POST(ctx, endpoint, nil, map[string]interface{}{
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
		if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
			return resp, false
		}
		return resp, true
	}

	// Step 1: Create a probe task as the authenticated owner.
	ownerResp, accepted := sendCreate(authedClient)
	if !accepted {
		// Not a responsive A2A server, or our credentials were rejected: there
		// is no owner-created task to test ownership against.
		f, restReached := e.probeTaskList(ctx, unauthClient, vars)
		if len(f) > 0 {
			return f, nil
		}
		// JSON-RPC creation did not succeed and the REST task-list probe reached
		// nothing: the rule could not be exercised against a testable endpoint.
		if !ok && !restReached {
			return nil, attack.ErrInconclusive
		}
		return nil, nil
	}
	taskID, contextID := extractTaskContext(ownerResp.Body)
	if taskID == "" {
		f, restReached := e.probeTaskList(ctx, unauthClient, vars)
		if len(f) > 0 {
			return f, nil
		}
		// JSON-RPC creation did not succeed and the REST task-list probe reached
		// nothing: the rule could not be exercised against a testable endpoint.
		if !ok && !restReached {
			return nil, attack.ErrInconclusive
		}
		return nil, nil
	}

	// Step 2: Auth-enforcement discriminator. Attempt the same creation with no
	// credentials. If anonymous creation SUCCEEDS, the server enforces no auth at
	// all - reading a task back without credentials is then expected behaviour,
	// not a broken-authorization (IDOR) finding. Suppress the ownership finding.
	_, anonAccepted := sendCreate(unauthClient)
	authEnforcedOnCreate := !anonAccepted

	// Step 3: Read the owner's task from an unauthenticated connection, trying the
	// v1.0 GetTask shape first and falling back to the v0.3 tasks/get shape so the
	// read works against either protocol version (mirrors sendCreate above).
	getParams := map[string]interface{}{"id": taskID, "historyLength": 10}
	getResp, err := unauthClient.POST(ctx, endpoint, map[string]string{"A2A-Version": "1.0"}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-get-" + vars.RandID,
		"method":  "GetTask",
		"params":  getParams,
	})
	if err != nil || !getResp.IsSuccess() || isJSONRPCError(getResp.Body) {
		getResp, err = unauthClient.POST(ctx, endpoint, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-get-" + vars.RandID,
			"method":  "tasks/get",
			"params":  getParams,
		})
	}
	unauthReadSucceeded := err == nil && getResp.IsSuccess() && !isJSONRPCError(getResp.Body) &&
		getResp.ContainsAny(`"history"`, `"contextId"`, taskID, contextID)

	if authEnforcedOnCreate && unauthReadSucceeded {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A task readable without owner credentials despite auth-gated creation (IDOR)",
			Description: fmt.Sprintf(
				"The server rejected unauthenticated task creation but returned task %s "+
					"(contextId %s), including its history, to a tasks/get request that presented "+
					"no credentials. Task lookup is not bound to the owning session, so any caller "+
					"who learns a task UUID can read another principal's full conversation history, "+
					"including LLM responses, tool outputs, and embedded system context.", taskID, contextID),
			Evidence:    fmt.Sprintf("taskId: %s\ncontextId: %s\nunauthenticated create: rejected\nunauthenticated tasks/get: HTTP %d\n%s", taskID, contextID, getResp.StatusCode, snippet(getResp.Body, 500)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}

	listFindings, _ := e.probeTaskList(ctx, unauthClient, vars)
	findings = append(findings, listFindings...)
	return findings, nil
}

// probeTaskList probes tasks/list - some implementations expose this as
// GET /v1/tasks or /tasks. An unauthenticated response that lists tasks
// discloses every session's task IDs (and often history) server-wide, which is
// the strongest form of the same broken-authorization failure. It runs over the
// unauthenticated client and is independent of the per-task IDOR check above.
func (e *TaskIDORExecutor) probeTaskList(ctx context.Context, unauthClient *attack.HTTPClient, vars attack.Vars) ([]attack.Finding, bool) {
	listEndpoints := []string{
		vars.BaseURL + "/v1/tasks",
		vars.BaseURL + "/tasks",
	}
	reached := false
	for _, le := range listEndpoints {
		listResp, err := unauthClient.GET(ctx, le, nil)
		if err == nil && listResp.StatusCode != 404 {
			reached = true
		}
		if err == nil && listResp.IsSuccess() && listResp.ContainsAny(`"tasks"`, `"contextId"`, `"history"`) {
			return []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "critical",
				Confidence: attack.ConfirmedExploit,
				Title:      "A2A server exposes tasks/list without authentication - server-wide task disclosure",
				Description: fmt.Sprintf(
					"GET %s returned a list of tasks without authentication. This exposes all task "+
						"IDs, context IDs, and potentially conversation history for every session on "+
						"the server.", le),
				Evidence:    fmt.Sprintf("HTTP %d from %s\n%s", listResp.StatusCode, le, snippet(listResp.Body, 400)),
				Remediation: e.rule.Remediation,
				TargetURL:   le,
			}}, reached
		}
	}
	return nil, reached
}
