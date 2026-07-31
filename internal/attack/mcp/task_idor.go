package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskIDORExecutor tests whether MCP tasks are bound to the authorization
// context that created them (rule mcp-task-idor-001).
//
// MCP 2025-11-25 added durable tasks: a task-augmented tools/call returns a
// taskId, and the caller later reads state with tasks/get and the underlying
// tool output with tasks/result. The spec is explicit that these are scoped:
// "receivers MUST reject tasks/get, tasks/result, and tasks/cancel requests for
// tasks that do not belong to the same authorization context as the requestor."
//
// Two failures are reported. Reading another context's task metadata discloses
// status, timing and status messages. Reading its result discloses the actual
// tool output, which is the payload the task existed to produce.
//
// SAFETY: creating a task requires invoking a real tool, which no other rule in
// this package does (mcp-tools-unauth-001 deliberately calls a non-existent tool
// so nothing executes). To bound that, the rule only invokes a task-capable tool
// whose annotations declare it read-only or explicitly non-destructive, and
// skips entirely when no such tool exists.
//
// Tasks are marked experimental in 2025-11-25, so this rule is version-scoped.
type TaskIDORExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-task-idor", func(rc attack.RuleContext) attack.Executor { return NewTaskIDORExecutor(rc) })
}

func NewTaskIDORExecutor(r attack.RuleContext) *TaskIDORExecutor {
	return &TaskIDORExecutor{rule: r}
}

// taskPollBudget bounds how long the rule waits for a task to reach a terminal
// status. tasks/result blocks until terminal by spec, so the rule polls
// tasks/get instead and only calls tasks/result once the task has finished.
const (
	taskPollBudget   = 12 * time.Second
	taskPollInterval = 750 * time.Millisecond
	taskPollMaxTries = 16
)

// safeTool is a task-capable tool the rule is willing to invoke.
type safeTool struct {
	name string
	args map[string]interface{}
}

func (e *TaskIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// One transport, with credentials attached per request, so each session can
	// present a different principal.
	client := attack.NewUnauthHTTPClient(opts, vars)

	tokenA, tokenB := opts.Token, opts.Token
	crossPrincipal := false
	if len(opts.Principals) >= 2 && opts.Principals[0].Token != opts.Principals[1].Token {
		tokenA, tokenB = opts.Principals[0].Token, opts.Principals[1].Token
		crossPrincipal = true
	}

	// Session A, which also discovers the endpoint.
	sessA, ok := e.initSession(ctx, client, vars.BaseURL, tokenA)
	if !ok {
		return nil, attack.ErrInconclusive // not an MCP server
	}

	// Gate on the tasks capability and on task-augmented tools/call specifically.
	if !sessA.ServerSupports("tasks") || !tasksSupportsToolCall(sessA.RawInit) {
		return nil, nil
	}

	// Gate on finding a tool this rule is willing to invoke.
	tool, ok := e.findSafeTaskTool(ctx, client, sessA, tokenA, vars.RandID)
	if !ok {
		return nil, nil
	}

	// Step 1: create a task as principal A.
	taskID := e.createTask(ctx, client, sessA, tokenA, tool)
	if taskID == "" {
		return nil, nil
	}

	// Step 2: discriminator. If an anonymous caller can create a task too, the
	// server enforces no authentication at all, which is a different (and more
	// obvious) failure owned by mcp-tools-unauth-001. Do not call that an IDOR.
	if anonSess, anonOK := e.initSession(ctx, client, vars.BaseURL, ""); anonOK {
		if e.createTask(ctx, client, anonSess, "", tool) != "" {
			return nil, nil
		}
	}

	// Step 3: a second session, as principal B, tries to read A's task.
	sessB, ok := e.initSession(ctx, client, vars.BaseURL, tokenB)
	if !ok || sessB.SessionID == sessA.SessionID {
		return nil, nil // need a distinct session to demonstrate the boundary
	}

	var findings []attack.Finding

	// Step 4: can B read A's task by id? A correctly-scoped server answers -32602.
	if meta, ok := e.getTask(ctx, client, sessB, tokenB, taskID); ok {
		findings = append(findings, e.metadataFinding(sessA.Endpoint, taskID, meta, crossPrincipal))

		// Escalate if B can also read the result. tasks/result blocks until the
		// task is terminal, so poll tasks/get first and stay inside the budget.
		if e.pollTerminal(ctx, client, sessB, tokenB, taskID) {
			if content, ok := e.getResult(ctx, client, sessB, tokenB, taskID); ok {
				findings = append(findings, e.resultFinding(sessA.Endpoint, taskID, tool.name, content, crossPrincipal))
			}
		}
	}

	// Step 5: can B enumerate A's task without knowing its id? This is checked
	// independently of step 4: the spec requires anything gettable to also be
	// listable, but not the converse, so a server can scope tasks/get and still
	// leak the list. Enumeration is the stronger failure because it needs no
	// prior knowledge of the task id at all.
	if tasksSupportsList(sessA.RawInit) {
		if ids, ok := e.listTasks(ctx, client, sessB, tokenB); ok && containsTaskID(ids, taskID) {
			findings = append(findings, e.enumerationFinding(sessA.Endpoint, taskID, len(ids), crossPrincipal))
		}
	}

	return findings, nil
}

// initSession performs an initialize handshake as the given token, discovering
// the endpoint across the candidate paths, and returns the resulting session.
func (e *TaskIDORExecutor) initSession(ctx context.Context, client *attack.HTTPClient, baseURL, token string) (mcpSession, bool) {
	for _, ep := range endpointCandidates(baseURL) {
		headers := map[string]string{}
		if token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-11-25",
				// Declaring the tasks client capability keeps the handshake
				// honest: this client really does poll and cancel tasks.
				"capabilities": map[string]interface{}{
					"tasks": map[string]interface{}{"list": map[string]interface{}{}, "cancel": map[string]interface{}{}},
				},
				"clientInfo": map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil || !resp.IsSuccess() {
			continue
		}
		if !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			continue
		}
		session := mcpSession{
			Endpoint:        ep,
			SessionID:       resp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(resp.Body),
			RawInit:         resp.Body,
		}
		_, _ = client.POST(ctx, ep, e.headers(session, token), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})
		return session, true
	}
	return mcpSession{}, false
}

// headers builds the per-request headers for a session and principal.
func (e *TaskIDORExecutor) headers(s mcpSession, token string) map[string]string {
	h := map[string]string{}
	if s.ProtocolVersion != "" {
		h["Mcp-Protocol-Version"] = s.ProtocolVersion
	}
	if s.SessionID != "" {
		h["Mcp-Session-Id"] = s.SessionID
	}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return h
}

// tasksSupportsToolCall reports whether the handshake declared
// capabilities.tasks.requests.tools.call, which is what permits augmenting a
// tools/call with a task.
func tasksSupportsToolCall(rawInit []byte) bool {
	var body struct {
		Result struct {
			Capabilities struct {
				Tasks struct {
					Requests struct {
						Tools map[string]json.RawMessage `json:"tools"`
					} `json:"requests"`
				} `json:"tasks"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rawInit, &body); err != nil {
		return false
	}
	_, ok := body.Result.Capabilities.Tasks.Requests.Tools["call"]
	return ok
}

// tasksSupportsList reports whether the handshake declared capabilities.tasks.list,
// which is what permits tasks/list at all. The spec tells receivers that cannot
// identify requestors not to declare it, precisely because listing exposes task
// metadata regardless of how much entropy the task ids carry.
func tasksSupportsList(rawInit []byte) bool {
	var body struct {
		Result struct {
			Capabilities struct {
				Tasks map[string]json.RawMessage `json:"tasks"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rawInit, &body); err != nil {
		return false
	}
	_, ok := body.Result.Capabilities.Tasks["list"]
	return ok
}

// listTasks enumerates the tasks visible to the given principal, returning the
// task ids from the first page. ok is false when the server refuses the call.
func (e *TaskIDORExecutor) listTasks(ctx context.Context, client *attack.HTTPClient, s mcpSession, token string) ([]string, bool) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, token), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  "tasks/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return nil, false
	}
	var body struct {
		Result *struct {
			Tasks []struct {
				TaskID string `json:"taskId"`
			} `json:"tasks"`
		} `json:"result"`
		Error map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, false
	}
	if body.Error != nil || body.Result == nil {
		return nil, false
	}
	ids := make([]string, 0, len(body.Result.Tasks))
	for _, t := range body.Result.Tasks {
		if t.TaskID != "" {
			ids = append(ids, t.TaskID)
		}
	}
	return ids, true
}

// containsTaskID reports whether the enumerated list includes the target task.
func containsTaskID(ids []string, taskID string) bool {
	for _, id := range ids {
		if id == taskID {
			return true
		}
	}
	return false
}

// findSafeTaskTool picks a task-capable tool the rule is willing to invoke, and
// synthesizes arguments for it from its input schema.
//
// Task creation is the one place this package executes real server-side
// functionality, so the tool must declare itself read-only or explicitly
// non-destructive. A tool with no annotations is not invoked: MCP treats
// destructiveHint as true by default when a tool is not read-only.
func (e *TaskIDORExecutor) findSafeTaskTool(ctx context.Context, client *attack.HTTPClient, s mcpSession, token, randID string) (safeTool, bool) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, token), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return safeTool{}, false
	}
	var body struct {
		Result struct {
			Tools []struct {
				Name      string `json:"name"`
				Execution struct {
					TaskSupport string `json:"taskSupport"`
				} `json:"execution"`
				Annotations *struct {
					ReadOnlyHint    *bool `json:"readOnlyHint"`
					DestructiveHint *bool `json:"destructiveHint"`
				} `json:"annotations"`
				InputSchema map[string]interface{} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return safeTool{}, false
	}
	for _, t := range body.Result.Tools {
		if t.Execution.TaskSupport != "optional" && t.Execution.TaskSupport != "required" {
			continue
		}
		if t.Annotations == nil {
			continue // unannotated: assume it may be destructive
		}
		readOnly := t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
		nonDestructive := t.Annotations.DestructiveHint != nil && !*t.Annotations.DestructiveHint
		if !readOnly && !nonDestructive {
			continue
		}
		return safeTool{name: t.Name, args: synthesizeArgs(t.InputSchema, randID)}, true
	}
	return safeTool{}, false
}

// synthesizeArgs builds a minimal argument object from a tool's JSON Schema,
// filling each declared property with an inert value of the right type.
func synthesizeArgs(schema map[string]interface{}, randID string) map[string]interface{} {
	args := map[string]interface{}{}
	props, _ := schema["properties"].(map[string]interface{})
	for name, raw := range props {
		spec, _ := raw.(map[string]interface{})
		switch spec["type"] {
		case "string":
			args[name] = "batesian task probe " + randID
		case "number", "integer":
			args[name] = 1
		case "boolean":
			args[name] = false
		case "array":
			args[name] = []interface{}{}
		case "object":
			args[name] = map[string]interface{}{}
		}
	}
	return args
}

// createTask issues a task-augmented tools/call and returns the created task id,
// or empty when the request was refused.
func (e *TaskIDORExecutor) createTask(ctx context.Context, client *attack.HTTPClient, s mcpSession, token string, tool safeTool) string {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, token), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      tool.name,
			"arguments": tool.args,
			"task":      map[string]interface{}{"ttl": 60000},
		},
	})
	if err != nil || !resp.IsSuccess() {
		return ""
	}
	var body struct {
		Result struct {
			Task struct {
				TaskID string `json:"taskId"`
			} `json:"task"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return ""
	}
	return body.Result.Task.TaskID
}

// taskState is the subset of a Task object the rule reports on.
type taskState struct {
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage"`
	CreatedAt     string `json:"createdAt"`
}

// getTask reads a task as the given principal. ok is false when the server
// refuses (the correctly-scoped outcome, a -32602 per spec).
func (e *TaskIDORExecutor) getTask(ctx context.Context, client *attack.HTTPClient, s mcpSession, token, taskID string) (taskState, bool) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, token), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tasks/get",
		"params":  map[string]interface{}{"taskId": taskID},
	})
	if err != nil || !resp.IsSuccess() {
		return taskState{}, false
	}
	var body struct {
		Result *taskState             `json:"result"`
		Error  map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return taskState{}, false
	}
	if body.Error != nil || body.Result == nil || body.Result.Status == "" {
		return taskState{}, false
	}
	return *body.Result, true
}

// pollTerminal waits for the task to reach a terminal status, within budget.
// tasks/result blocks until terminal, so polling first keeps the scan bounded.
func (e *TaskIDORExecutor) pollTerminal(ctx context.Context, client *attack.HTTPClient, s mcpSession, token, taskID string) bool {
	deadline := time.Now().Add(taskPollBudget)
	for i := 0; i < taskPollMaxTries && time.Now().Before(deadline); i++ {
		st, ok := e.getTask(ctx, client, s, token, taskID)
		if !ok {
			return false
		}
		switch st.Status {
		case "completed", "failed", "cancelled":
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(taskPollInterval):
		}
	}
	return false
}

// getResult reads the underlying tool output for a terminal task, returning the
// raw result payload when the server disclosed it.
func (e *TaskIDORExecutor) getResult(ctx context.Context, client *attack.HTTPClient, s mcpSession, token, taskID string) (string, bool) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, token), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tasks/result",
		"params":  map[string]interface{}{"taskId": taskID},
	})
	if err != nil || !resp.IsSuccess() {
		return "", false
	}
	var body struct {
		Result json.RawMessage        `json:"result"`
		Error  map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return "", false
	}
	if body.Error != nil || len(body.Result) == 0 {
		return "", false
	}
	return string(body.Result), true
}

// requestorLabel describes what boundary was actually crossed, so the finding
// never claims a cross-principal read when only two sessions were available.
func requestorLabel(crossPrincipal bool) string {
	if crossPrincipal {
		return "a different authenticated principal"
	}
	return "a separate authenticated session"
}

func (e *TaskIDORExecutor) metadataFinding(endpoint, taskID string, st taskState, crossPrincipal bool) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP task readable by another authorization context (tasks/get IDOR)",
		Description: fmt.Sprintf(
			"tasks/get at %s returned task %s to %s that did not create it. The server rejected "+
				"anonymous task creation, so authentication is enforced, yet task lookup is not bound to "+
				"the creating context. The MCP spec requires receivers to reject tasks/get for tasks "+
				"outside the requestor's authorization context, so any caller who learns or guesses a "+
				"task id can track another context's work.", endpoint, taskID, requestorLabel(crossPrincipal)),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask: %s\nanonymous task creation: rejected (auth enforced)\n"+
				"cross-context tasks/get: accepted\ndisclosed status: %s\nstatusMessage: %s\ncreatedAt: %s",
			endpoint, taskID, st.Status, st.StatusMessage, st.CreatedAt),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskIDORExecutor) enumerationFinding(endpoint, taskID string, total int, crossPrincipal bool) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "critical",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP tasks/list enumerates another authorization context's tasks",
		Description: fmt.Sprintf(
			"tasks/list at %s returned task %s to %s that did not create it, in a list of %d task(s). "+
				"This is a stronger failure than reading a task by id: the caller needs no prior knowledge "+
				"of any task id, so every task on the server can be enumerated and then read. The MCP spec "+
				"requires receivers to return only tasks associated with the requestor's authorization "+
				"context, and to not advertise the tasks.list capability at all when requestors cannot be "+
				"identified.", endpoint, taskID, requestorLabel(crossPrincipal), total),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nanonymous task creation: rejected (auth enforced)\n"+
				"cross-context tasks/list: accepted\ntasks returned: %d\nincludes another context's task: %s",
			endpoint, total, taskID),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskIDORExecutor) resultFinding(endpoint, taskID, toolName, content string, crossPrincipal bool) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "critical",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP task result readable by another authorization context (tasks/result IDOR)",
		Description: fmt.Sprintf(
			"tasks/result at %s returned the completed output of task %s to %s that did not create it. "+
				"This is the actual result of the %q tool invocation, not task metadata, so whatever that "+
				"tool returned is disclosed across the authorization boundary. The MCP spec requires "+
				"receivers to reject tasks/result for tasks outside the requestor's authorization context.",
			endpoint, taskID, requestorLabel(crossPrincipal), toolName),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask: %s\ntool: %s\nanonymous task creation: rejected (auth enforced)\n"+
				"cross-context tasks/result: accepted\ndisclosed result: %s",
			endpoint, taskID, toolName, snippetMCP([]byte(content))),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
