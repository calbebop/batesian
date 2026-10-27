package mcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskAccessExecutor probes authorization on the modern Tasks extension.
type TaskAccessExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-task-access", func(rc attack.RuleContext) attack.Executor {
		return &TaskAccessExecutor{rule: rc}
	})
}

func NewTaskAccessExecutor(rc attack.RuleContext) *TaskAccessExecutor {
	return &TaskAccessExecutor{rule: rc}
}

func (e *TaskAccessExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	a, b, err := taskPrincipals(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	var session mcpSession
	for _, ep := range modernDiscoveryEndpoints(vars.BaseURL, "") {
		probe := mcpSession{Endpoint: ep, Era: EraModern}
		resp, reqErr := taskAccessPost(ctx, client, probe, a, "batesian-task-discover", "server/discover", nil, nil)
		if reqErr != nil || resp == nil || !resp.IsSuccess() {
			continue
		}
		body, ok := parseResponseBody(resp.Body)
		if !ok || !matchesRPCStringID(body, "batesian-task-discover") || !validRPCResult(body) ||
			!modernWireAdvertised(resp.Body) {
			continue
		}
		session = probe
		session.RawInit = resp.Body
		break
	}
	if session.Endpoint == "" {
		return nil, fmt.Errorf("%w: principal %s could not discover a modern MCP wire at %s",
			attack.ErrInconclusive, a.name, vars.BaseURL)
	}
	if !session.ServerSupports("tools") || !teSupportsTasks(session) {
		return nil, nil
	}

	tool, pending, listed := taskAccessTool(ctx, client, session, a, opts.MCPInvokeTools)
	if !listed {
		return nil, fmt.Errorf("%w: principal %s did not receive a complete tools/list on the modern wire",
			attack.ErrInconclusive, a.name)
	}
	if tool.name == "" {
		if len(pending) == 0 {
			return nil, fmt.Errorf("%w: no annotated read-only tool is available for a disposable task",
				attack.ErrInconclusive)
		}
		sort.Strings(pending)
		return nil, fmt.Errorf("%w: approve an exact read-only tool with --mcp-invoke-tool: %s",
			attack.ErrInconclusive, strings.Join(pending, ", "))
	}

	firstID, err := taskAccessCreate(ctx, client, session, a, tool, vars.RandID+"-read", 40)
	if err != nil {
		return nil, fmt.Errorf("%w: principal %s did not receive a task handle from %q: %v",
			attack.ErrInconclusive, a.name, tool.name, err)
	}
	defer taskAccessAck(ctx, client, session, a, 60, "tasks/cancel", map[string]interface{}{"taskId": firstID})
	ownerTask, ownerVerdict := taskAccessGet(ctx, client, session, a, firstID, 41)
	if ownerVerdict != probeAnswered {
		return nil, fmt.Errorf("%w: principal %s could not read its new task", attack.ErrInconclusive, a.name)
	}

	var findings []attack.Finding
	var incomplete []error
	if _, control := taskAccessGet(ctx, client, session, b, "batesian-missing-"+vars.RandID, 42); control != probeRejected {
		incomplete = append(incomplete, fmt.Errorf("%w: tasks/get did not reject a nonexistent task, so a matching response cannot establish access",
			attack.ErrInconclusive))
	} else if _, verdict := taskAccessGet(ctx, client, session, b, firstID, 43); verdict == probeAnswered {
		findings = append(findings, e.finding(session.Endpoint, "tasks/get", a, b,
			"returned the scanner-created task to another principal", "The task state was disclosed."))
	} else if verdict == probeInconclusive {
		incomplete = append(incomplete, fmt.Errorf("%w: tasks/get as principal %s returned no verdict", attack.ErrInconclusive, b.name))
	}

	if key := safeTaskInputKey(ownerTask); key != "" {
		responses := map[string]interface{}{key: map[string]interface{}{"action": "decline"}}
		control := taskAccessAck(ctx, client, session, b, 44, "tasks/update", map[string]interface{}{
			"taskId": "batesian-missing-" + vars.RandID, "inputResponses": responses,
		})
		if control != probeRejected {
			incomplete = append(incomplete, fmt.Errorf("%w: tasks/update did not reject a nonexistent task, so an acknowledgement cannot establish access",
				attack.ErrInconclusive))
		} else {
			verdict := taskAccessAck(ctx, client, session, b, 45, "tasks/update", map[string]interface{}{
				"taskId": firstID, "inputResponses": responses,
			})
			switch verdict {
			case probeAnswered:
				findings = append(findings, e.finding(session.Endpoint, "tasks/update", a, b,
					"acknowledged a decline for the owner's outstanding elicitation", "The acknowledgement does not prove the task changed state."))
			case probeInconclusive:
				incomplete = append(incomplete, fmt.Errorf("%w: tasks/update as principal %s returned no verdict", attack.ErrInconclusive, b.name))
			}
		}
	} else {
		incomplete = append(incomplete, fmt.Errorf("%w: tasks/update was not tested because the owner's task had no pending form elicitation",
			attack.ErrInconclusive))
	}

	cancelID, createErr := taskAccessCreate(ctx, client, session, a, tool, vars.RandID+"-cancel", 50)
	if createErr != nil {
		incomplete = append(incomplete, fmt.Errorf("%w: no second disposable task was created for tasks/cancel: %v",
			attack.ErrInconclusive, createErr))
	} else if cancelID == firstID {
		incomplete = append(incomplete, fmt.Errorf("%w: the tool reused the first task handle, so tasks/cancel was not tested on a separate task",
			attack.ErrInconclusive))
	} else if state, verdict := taskAccessGet(ctx, client, session, a, cancelID, 51); verdict != probeAnswered ||
		(state.Status != "working" && state.Status != "input_required") {
		defer taskAccessAck(ctx, client, session, a, 61, "tasks/cancel", map[string]interface{}{"taskId": cancelID})
		incomplete = append(incomplete, fmt.Errorf("%w: the cancellation task was not observed active under its owner",
			attack.ErrInconclusive))
	} else {
		defer taskAccessAck(ctx, client, session, a, 61, "tasks/cancel", map[string]interface{}{"taskId": cancelID})
		control := taskAccessAck(ctx, client, session, b, 52, "tasks/cancel", map[string]interface{}{
			"taskId": "batesian-missing-" + vars.RandID,
		})
		if control != probeRejected {
			incomplete = append(incomplete, fmt.Errorf("%w: tasks/cancel did not reject a nonexistent task, so an acknowledgement cannot establish access",
				attack.ErrInconclusive))
		} else {
			verdict := taskAccessAck(ctx, client, session, b, 53, "tasks/cancel", map[string]interface{}{"taskId": cancelID})
			switch verdict {
			case probeAnswered:
				findings = append(findings, e.finding(session.Endpoint, "tasks/cancel", a, b,
					"acknowledged cancellation intent for the owner's active task", "Cancellation is cooperative; the acknowledgement does not prove the task stopped."))
			case probeInconclusive:
				incomplete = append(incomplete, fmt.Errorf("%w: tasks/cancel as principal %s returned no verdict", attack.ErrInconclusive, b.name))
			}
		}
	}

	return findings, errors.Join(incomplete...)
}

func taskAccessPost(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal,
	id interface{}, method string, params, schema map[string]interface{}) (*attack.Response, error) {
	var headers map[string]string
	var body map[string]interface{}
	if method == "tools/call" {
		var err error
		headers, body, err = s.toolRequest(id, params, schema)
		if err != nil {
			return nil, err
		}
	} else {
		headers, body = s.request(id, method, params)
	}
	meta := body["params"].(map[string]interface{})["_meta"].(map[string]interface{})
	caps := meta[metaClientCapabilities].(map[string]interface{})
	caps["extensions"] = map[string]interface{}{tasksExtensionName: map[string]interface{}{}}
	principalHeaders := map[string]string{}
	attachPrincipal(principalHeaders, p)
	for name, value := range headers {
		principalHeaders[name] = value
	}
	return client.POST(ctx, s.Endpoint, principalHeaders, body)
}

func taskAccessTool(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal,
	approved []string) (teSafeTool, []string, bool) {
	var pending []string
	seen := map[string]bool{}
	var params map[string]interface{}
	for page := 0; page < toolListPageCap; page++ {
		id := 20 + page
		resp, err := taskAccessPost(ctx, client, s, p, id, "tools/list", params, nil)
		verdict, body := classifyProbe(resp, err, id)
		if verdict != probeAnswered || !validRPCResult(body) {
			return teSafeTool{}, nil, false
		}
		result, ok := body["result"].(map[string]interface{})
		if !ok || result["resultType"] != "complete" {
			return teSafeTool{}, nil, false
		}
		tools, ok := result["tools"].([]interface{})
		if !ok {
			return teSafeTool{}, nil, false
		}
		for _, raw := range tools {
			tool, ok := raw.(map[string]interface{})
			if !ok {
				return teSafeTool{}, nil, false
			}
			name, _ := tool["name"].(string)
			annotations, _ := tool["annotations"].(map[string]interface{})
			readOnly, _ := annotations["readOnlyHint"].(bool)
			destructive, _ := annotations["destructiveHint"].(bool)
			if name == "" || !readOnly || destructive {
				continue
			}
			schema, _ := tool["inputSchema"].(map[string]interface{})
			if approvedToolName(name, approved) {
				return teSafeTool{name: name, schema: schema}, nil, true
			}
			pending = append(pending, name)
		}
		cursor, hasNext := result["nextCursor"]
		if !hasNext {
			return teSafeTool{}, pending, true
		}
		next, ok := cursor.(string)
		if !ok || next == "" || seen[next] {
			return teSafeTool{}, nil, false
		}
		seen[next] = true
		params = map[string]interface{}{"cursor": next}
	}
	return teSafeTool{}, nil, false
}

func taskAccessCreate(ctx context.Context, client *attack.HTTPClient, s mcpSession, owner taskPrincipal,
	tool teSafeTool, marker string, id int) (string, error) {
	resp, err := taskAccessPost(ctx, client, s, owner, id, "tools/call", map[string]interface{}{
		"name": tool.name, "arguments": synthesizeArgs(tool.schema, marker),
	}, tool.schema)
	if verdict, _ := classifyProbe(resp, err, id); verdict != probeAnswered || resp == nil || teTaskID(resp.Body, id) == "" {
		return "", fmt.Errorf("tools/call returned no correlated task result")
	}
	return teTaskID(resp.Body, id), nil
}

type taskAccessState struct {
	Status        string
	InputRequests map[string]interface{}
}

func taskAccessGet(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal,
	taskID string, id int) (taskAccessState, probeVerdict) {
	resp, err := taskAccessPost(ctx, client, s, p, id, "tasks/get", map[string]interface{}{"taskId": taskID}, nil)
	verdict, body := classifyTaskRead(resp, err, id, true)
	if verdict != probeAnswered || !validRPCResult(body) {
		return taskAccessState{}, verdict
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" || result["taskId"] != taskID {
		return taskAccessState{}, probeInconclusive
	}
	status, _ := result["status"].(string)
	switch status {
	case "working", "input_required", "completed", "cancelled", "failed":
	default:
		return taskAccessState{}, probeInconclusive
	}
	requests, _ := result["inputRequests"].(map[string]interface{})
	if status == "input_required" && requests == nil {
		return taskAccessState{}, probeInconclusive
	}
	if status == "completed" {
		if _, ok := result["result"].(map[string]interface{}); !ok {
			return taskAccessState{}, probeInconclusive
		}
	}
	if status == "failed" {
		if _, ok := result["error"].(map[string]interface{}); !ok {
			return taskAccessState{}, probeInconclusive
		}
	}
	return taskAccessState{Status: status, InputRequests: requests}, probeAnswered
}

func safeTaskInputKey(state taskAccessState) string {
	if state.Status != "input_required" {
		return ""
	}
	keys := make([]string, 0, len(state.InputRequests))
	for key, raw := range state.InputRequests {
		request, ok := raw.(map[string]interface{})
		if !ok || request["method"] != "elicitation/create" {
			continue
		}
		params, _ := request["params"].(map[string]interface{})
		if params["mode"] == "form" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func taskAccessAck(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal,
	id int, method string, params map[string]interface{}) probeVerdict {
	resp, err := taskAccessPost(ctx, client, s, p, id, method, params, nil)
	verdict, body := classifyTaskRead(resp, err, id, true)
	if verdict != probeAnswered || !validRPCResult(body) {
		return verdict
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return probeInconclusive
	}
	return probeAnswered
}

func (e *TaskAccessExecutor) finding(endpoint, method string, owner, caller taskPrincipal,
	observation, limit string) attack.Finding {
	operation := map[string]string{
		"tasks/get": attack.MCPTasksGet, "tasks/update": attack.MCPTasksUpdate, "tasks/cancel": attack.MCPTasksCancel,
	}[method]
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.RiskIndicator,
		Title: "MCP " + method + " accepted across principals",
		Description: fmt.Sprintf("A task created by %s was accessible through %s as %s. A known task ID may be shared by policy; declare an expected denial to confirm a violation. %s",
			owner.name, method, caller.name, limit),
		Evidence: fmt.Sprintf("endpoint: %s\nwire: MCP %s\nowner: %s\ncaller: %s\n%s: %s",
			endpoint, modernEraVersion, owner.name, caller.name, method, observation),
		Remediation: e.rule.Remediation, TargetURL: endpoint,
		Access: &attack.AccessObservation{Operation: operation, Caller: caller.name, CallerTenant: caller.tenant,
			Owner: owner.name, OwnerTenant: owner.tenant},
	}
}
