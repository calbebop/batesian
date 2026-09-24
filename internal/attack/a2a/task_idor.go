package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

// TaskIDORExecutor checks whether anonymous callers can read or list a task
// created by an authenticated owner.
type TaskIDORExecutor struct {
	rule attack.RuleContext
}

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
	// Keep the anonymous client's state separate from the owner's.
	anonVars := attack.NewVars(target, opts.OOBListenerURL)
	unauthClient := attack.NewUnauthHTTPClient(opts, anonVars)

	type createProbe struct {
		response     *attack.Response
		acceptedWire int
		deniedWire   [2]bool
	}
	// Try v1.0, then v0.3. Keep the per-wire auth result for the owner check.
	sendCreate := func(c *attack.HTTPClient, randID string) createProbe {
		var probe createProbe
		v1Headers := map[string]string{"A2A-Version": "1.0"}
		resp, err := c.POST(ctx, endpoint, v1Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-create-" + randID,
			"method":  "SendMessage",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      1, // USER
					"parts":     []interface{}{map[string]string{"text": "batesian idor probe " + randID}},
					"messageId": "batesian-" + randID,
				},
			},
		})
		probe.response = resp
		if err == nil && resp.IsAccepted() {
			probe.acceptedWire = 1
			return probe
		}
		probe.deniedWire[0] = resp != nil && isA2AAuthRejection(resp)
		resp, err = c.POST(ctx, endpoint, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-create-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian idor probe " + randID}},
					"messageId": "batesian-" + randID,
				},
			},
		})
		probe.response = resp
		if err == nil && resp.IsAccepted() {
			probe.acceptedWire = 2
			return probe
		}
		probe.deniedWire[1] = resp != nil && isA2AAuthRejection(resp)
		return probe
	}

	// Create an owner task to compare against anonymous responses.
	owner := sendCreate(authedClient, vars.RandID)
	if owner.acceptedWire == 0 {
		list := e.probeTaskList(ctx, unauthClient, authedClient, vars, "", "", false)
		if list.unverified {
			return nil, fmt.Errorf("%w: an anonymous task list answered, but no authenticated owner task was created to establish disclosure", attack.ErrInconclusive)
		}
		if !ok && !list.reached {
			return nil, attack.ErrInconclusive
		}
		return nil, classifyTaskSetup("creating a probe task as the owner", endpoint,
			authedClient.PresentsCredential(endpoint), owner.response).err()
	}
	taskID, contextID := extractTaskContext(owner.response.Body)
	if taskID == "" {
		list := e.probeTaskList(ctx, unauthClient, authedClient, vars, "", "", false)
		if list.unverified {
			return nil, fmt.Errorf("%w: an anonymous task list answered, but no authenticated owner task ID was returned to establish disclosure", attack.ErrInconclusive)
		}
		if !ok && !list.reached {
			return nil, attack.ErrInconclusive
		}
		return nil, classifyTaskSetup("creating a probe task as the owner", endpoint,
			authedClient.PresentsCredential(endpoint), owner.response).err()
	}

	// Prove that the owner task's create method rejects anonymous callers.
	anon := sendCreate(unauthClient, anonVars.RandID)
	ownerProtected := authedClient.PresentsCredential(endpoint) && anon.acceptedWire == 0 &&
		anon.deniedWire[owner.acceptedWire-1]
	anonTaskID := ""
	if anon.acceptedWire != 0 {
		anonTaskID, _ = extractTaskContext(anon.response.Body)
	}

	// Try both task-read method names.
	getParams := map[string]interface{}{"id": taskID, "historyLength": 10}
	getResp, err := unauthClient.POST(ctx, endpoint, map[string]string{"A2A-Version": "1.0"}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-get-" + vars.RandID,
		"method":  "GetTask",
		"params":  getParams,
	})
	if err != nil || !getResp.IsAccepted() {
		getResp, err = unauthClient.POST(ctx, endpoint, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-get-" + vars.RandID,
			"method":  "tasks/get",
			"params":  getParams,
		})
	}
	// Match task identifiers in the result, not arbitrary response text.
	unauthReadSucceeded := err == nil && getResp.IsAccepted() &&
		resultReferencesTask(getResp.Body, taskID, contextID)

	if ownerProtected && unauthReadSucceeded {
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

	list := e.probeTaskList(ctx, unauthClient, authedClient, vars, taskID, anonTaskID, ownerProtected)
	findings = append(findings, list.findings...)
	if len(findings) == 0 && list.unverified {
		return nil, fmt.Errorf("%w: an anonymous task list answered, but ownership of the listed tasks could not be established", attack.ErrInconclusive)
	}
	return findings, nil
}

type taskListProbe struct {
	findings   []attack.Finding
	reached    bool
	unverified bool
}

// probeTaskList compares an anonymous REST listing with the owner task ID.
func (e *TaskIDORExecutor) probeTaskList(ctx context.Context, unauthClient, cardClient *attack.HTTPClient,
	vars attack.Vars, ownerTaskID, anonTaskID string, ownerProtected bool) taskListProbe {
	// Resolve the advertised REST base with owner credentials; list anonymously.
	bases := []string{}
	if restBase := resolveHTTPJSONBase(ctx, cardClient, vars.BaseURL); restBase != "" {
		bases = append(bases, restBase)
	}
	if len(bases) == 0 || bases[0] != vars.BaseURL {
		bases = append(bases, vars.BaseURL)
	}
	var listEndpoints []string
	for _, b := range bases {
		listEndpoints = append(listEndpoints, endpoint.AppendPath(b, "/v1/tasks"), endpoint.AppendPath(b, "/tasks"))
	}
	var probe taskListProbe
	for _, le := range listEndpoints {
		listResp, err := unauthClient.GET(ctx, le, nil)
		if err == nil && listResp.StatusCode != 404 {
			probe.reached = true
		}
		if err == nil && listResp.IsSuccess() {
			ids := listedTaskIDs(listResp.Body)
			if len(ids) == 0 && countListedTasks(listResp.Body) > 0 {
				probe.unverified = true
			}
			if !containsTaskID(ids, ownerTaskID) {
				for _, id := range ids {
					if id != anonTaskID {
						probe.unverified = true
					}
				}
				continue
			}
			if !ownerProtected {
				probe.unverified = true
				continue
			}
			probe.findings = []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      "A2A task list exposes an authenticated owner's task to an anonymous caller",
				Description: fmt.Sprintf(
					"GET %s returned task %q, created with the owner's credential, to an anonymous caller. The server rejected anonymous task creation but did not scope the task list to the caller.", le, ownerTaskID),
				Evidence: fmt.Sprintf("HTTP %d from %s\nowner task: %s\nanonymous list: %s",
					listResp.StatusCode, le, ownerTaskID, snippet(listResp.Body, 400)),
				Remediation: e.rule.Remediation,
				TargetURL:   le,
			}}
			return probe
		}
	}
	return probe
}
