package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/calbebop/batesian/internal/attack"
	endpointpkg "github.com/calbebop/batesian/internal/endpoint"
)

// TaskEnumerationExecutor checks whether ListTasks exposes one principal's task to
// another. This covers authenticated enumeration, unlike the anonymous REST probe.
type TaskEnumerationExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-task-enumeration", func(rc attack.RuleContext) attack.Executor {
		return NewTaskEnumerationExecutor(rc)
	})
}

func NewTaskEnumerationExecutor(r attack.RuleContext) *TaskEnumerationExecutor {
	return &TaskEnumerationExecutor{rule: r}
}

func (e *TaskEnumerationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	a, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))
	restBases := resolveHTTPJSONBases(ctx, clientA, vars.BaseURL)
	if !ok && len(restBases) == 0 {
		return nil, attack.ErrInconclusive
	}

	var incomplete error
	if ok {
		findings, err := e.probeJSONRPC(ctx, endpoint, vars.RandID, a, b, clientA, clientB, unauthClient)
		if len(findings) != 0 {
			return findings, nil
		}
		incomplete = err
	}
	for _, base := range restBases {
		baseTested := false
		for _, route := range []struct{ send, list, version string }{
			{"/message:send", "/tasks", "1.0"},
			{"/v1/message:send", "/v1/tasks", "0.3.0"},
		} {
			sendURL := endpointpkg.AppendPath(base, route.send)
			listURL := endpointpkg.AppendPath(base, route.list)
			findings, err, tested := e.probeREST(ctx, sendURL, listURL, route.version, vars.RandID,
				a, b, clientA, clientB, unauthClient)
			if len(findings) != 0 {
				return findings, nil
			}
			baseTested = baseTested || tested
			if incomplete == nil {
				incomplete = err
			}
		}
		if !baseTested && incomplete == nil {
			incomplete = fmt.Errorf("%w: advertised HTTP+JSON interface at %s did not create a task to test",
				attack.ErrInconclusive, base)
		}
	}
	return nil, incomplete
}

func (e *TaskEnumerationExecutor) probeJSONRPC(ctx context.Context, endpoint, randID string,
	a, b attack.Principal, clientA, clientB, unauthClient *attack.HTTPClient) ([]attack.Finding, error) {
	taskID, _, _, obs := e.createTask(ctx, clientA, endpoint, a, randID)
	if taskID == "" {
		return nil, obs.err()
	}
	list := func(c *attack.HTTPClient, headers map[string]string) ([]string, listOutcome) {
		return e.listTasks(ctx, c, endpoint, headers, randID, taskID)
	}
	return e.probeListing(endpoint, taskID, a, b, clientA, clientB, unauthClient, list)
}

func (e *TaskEnumerationExecutor) probeREST(ctx context.Context, sendURL, listURL, version, randID string,
	a, b attack.Principal, clientA, clientB, unauthClient *attack.HTTPClient) ([]attack.Finding, error, bool) {
	headers := restVersionHeaders(version, a.Headers)
	if version == "1.0" {
		headers["Content-Type"] = "application/a2a+json"
	}
	messageID := randID + "-" + version
	body := buildRESTSendRequest(messageID)
	if version != "1.0" {
		body = map[string]interface{}{"message": map[string]interface{}{
			"messageId": "batesian-" + messageID,
			"role":      "user",
			"parts":     []interface{}{map[string]string{"kind": "text", "text": "ping"}},
		}}
	}
	resp, err := clientA.POST(ctx, sendURL, headers, body)
	if err != nil || resp == nil {
		return nil, fmt.Errorf("%w: REST task creation at %s did not answer", attack.ErrInconclusive, sendURL), false
	}
	if resp.StatusCode == 404 {
		return nil, nil, false
	}
	taskID := ""
	if resp.IsSuccess() && resp.IsJSON() && !isJSONRPCError(resp.Body) {
		taskID = restTaskID(resp.Body)
	}
	if taskID == "" {
		return nil, classifyTaskSetup("creating a REST probe task as principal "+a.Name,
			sendURL, principalCredentialPresent(clientA, sendURL, a.Headers), resp).err(), false
	}
	list := func(c *attack.HTTPClient, principalHeaders map[string]string) ([]string, listOutcome) {
		return e.listRESTTasks(ctx, c, listURL, restVersionHeaders(version, principalHeaders), taskID)
	}
	findings, err := e.probeListing(listURL, taskID, a, b, clientA, clientB, unauthClient, list)
	return findings, err, true
}

func restVersionHeaders(version string, extra map[string]string) map[string]string {
	headers := map[string]string{}
	if version == "1.0" {
		headers["A2A-Version"] = version
	}
	for key, value := range extra {
		headers[key] = value
	}
	return headers
}

func (e *TaskEnumerationExecutor) probeListing(endpoint, taskID string, a, b attack.Principal,
	clientA, clientB, unauthClient *attack.HTTPClient,
	list func(*attack.HTTPClient, map[string]string) ([]string, listOutcome)) ([]attack.Finding, error) {

	ownList, ownOutcome := list(clientA, a.Headers)
	switch ownOutcome {
	case listAbsent:
		// No list method here. Nothing to scope, and nothing wrong: the same call the
		// OAuth-gated rules make for a server exposing no OAuth.
		return nil, nil
	case listRefused:
		return nil, fmt.Errorf("%w: ListTasks at %s was refused for the task's own owner (%s), "+
			"so whether the listing is scoped to the caller could not be established",
			attack.ErrInconclusive, endpoint, a.Name)
	case listIncomplete:
		return nil, fmt.Errorf("%w: ListTasks at %s could not complete the owner's listing",
			attack.ErrInconclusive, endpoint)
	}
	if !containsTaskID(ownList, taskID) {
		// The owner cannot see their own task, so this listing does not enumerate what
		// the rule assumes it enumerates and B seeing nothing would prove nothing.
		return nil, fmt.Errorf("%w: ListTasks at %s did not return principal %s's own task %s, "+
			"so the listing does not enumerate the tasks this rule compares against",
			attack.ErrInconclusive, endpoint, a.Name, taskID)
	}

	anonList, anonOutcome := list(unauthClient, nil)
	if anonOutcome == listIncomplete {
		return nil, fmt.Errorf("%w: anonymous ListTasks at %s could not complete its listing",
			attack.ErrInconclusive, endpoint)
	}
	if anonOutcome == listOK && containsTaskID(anonList, taskID) {
		return nil, nil
	}

	otherList, otherOutcome := list(clientB, b.Headers)
	if otherOutcome == listIncomplete {
		return nil, fmt.Errorf("%w: ListTasks at %s could not complete principal %s's listing",
			attack.ErrInconclusive, endpoint, b.Name)
	}
	if otherOutcome != listOK {
		// B cannot list at all, which is one legitimate way to scope the surface.
		return nil, nil
	}
	if !containsTaskID(otherList, taskID) {
		return nil, nil // scoped: B's listing does not include A's task
	}

	return []attack.Finding{e.finding(endpoint, a, b, taskID, otherList)}, nil
}

// listOutcome distinguishes complete, absent, refused, and incomplete listings.
type listOutcome int

const (
	listOK listOutcome = iota
	// listAbsent means the listing method or path is not implemented.
	listAbsent
	// listRefused is an explicit authorization refusal.
	listRefused
	// listIncomplete means a listing started but could not be exhausted.
	listIncomplete
)

const maxTaskListPages = 10

// listTasks walks bounded pages until the task is found or the list ends.
func (e *TaskEnumerationExecutor) listTasks(ctx context.Context, c *attack.HTTPClient, endpoint string,
	extraHeaders map[string]string, randID, wantedID string) ([]string, listOutcome) {
	attempts := []struct {
		method  string
		headers map[string]string
	}{
		{"ListTasks", withV1Version(extraHeaders)},
		// v0.3 defines no list method, so this only reaches an implementation that
		// chose the slash spelling anyway. It costs one request on a path that would
		// otherwise report the surface absent.
		{"tasks/list", extraHeaders},
	}

	absentEverywhere := true
	incompleteFirstPage := false
	for _, at := range attempts {
		next := ""
		seen := map[string]bool{}
		var ids []string
		for page := 0; page < maxTaskListPages; page++ {
			params := map[string]interface{}{"pageSize": 100, "historyLength": 0}
			if next != "" {
				params["pageToken"] = next
			}
			requestID := fmt.Sprintf("batesian-enum-%s-%d", randID, page)
			resp, err := c.POST(ctx, endpoint, at.headers, map[string]interface{}{
				"jsonrpc": "2.0", "id": requestID, "method": at.method, "params": params,
			})
			if err != nil {
				if page > 0 {
					return nil, listIncomplete
				}
				absentEverywhere = false
				incompleteFirstPage = true
				break
			}
			result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
			if !resp.IsSuccess() || !valid || hasError {
				if page > 0 {
					return nil, listIncomplete
				}
				if valid && hasError && code == jsonRPCMethodNotFound {
					break
				}
				absentEverywhere = false
				if !isA2AAuthRejection(resp) {
					incompleteFirstPage = true
				}
				break
			}
			pageIDs, token, ok := parseTaskListPage(result)
			if !ok {
				return nil, listIncomplete
			}
			ids = append(ids, pageIDs...)
			if containsTaskID(pageIDs, wantedID) || token == "" {
				return ids, listOK
			}
			if seen[token] {
				return nil, listIncomplete
			}
			seen[token] = true
			next = token
		}
		if next != "" {
			return nil, listIncomplete
		}
	}
	if incompleteFirstPage {
		return nil, listIncomplete
	}
	if absentEverywhere {
		return nil, listAbsent
	}
	return nil, listRefused
}

func (e *TaskEnumerationExecutor) listRESTTasks(ctx context.Context, c *attack.HTTPClient, endpoint string,
	headers map[string]string, wantedID string) ([]string, listOutcome) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, listIncomplete
	}
	next := ""
	seen := map[string]bool{}
	var ids []string
	for page := 0; page < maxTaskListPages; page++ {
		u := *base
		query := u.Query()
		query.Set("pageSize", "100")
		query.Set("historyLength", "0")
		if next != "" {
			query.Set("pageToken", next)
		}
		u.RawQuery = query.Encode()
		resp, err := c.GET(ctx, u.String(), headers)
		if err != nil || resp == nil {
			return nil, listIncomplete
		}
		if !resp.IsSuccess() {
			if page == 0 && resp.StatusCode == 404 {
				return nil, listAbsent
			}
			if page == 0 && isA2AAuthRejection(resp) {
				return nil, listRefused
			}
			return nil, listIncomplete
		}
		pageIDs, token, valid := parseRESTTaskListPage(resp.Body)
		if !valid {
			return nil, listIncomplete
		}
		ids = append(ids, pageIDs...)
		if containsTaskID(pageIDs, wantedID) || token == "" {
			return ids, listOK
		}
		if seen[token] {
			return nil, listIncomplete
		}
		seen[token] = true
		next = token
	}
	return nil, listIncomplete
}

func parseTaskListPage(raw json.RawMessage) ([]string, string, bool) {
	var page struct {
		Tasks []struct {
			ID     string `json:"id"`
			TaskID string `json:"taskId"`
		} `json:"tasks"`
		NextPageToken *string `json:"nextPageToken"`
	}
	if json.Unmarshal(raw, &page) != nil || page.Tasks == nil || page.NextPageToken == nil {
		return nil, "", false
	}
	ids := make([]string, 0, len(page.Tasks))
	for _, task := range page.Tasks {
		id := task.ID
		if id == "" {
			id = task.TaskID
		}
		if id == "" {
			return nil, "", false
		}
		ids = append(ids, id)
	}
	return ids, *page.NextPageToken, true
}

// withV1Version adds the v1.0 revision header to a principal's own headers without
// mutating them.
func withV1Version(extra map[string]string) map[string]string {
	h := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// createTask establishes a task owned by p, trying the v1.0 method name then the v0.3
// one. The observation is returned so a caller that got no task can say why rather
// than reporting a scoped listing it never tested.
func (e *TaskEnumerationExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (taskID, contextID string, accepted bool, obs setupObservation) {
	resp, err := c.POST(ctx, endpoint, withV1Version(p.Headers), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-enum-create-" + p.Name + "-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1, // ROLE_USER
				"parts":     []interface{}{map[string]string{"text": "batesian enumeration probe " + randID}},
				"messageId": "batesian-enum-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !resp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp))
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-enum-create-" + p.Name + "-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian enumeration probe " + randID}},
					"messageId": "batesian-enum-" + p.Name + "-" + randID,
				},
			},
		})
	}
	if err != nil || !resp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp))
		return "", "", false, obs
	}
	taskID, contextID = extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp))
	}
	return taskID, contextID, taskID != "", obs
}

func (e *TaskEnumerationExecutor) finding(endpoint string, a, b attack.Principal,
	taskID string, otherList []string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A ListTasks enumerates another principal's tasks (broken authorization scoping)",
		Description: fmt.Sprintf(
			"ListTasks at %s returned principal %s's task to principal %s, who has no claim to it. "+
				"The specification requires the opposite twice: section 3.1.4 states that "+
				"implementations MUST implement appropriate authorization scoping so clients can only "+
				"access authorized tasks, and section 13.1 that servers MUST return only tasks visible "+
				"to the authenticated client. Enumeration is worse than reading a task by id, because "+
				"it needs no prior knowledge: one valid credential yields every task identifier on the "+
				"server, and those identifiers are what the per-task read, cancel and push-config "+
				"surfaces take as input.", endpoint, a.Name, b.Name),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask owner: %s (tenant %s)\nenumerating principal: %s (tenant %s)\n"+
				"task created by %s: %s\ntask ids returned to %s: %v\n"+
				"unauthenticated ListTasks: did not return the task, so authorization is enforced "+
				"and the failure is scoping between valid principals",
			endpoint, a.Name, a.Tenant, b.Name, b.Tenant, a.Name, taskID, b.Name, otherList),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
