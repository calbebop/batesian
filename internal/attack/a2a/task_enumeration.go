package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

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
	ctx = withTenantRouting(ctx)
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
	var incomplete error
	if !ok {
		incomplete = advertisedJSONRPCUnavailable(ctx, unauthClient, vars.BaseURL)
	}
	if !ok && len(restBases) == 0 {
		if incomplete != nil {
			return nil, incomplete
		}
		return nil, attack.ErrInconclusive
	}

	if ok {
		findings, err := e.probeJSONRPC(ctx, endpoint, vars.RandID, a, b, clientA, clientB, unauthClient)
		if len(findings) != 0 {
			return findings, err
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
				return findings, errors.Join(incomplete, err)
			}
			baseTested = baseTested || tested
			incomplete = errors.Join(incomplete, err)
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
	taskID, obs := e.createTask(ctx, clientA, endpoint, a, randID)
	if taskID == "" {
		return nil, obs.err()
	}
	list := func(c *attack.HTTPClient, headers map[string]string, phase string) taskListing {
		return e.listTasks(ctx, c, endpoint, headers, randID, taskID, phase)
	}
	findings, err := e.probeListing(endpoint, taskID, a, b, clientA, clientB, unauthClient, list)
	return findings, errors.Join(obs.partialErr(), err)
}

func (e *TaskEnumerationExecutor) probeREST(ctx context.Context, sendURL, listURL, version, randID string,
	a, b attack.Principal, clientA, clientB, unauthClient *attack.HTTPClient) ([]attack.Finding, error, bool) {
	headers := restVersionHeaders(version, a.Headers)
	if version == "1.0" {
		headers["Content-Type"] = "application/a2a+json"
	}
	messageID := randID + "-" + version
	body := restTaskSendRequest(messageID, "ping", version)
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
	list := func(c *attack.HTTPClient, principalHeaders map[string]string, _ string) taskListing {
		ids, outcome := e.listRESTTasks(ctx, c, listURL, restVersionHeaders(version, principalHeaders), taskID)
		return taskListing{ids: ids, outcome: outcome}
	}
	findings, err := e.probeListing(listURL, taskID, a, b, clientA, clientB, unauthClient, list)
	return findings, err, true
}

func restVersionHeaders(version string, extra map[string]string) map[string]string {
	headers := map[string]string{}
	for key, value := range extra {
		if !strings.EqualFold(key, "A2A-Version") {
			headers[key] = value
		}
	}
	if version == "1.0" {
		headers["A2A-Version"] = version
	}
	return headers
}

func (e *TaskEnumerationExecutor) probeListing(endpoint, taskID string, a, b attack.Principal,
	clientA, clientB, unauthClient *attack.HTTPClient,
	list func(*attack.HTTPClient, map[string]string, string) taskListing) ([]attack.Finding, error) {

	partial := false
	finish := func(findings []attack.Finding, err error) ([]attack.Finding, error) {
		if partial {
			err = errors.Join(err, fmt.Errorf("%w: an earlier ListTasks reply was unjudged", attack.ErrInconclusive))
		}
		return findings, err
	}
	ownList := list(clientA, a.Headers, "owner")
	partial = partial || ownList.partial
	switch ownList.outcome {
	case listAbsent:
		return finish(nil, nil)
	case listRefused:
		return finish(nil, fmt.Errorf("%w: ListTasks at %s was refused for the task's own owner (%s), "+
			"so whether the listing is scoped to the caller could not be established",
			attack.ErrInconclusive, endpoint, a.Name))
	case listIncomplete:
		return finish(nil, fmt.Errorf("%w: ListTasks at %s could not complete the owner's listing",
			attack.ErrInconclusive, endpoint))
	}
	if !containsTaskID(ownList.ids, taskID) {
		// The owner cannot see their own task, so this listing does not enumerate what
		// the rule assumes it enumerates and B seeing nothing would prove nothing.
		return finish(nil, fmt.Errorf("%w: ListTasks at %s did not return principal %s's own task %s, "+
			"so the listing does not enumerate the tasks this rule compares against",
			attack.ErrInconclusive, endpoint, a.Name, taskID))
	}

	anonList := list(unauthClient, nil, "anonymous")
	partial = partial || anonList.partial
	if anonList.outcome == listIncomplete {
		return finish(nil, fmt.Errorf("%w: anonymous ListTasks at %s could not complete its listing",
			attack.ErrInconclusive, endpoint))
	}
	if anonList.outcome == listOK && containsTaskID(anonList.ids, taskID) {
		return finish(nil, nil)
	}

	otherList := list(clientB, b.Headers, "other")
	partial = partial || otherList.partial
	if otherList.outcome == listIncomplete {
		return finish(nil, fmt.Errorf("%w: ListTasks at %s could not complete principal %s's listing",
			attack.ErrInconclusive, endpoint, b.Name))
	}
	if otherList.outcome != listOK {
		// B cannot list at all, which is one legitimate way to scope the surface.
		return finish(nil, nil)
	}
	if !containsTaskID(otherList.ids, taskID) {
		return finish(nil, nil)
	}

	return finish([]attack.Finding{e.finding(endpoint, a, b, taskID, otherList.ids)}, nil)
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

type taskListing struct {
	ids     []string
	outcome listOutcome
	partial bool
}

// listTasks walks bounded pages until the task is found or the list ends.
func (e *TaskEnumerationExecutor) listTasks(ctx context.Context, c *attack.HTTPClient, endpoint string,
	extraHeaders map[string]string, randID, wantedID, phase string) taskListing {
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
	partial := false
	for _, at := range attempts {
		next := ""
		seen := map[string]bool{}
		var ids []string
		for page := 0; page < maxTaskListPages; page++ {
			params := map[string]interface{}{"pageSize": 100, "historyLength": 0}
			if next != "" {
				params["pageToken"] = next
			}
			requestID := fmt.Sprintf("batesian-enum-%s-%s-%s-%d", randID, phase, at.method, page)
			resp, err := c.POST(ctx, endpoint, at.headers, map[string]interface{}{
				"jsonrpc": "2.0", "id": requestID, "method": at.method, "params": params,
			})
			if err != nil || resp == nil {
				if page > 0 {
					return taskListing{outcome: listIncomplete}
				}
				absentEverywhere = false
				partial = true
				break
			}
			result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
			if !resp.IsSuccess() || !valid || hasError {
				if page > 0 {
					return taskListing{outcome: listIncomplete}
				}
				if resp.IsSuccess() && valid && hasError && code == jsonRPCMethodNotFound {
					break
				}
				absentEverywhere = false
				authError := resp.IsSuccess() && valid && hasError && errMessageIsAuth(resp.Body)
				if resp.StatusCode != 401 && resp.StatusCode != 403 && !authError {
					partial = true
				}
				break
			}
			pageIDs, token, ok := parseTaskListPage(result)
			if !ok {
				return taskListing{outcome: listIncomplete}
			}
			ids = append(ids, pageIDs...)
			if containsTaskID(pageIDs, wantedID) || token == "" {
				return taskListing{ids: ids, outcome: listOK, partial: partial}
			}
			if seen[token] {
				return taskListing{outcome: listIncomplete}
			}
			seen[token] = true
			next = token
		}
		if next != "" {
			return taskListing{outcome: listIncomplete}
		}
	}
	if partial {
		return taskListing{outcome: listIncomplete}
	}
	if absentEverywhere {
		return taskListing{outcome: listAbsent}
	}
	return taskListing{outcome: listRefused}
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
	p attack.Principal, randID string) (taskID string, obs setupObservation) {
	requestID := "batesian-enum-create-" + p.Name + "-" + randID
	resp, err := c.POST(ctx, endpoint, withV1Version(p.Headers), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
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
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		requestID += "-v03"
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
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
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
		return "", obs
	}
	taskID, _ = extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(correlatedTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			principalCredentialPresent(c, endpoint, p.Headers), resp, requestID))
	}
	return taskID, obs
}

func (e *TaskEnumerationExecutor) finding(endpoint string, a, b attack.Principal,
	taskID string, otherList []string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title:      "A2A ListTasks returned a task created with another credential",
		Description: fmt.Sprintf(
			"ListTasks at %s returned a task created with principal %s's credential to principal %s. "+
				"The anonymous listing did not return it. This may expose task identifiers across an "+
				"intended authorization boundary, but different credentials alone do not establish "+
				"different task visibility. Check whether %s is authorized to see this task under the "+
				"agent's access policy.", endpoint, a.Name, b.Name, b.Name),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask creator: %s (configured tenant %s)\nlisting principal: %s (configured tenant %s)\n"+
				"task created by %s: %s\ntask ids returned to %s: %v\n"+
				"unauthenticated ListTasks: did not return the task\n"+
				"authorization policy for the two principals: not verified",
			endpoint, a.Name, a.Tenant, b.Name, b.Tenant, a.Name, taskID, b.Name, otherList),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
