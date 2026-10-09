package a2a

import (
	"context"
	"fmt"
	"net/url"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

func (e *TaskIDORExecutor) probeRESTTaskReads(ctx context.Context, target string,
	opts attack.Options) ([]attack.Finding, error, bool) {
	if opts.Token == "" {
		return nil, nil, false
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	owner := attack.NewHTTPClient(opts, vars)
	anon := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))
	bases := resolveHTTPJSONBases(ctx, owner, vars.BaseURL)
	if len(bases) == 0 {
		return nil, nil, false
	}
	var incomplete error
	anyTested := false
	for _, base := range bases {
		baseTested := false
		for _, route := range []struct{ send, tasks, version string }{
			{"/message:send", "/tasks", "1.0"},
			{"/v1/message:send", "/v1/tasks", "0.3.0"},
		} {
			sendURL := endpoint.AppendPath(base, route.send)
			findings, err, tested := e.probeRESTTaskRead(ctx, owner, anon, sendURL,
				endpoint.AppendPath(base, route.tasks), route.version, vars.RandID)
			if len(findings) != 0 {
				return findings, nil, true
			}
			baseTested = baseTested || tested
			anyTested = anyTested || tested
			if incomplete == nil {
				incomplete = err
			}
		}
		if !baseTested && incomplete == nil {
			incomplete = fmt.Errorf("%w: advertised HTTP+JSON interface at %s did not yield a testable owner task",
				attack.ErrInconclusive, base)
		}
	}
	return nil, incomplete, anyTested
}

func (e *TaskIDORExecutor) probeRESTTaskRead(ctx context.Context, owner, anon *attack.HTTPClient,
	sendURL, tasksURL, version, randID string) ([]attack.Finding, error, bool) {
	marker := "batesian idor probe " + randID + "-" + version
	headers := restVersionHeaders(version, nil)
	sendHeaders := restVersionHeaders(version, nil)
	if version == "1.0" {
		sendHeaders["Content-Type"] = "application/a2a+json"
	}
	ownerResp, err := owner.POST(ctx, sendURL, sendHeaders,
		restTaskSendRequest(randID+"-owner-"+version, marker, version))
	if err != nil || ownerResp == nil {
		return nil, fmt.Errorf("%w: REST task creation at %s did not answer", attack.ErrInconclusive, sendURL), false
	}
	if ownerResp.StatusCode == 404 {
		return nil, nil, false
	}
	taskID := ""
	if ownerResp.IsSuccess() && ownerResp.IsJSON() && !isJSONRPCError(ownerResp.Body) {
		taskID = restTaskID(ownerResp.Body)
	}
	if taskID == "" {
		return nil, classifyTaskSetup("creating a REST probe task as the owner", sendURL,
			owner.PresentsCredential(sendURL), ownerResp).err(), false
	}
	if !owner.PresentsCredential(sendURL) {
		return nil, fmt.Errorf("%w: REST task creation at %s used no owner credential", attack.ErrInconclusive, sendURL), false
	}
	readURL := endpoint.AppendPath(tasksURL, "/"+url.PathEscape(taskID))
	u, err := url.Parse(readURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid REST task URL at %s", attack.ErrInconclusive, tasksURL), false
	}
	query := u.Query()
	query.Set("historyLength", "10")
	u.RawQuery = query.Encode()
	readURL = u.String()
	ownerRead, err := owner.GET(ctx, readURL, headers)
	if err != nil || ownerRead == nil || !ownerRead.IsSuccess() {
		return nil, fmt.Errorf("%w: the owner could not read REST task %s at %s",
			attack.ErrInconclusive, taskID, readURL), false
	}
	if location, _ := taskMarkerLocation(ownerRead.Body, taskID, marker); location == "" {
		return nil, fmt.Errorf("%w: the owner read of REST task %s omitted its probe content",
			attack.ErrInconclusive, taskID), false
	}
	anonResp, err := anon.POST(ctx, sendURL, sendHeaders,
		restTaskSendRequest(randID+"-anon-"+version, "batesian anonymous probe "+randID, version))
	if err != nil || anonResp == nil {
		return nil, fmt.Errorf("%w: anonymous REST task creation at %s did not answer",
			attack.ErrInconclusive, sendURL), false
	}
	if anonResp.IsSuccess() && anonResp.IsJSON() && !isJSONRPCError(anonResp.Body) &&
		restTaskID(anonResp.Body) != "" {
		return nil, nil, true
	}
	if !isA2AAuthRejection(anonResp) {
		return nil, fmt.Errorf("%w: anonymous REST task creation at %s did not establish an auth rejection",
			attack.ErrInconclusive, sendURL), false
	}
	read, err := anon.GET(ctx, readURL, headers)
	if err != nil || read == nil {
		return nil, fmt.Errorf("%w: anonymous REST task read at %s did not answer",
			attack.ErrInconclusive, readURL), true
	}
	if read.StatusCode == 401 || read.StatusCode == 403 || read.StatusCode == 404 {
		return nil, nil, true
	}
	if !read.IsSuccess() {
		return nil, fmt.Errorf("%w: anonymous REST task read at %s returned HTTP %d",
			attack.ErrInconclusive, readURL, read.StatusCode), true
	}
	if !read.IsJSON() || isJSONRPCError(read.Body) {
		return nil, fmt.Errorf("%w: anonymous REST task read at %s returned no task JSON",
			attack.ErrInconclusive, readURL), true
	}
	location, matched := taskMarkerLocation(read.Body, taskID, marker)
	if location == "" {
		if matched {
			return nil, fmt.Errorf("%w: anonymous REST task %s omitted its owner probe content",
				attack.ErrInconclusive, taskID), true
		}
		return nil, fmt.Errorf("%w: anonymous REST task read returned no matching task %s",
			attack.ErrInconclusive, taskID), true
	}
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A task content readable without owner credentials",
		Description: fmt.Sprintf("An anonymous REST task read returned the owner's unique probe text in task %s's %s, "+
			"despite the same task-creation endpoint rejecting anonymous callers.", taskID, location),
		Evidence: fmt.Sprintf("taskId: %s\nowner marker: %s\nlocation: %s\nanonymous GET: HTTP %d\n%s",
			taskID, marker, location, read.StatusCode, snippet(read.Body, 500)),
		Remediation: e.rule.Remediation,
		TargetURL:   readURL,
	}}, nil, true
}
