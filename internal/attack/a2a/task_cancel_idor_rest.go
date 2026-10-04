package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

func (e *TaskCancelIDORExecutor) probeREST(ctx context.Context, target, randID string,
	a, b attack.Principal, owner, other, anon *attack.HTTPClient) ([]attack.Finding, error, bool) {
	bases := resolveHTTPJSONBases(ctx, owner, target)
	if len(bases) == 0 {
		return nil, nil, false
	}
	var incomplete error
	anyTested := false
	for baseIndex, base := range bases {
		baseTested := false
		var setupErr error
		for _, route := range []struct{ send, tasks, version string }{
			{"/message:send", "/tasks", "1.0"},
			{"/v1/message:send", "/v1/tasks", "0.3.0"},
		} {
			routeID := fmt.Sprintf("%s-%d-%s", randID, baseIndex, route.version)
			findings, err, tested := e.probeRESTRoute(ctx, endpoint.AppendPath(base, route.send),
				endpoint.AppendPath(base, route.tasks), route.version, routeID,
				a, b, owner, other, anon)
			if len(findings) != 0 {
				return findings, nil, true
			}
			baseTested = baseTested || tested
			anyTested = anyTested || tested
			if err != nil {
				if tested && incomplete == nil {
					incomplete = err
				} else if setupErr == nil {
					setupErr = err
				}
			}
		}
		if !baseTested && incomplete == nil {
			if setupErr != nil {
				incomplete = setupErr
			} else {
				incomplete = fmt.Errorf("%w: advertised HTTP+JSON interface at %s did not create a task to test",
					attack.ErrInconclusive, base)
			}
		}
	}
	return nil, incomplete, anyTested
}

func (e *TaskCancelIDORExecutor) probeRESTRoute(ctx context.Context, sendURL, tasksURL, version, randID string,
	a, b attack.Principal, owner, other, anon *attack.HTTPClient) ([]attack.Finding, error, bool) {
	headers := restVersionHeaders(version, a.Headers)
	sendHeaders := restVersionHeaders(version, a.Headers)
	if version == "1.0" {
		sendHeaders["Content-Type"] = "application/a2a+json"
	}
	body := restTaskSendRequest(randID+"-cancel-"+version, "batesian cancel probe "+randID, version)
	resp, err := owner.POST(ctx, sendURL, sendHeaders, body)
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
		return nil, classifyTaskSetup("creating a REST cancel probe task as principal "+a.Name,
			sendURL, principalCredentialPresent(owner, sendURL, a.Headers), resp).err(), false
	}
	if !principalCredentialPresent(owner, sendURL, a.Headers) {
		return nil, fmt.Errorf("%w: REST task creation at %s used no owner credential", attack.ErrInconclusive, sendURL), true
	}
	readURL := endpoint.AppendPath(tasksURL, "/"+url.PathEscape(taskID))
	cancelURL := endpoint.AppendPath(tasksURL, "/"+url.PathEscape(taskID)+":cancel")
	baseline, seen := readRESTTaskState(ctx, owner, readURL, headers, taskID)
	if !seen || !activeTaskState(baseline) {
		return nil, fmt.Errorf("%w: owner task %s was not confirmed in a cancelable state at %s",
			attack.ErrInconclusive, taskID, readURL), true
	}
	method := "POST /tasks/{id}:cancel"
	if version != "1.0" {
		method = "POST /v1/tasks/{id}:cancel"
	}
	anonOutcome, err := cancelRESTTask(ctx, anon, owner, cancelURL, readURL, version, nil,
		headers, taskID)
	if err != nil {
		return nil, err, true
	}
	switch anonOutcome {
	case cancelCanceled:
		return []attack.Finding{e.unauthFinding(cancelURL, taskID, baseline, method)}, nil, true
	case cancelDenied:
	default:
		return nil, fmt.Errorf("%w: anonymous REST cancellation of task %s was not conclusively denied",
			attack.ErrInconclusive, taskID), true
	}
	preBState, seen := readRESTTaskState(ctx, owner, readURL, headers, taskID)
	if !seen || !activeTaskState(preBState) {
		return nil, fmt.Errorf("%w: owner task %s was no longer live before the cross-principal REST cancel",
			attack.ErrInconclusive, taskID), true
	}
	otherOutcome, err := cancelRESTTask(ctx, other, owner, cancelURL, readURL, version, b.Headers,
		headers, taskID)
	if err != nil {
		return nil, err, true
	}
	if otherOutcome == cancelCanceled {
		return []attack.Finding{e.idorFinding(cancelURL, a, b, taskID, preBState, method)}, nil, true
	}
	return nil, nil, true
}

func cancelRESTTask(ctx context.Context, caller, owner *attack.HTTPClient, cancelURL, readURL, version string,
	callerHeaders, ownerHeaders map[string]string, taskID string) (cancelOutcome, error) {
	headers := restVersionHeaders(version, callerHeaders)
	if version == "1.0" {
		headers["Content-Type"] = "application/a2a+json"
	}
	body := map[string]string{"id": taskID}
	if version != "1.0" {
		body = map[string]string{"name": "tasks/" + taskID}
	}
	resp, err := caller.POST(ctx, cancelURL, headers, body)
	state, seen := readRESTTaskState(ctx, owner, readURL, ownerHeaders, taskID)
	if !seen {
		return cancelOther, fmt.Errorf("%w: owner could not read REST task %s after a cancellation attempt",
			attack.ErrInconclusive, taskID)
	}
	if isCanceledState(state) {
		return cancelCanceled, nil
	}
	if !activeTaskState(state) {
		return cancelOther, fmt.Errorf("%w: REST task %s left its cancelable state without a confirmed cancellation",
			attack.ErrInconclusive, taskID)
	}
	if err != nil || resp == nil {
		return cancelOther, fmt.Errorf("%w: REST cancellation at %s did not answer",
			attack.ErrInconclusive, cancelURL)
	}
	if isA2AAuthRejection(resp) || resp.StatusCode == 404 {
		return cancelDenied, nil
	}
	return cancelOther, fmt.Errorf("%w: REST cancellation of task %s at %s was not conclusively denied",
		attack.ErrInconclusive, taskID, cancelURL)
}

func readRESTTaskState(ctx context.Context, owner *attack.HTTPClient, readURL string,
	headers map[string]string, taskID string) (string, bool) {
	resp, err := owner.GET(ctx, readURL, headers)
	if err != nil || resp == nil || !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return "", false
	}
	return restTaskStateForID(resp.Body, taskID)
}

func restTaskStateForID(body []byte, taskID string) (string, bool) {
	type task struct {
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	var envelope struct {
		task
		Task *task `json:"task"`
	}
	if taskID == "" || json.Unmarshal(body, &envelope) != nil {
		return "", false
	}
	if envelope.Task != nil {
		if envelope.Task.ID == taskID {
			return envelope.Task.Status.State, true
		}
		return "", false
	}
	if envelope.ID == taskID {
		return envelope.Status.State, true
	}
	return "", false
}
