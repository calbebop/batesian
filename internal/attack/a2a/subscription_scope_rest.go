package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

func (e *SubscriptionScopeExecutor) probeREST(ctx context.Context, target, randID string,
	owner, other attack.Principal, clientA, clientB *attack.HTTPClient) ([]attack.Finding, error, bool) {
	bases := resolveHTTPJSONBases(ctx, clientA, target)
	if len(bases) == 0 {
		return nil, nil, false
	}
	var partial error
	tested := false
	for baseIndex, base := range bases {
		for _, route := range restPushRoutes {
			findings, err, routeTested := e.probeRESTRoute(ctx, base, route,
				fmt.Sprintf("%s-%d-%s", randID, baseIndex, route.version), owner, other, clientA, clientB)
			if len(findings) != 0 {
				return findings, errors.Join(partial, err), true
			}
			tested = tested || routeTested
			partial = errors.Join(partial, err)
		}
	}
	if !tested && partial == nil {
		partial = fmt.Errorf("%w: advertised HTTP+JSON interface did not expose a testable task subscription",
			attack.ErrInconclusive)
	}
	return nil, partial, true
}

func (e *SubscriptionScopeExecutor) probeRESTRoute(ctx context.Context, base string, route restPushRoute,
	randID string, owner, other attack.Principal, clientA, clientB *attack.HTTPClient) ([]attack.Finding, error, bool) {
	sendURL := endpoint.AppendPath(base, route.sendPath)
	taskURL := endpoint.AppendPath(base, route.taskPath)
	headers := restVersionHeaders(route.version, owner.Headers)
	if route.version == "1.0" {
		headers["Content-Type"] = "application/a2a+json"
	}
	resp, err := clientA.POST(ctx, sendURL, headers,
		restTaskSendRequest(randID+"-subscription", "batesian subscription probe "+randID, route.version))
	if err != nil || resp == nil {
		return nil, fmt.Errorf("%w: REST task creation did not answer", attack.ErrInconclusive), false
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, nil, false
	}
	taskID := restPushTaskID(resp)
	if taskID == "" {
		return nil, classifyTaskSetup("creating a REST subscription probe task", sendURL,
			principalCredentialPresent(clientA, sendURL, owner.Headers), resp).err(), false
	}
	if !principalCredentialPresent(clientA, sendURL, owner.Headers) {
		return nil, fmt.Errorf("%w: REST task creation used no owner credential", attack.ErrInconclusive), true
	}
	readURL := endpoint.AppendPath(taskURL, "/"+url.PathEscape(taskID))
	subscribeURL := endpoint.AppendPath(taskURL, "/"+url.PathEscape(taskID)+":subscribe")
	ownerRead := e.restTaskRequest(ctx, clientA, readURL, headers, taskID, route.version, false)
	if ownerRead.kind != subscriptionData || !activeTaskState(ownerRead.state) {
		return nil, fmt.Errorf("%w: owner REST task read did not confirm a nonterminal task", attack.ErrInconclusive), true
	}
	ownerStream := e.restTaskRequest(ctx, clientA, subscribeURL, headers, taskID, route.version, true)
	if ownerStream.kind == subscriptionUnsupported {
		return nil, nil, true
	}
	if ownerStream.kind != subscriptionData || ownerStream.contextID != ownerRead.contextID ||
		(route.version == "1.0" && !activeTaskState(ownerStream.state)) {
		return nil, fmt.Errorf("%w: owner REST subscription did not return matching task data", attack.ErrInconclusive), true
	}
	otherRead := e.restTaskRequest(ctx, clientB, readURL, restVersionHeaders(route.version, other.Headers),
		taskID, route.version, false)
	if otherRead.kind != subscriptionDenied {
		return nil, fmt.Errorf("%w: second principal was not confirmed outside REST task-read scope",
			attack.ErrInconclusive), true
	}
	otherStream := e.restTaskRequest(ctx, clientB, subscribeURL, restVersionHeaders(route.version, other.Headers),
		taskID, route.version, true)
	switch otherStream.kind {
	case subscriptionData:
		if otherStream.contextID != ownerStream.contextID {
			return nil, fmt.Errorf("%w: second principal's REST event did not match the owner's context",
				attack.ErrInconclusive), true
		}
		method := "POST /tasks/{id}:subscribe"
		readMethod := "GET /tasks/{id}"
		if route.version != "1.0" {
			method = "POST /v1/tasks/{id}:subscribe"
			readMethod = "GET /v1/tasks/{id}"
		}
		return []attack.Finding{e.finding(base, owner, other, readMethod, method)}, nil, true
	case subscriptionDenied:
		return nil, nil, true
	default:
		return nil, fmt.Errorf("%w: second principal's REST subscription was unjudged",
			attack.ErrInconclusive), true
	}
}

func (e *SubscriptionScopeExecutor) restTaskRequest(ctx context.Context, client *attack.HTTPClient,
	requestURL string, headers map[string]string, taskID, version string, stream bool) subscriptionProbe {
	var resp *attack.Response
	var err error
	if stream {
		requestHeaders := restVersionHeaders(version, headers)
		requestHeaders["Accept"] = "text/event-stream"
		body := map[string]string{"id": taskID}
		if version != "1.0" {
			body = map[string]string{"name": "tasks/" + taskID}
		} else {
			requestHeaders["Content-Type"] = "application/a2a+json"
		}
		resp, err = client.POSTFirstSSE(ctx, requestURL, requestHeaders, body)
	} else {
		resp, err = client.GET(ctx, requestURL, headers)
	}
	if err != nil || resp == nil {
		return subscriptionProbe{}
	}
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return subscriptionProbe{kind: subscriptionUnsupported}
	}
	if restSubscriptionUnsupported(resp) {
		return subscriptionProbe{kind: subscriptionUnsupported}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound {
		return subscriptionProbe{kind: subscriptionDenied}
	}
	if !resp.IsSuccess() || (stream && !strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "text/event-stream")) ||
		(!stream && (!resp.IsJSON() || isJSONRPCError(resp.Body))) {
		return subscriptionProbe{}
	}
	if !stream {
		state, matched := restTaskStateForID(resp.Body, taskID)
		if matched && state != "" {
			if contextID := subscriptionContextID(resp.Body); contextID != "" {
				return subscriptionProbe{kind: subscriptionData, state: state, contextID: contextID}
			}
		}
		return subscriptionProbe{}
	}
	var event map[string]json.RawMessage
	if json.Unmarshal(resp.Body, &event) != nil || event == nil || len(event) != 1 {
		return subscriptionProbe{}
	}
	if raw, ok := event["task"]; ok {
		state, matched := restTaskStateForID(resp.Body, taskID)
		if matched && state != "" && len(raw) > 0 {
			if contextID := subscriptionContextID(resp.Body); contextID != "" {
				return subscriptionProbe{kind: subscriptionData, state: state, contextID: contextID}
			}
		}
	}
	if version == "1.0" {
		return subscriptionProbe{}
	}
	for _, key := range []string{"statusUpdate", "artifactUpdate"} {
		raw, ok := event[key]
		if !ok {
			continue
		}
		var update struct {
			TaskID    string `json:"taskId"`
			ContextID string `json:"contextId"`
			Status    struct {
				State string `json:"state"`
			} `json:"status"`
			Artifact struct {
				ID    string            `json:"artifactId"`
				Parts []json.RawMessage `json:"parts"`
			} `json:"artifact"`
		}
		if json.Unmarshal(raw, &update) != nil || update.TaskID != taskID || update.ContextID == "" {
			return subscriptionProbe{}
		}
		if key == "statusUpdate" && update.Status.State != "" ||
			key == "artifactUpdate" && update.Artifact.ID != "" && len(update.Artifact.Parts) > 0 {
			return subscriptionProbe{kind: subscriptionData, contextID: update.ContextID}
		}
	}
	return subscriptionProbe{}
}

func restSubscriptionUnsupported(resp *attack.Response) bool {
	if resp.StatusCode != http.StatusBadRequest {
		return false
	}
	var reply struct {
		Error struct {
			Details []struct {
				Type   string `json:"@type"`
				Reason string `json:"reason"`
				Domain string `json:"domain"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &reply) != nil {
		return false
	}
	for _, detail := range reply.Error.Details {
		if detail.Type == "type.googleapis.com/google.rpc.ErrorInfo" && detail.Domain == "a2a-protocol.org" &&
			detail.Reason == "UNSUPPORTED_OPERATION" {
			return true
		}
	}
	return false
}
