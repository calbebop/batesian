package a2a

import (
	"bytes"
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

func (e *PushLifecycleExecutor) probeREST(ctx context.Context, target string, opts attack.Options, randID string,
	owner, other attack.Principal, clientA, clientB *attack.HTTPClient) ([]attack.Finding, error, bool) {
	bases := resolveHTTPJSONBases(ctx, clientA, target)
	if len(bases) == 0 {
		return nil, nil, false
	}
	var findings []attack.Finding
	var partial error
	for baseIndex, base := range bases {
		for _, route := range restPushRoutes {
			routeFindings, routeErr := e.probeRESTRoute(ctx, base, route, opts,
				fmt.Sprintf("%s-%d-%s", randID, baseIndex, route.version), owner, other, clientA, clientB)
			findings = append(findings, routeFindings...)
			partial = errors.Join(partial, routeErr)
		}
	}
	return findings, partial, true
}

func (e *PushLifecycleExecutor) probeRESTRoute(ctx context.Context, base string, route restPushRoute,
	opts attack.Options, randID string, owner, other attack.Principal,
	clientA, clientB *attack.HTTPClient) (findings []attack.Finding, err error) {
	sendURL := endpoint.AppendPath(base, route.sendPath)
	ownerHeaders := restVersionHeaders(route.version, owner.Headers)
	if route.version == "1.0" {
		ownerHeaders["Content-Type"] = "application/a2a+json"
	}
	resp, requestErr := clientA.POST(ctx, sendURL, ownerHeaders,
		restTaskSendRequest(randID+"-lifecycle", "batesian push lifecycle probe "+randID, route.version))
	if requestErr != nil || resp == nil {
		return nil, fmt.Errorf("%w: REST task creation did not answer", attack.ErrInconclusive)
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, nil
	}
	taskID := restPushTaskID(resp)
	if taskID == "" {
		return nil, classifyTaskSetup("creating a REST push lifecycle task", sendURL,
			principalCredentialPresent(clientA, sendURL, owner.Headers), resp).err()
	}
	if !principalCredentialPresent(clientA, sendURL, owner.Headers) {
		return nil, fmt.Errorf("%w: REST task creation used no owner credential", attack.ErrInconclusive)
	}
	configURL := endpoint.AppendPath(base, route.configPath(taskID))
	markerURL := "https://batesian-lifecycle-" + randID + ".example/cb"
	configRequest := restPushConfigRequest(taskID, markerURL, "lifecycle-"+randID, "", randID, route.version)
	resp, requestErr = clientA.POST(ctx, configURL, ownerHeaders, configRequest)
	if requestErr != nil || !restPushRegistrationReplyAccepted(resp, taskID, markerURL, route.version) {
		if requestErr != nil {
			return nil, fmt.Errorf("%w: REST push configuration did not answer", attack.ErrInconclusive)
		}
		return nil, restPushRegistrationOutcome("creating a REST push configuration", resp,
			taskID, markerURL, route.version).err()
	}
	configID := pushConfigID(taskID, route.version, resp)
	if !safePushConfigPathID(configID) {
		recordPushConfig(opts.TargetState, configURL, taskID, configID, attack.CleanupUnavailable,
			"registration returned no safe configuration ID; verify on target")
		return nil, fmt.Errorf("%w: REST push registration did not return a safe configuration ID", attack.ErrInconclusive)
	}
	registration := newPushRegistration(configURL, taskID, route.version, markerURL, resp, true)
	registration.authHeaders = owner.Headers
	deleted := false
	deletionDetail := "deleted by cross-principal probe"
	defer func() {
		line := ""
		if deleted {
			recordPushConfig(opts.TargetState, configURL, taskID, configID, attack.CleanupCompleted, deletionDetail)
			line = fmt.Sprintf("scanner-created push config %q on task %q: %s", configID, taskID, deletionDetail)
		} else {
			line = registration.finish(ctx, clientA, opts.TargetState, false)
		}
		for i := range findings {
			findings[i].Evidence += "\n" + line
		}
	}()

	configItemURL := endpoint.AppendPath(configURL, "/"+url.PathEscape(configID))
	taskURL := endpoint.AppendPath(base, route.taskPath+"/"+url.PathEscape(taskID))
	if e.readRESTConfig(ctx, clientA, configItemURL, ownerHeaders, taskID, configID, markerURL, route.version) != configPresent {
		return nil, fmt.Errorf("%w: owner REST push config was not confirmed after creation", attack.ErrInconclusive)
	}
	if e.readRESTTask(ctx, clientA, taskURL, ownerHeaders, taskID) != taskPresent {
		return nil, fmt.Errorf("%w: owner could not read the REST probe task", attack.ErrInconclusive)
	}
	otherHeaders := restVersionHeaders(route.version, other.Headers)
	if e.readRESTTask(ctx, clientB, taskURL, otherHeaders, taskID) != taskDenied {
		return nil, fmt.Errorf("%w: second principal was not confirmed outside REST task-read scope", attack.ErrInconclusive)
	}
	ownerList := e.listRESTConfigs(ctx, clientA, configURL, ownerHeaders, taskID, configID, markerURL, route.version)
	if ownerList.found {
		otherList := e.listRESTConfigs(ctx, clientB, configURL, otherHeaders, taskID, configID, markerURL, route.version)
		if otherList.found {
			findings = append(findings, e.finding(configURL, owner, other, taskID, configID, markerURL, "list", "GET task"))
		} else if !otherList.complete && !otherList.denied {
			err = errors.Join(err, fmt.Errorf("%w: cross-principal REST push-config list was unjudged", attack.ErrInconclusive))
		}
	} else if !ownerList.unsupported {
		err = errors.Join(err, fmt.Errorf("%w: owner REST push-config list did not confirm the marker", attack.ErrInconclusive))
	}
	if e.readRESTConfig(ctx, clientA, configItemURL, ownerHeaders, taskID, configID, markerURL, route.version) != configPresent {
		return findings, errors.Join(err, fmt.Errorf("%w: owner REST marker was not present before the delete probe", attack.ErrInconclusive))
	}
	deleteReply := e.deleteRESTConfig(ctx, clientB, configItemURL, otherHeaders)
	readback := e.readRESTConfig(ctx, clientA, configItemURL, ownerHeaders, taskID, configID, markerURL, route.version)
	if readback == configAbsent && e.readRESTTask(ctx, clientA, taskURL, ownerHeaders, taskID) == taskPresent {
		deleted = true
		if deleteReply == deleteAccepted {
			findings = append(findings, e.finding(configURL, owner, other, taskID, configID, markerURL, "delete", "GET task"))
		} else {
			deletionDetail = "absent after probe; deletion source unconfirmed"
			err = errors.Join(err, fmt.Errorf("%w: REST marker disappeared without a confirmed delete response", attack.ErrInconclusive))
		}
	} else if readback == configPresent && deleteReply != deleteDenied && deleteReply != deleteUnsupported {
		err = errors.Join(err, fmt.Errorf("%w: cross-principal REST delete was not conclusively denied", attack.ErrInconclusive))
	} else if readback == configUnknown {
		err = errors.Join(err, fmt.Errorf("%w: REST delete readback was unjudged", attack.ErrInconclusive))
	}
	return findings, err
}

func (e *PushLifecycleExecutor) readRESTTask(ctx context.Context, client *attack.HTTPClient,
	taskURL string, headers map[string]string, taskID string) taskAccess {
	resp, err := client.GET(ctx, taskURL, headers)
	if err != nil || resp == nil {
		return taskUnknown
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return taskDenied
	}
	if !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return taskUnknown
	}
	state, matched := restTaskStateForID(resp.Body, taskID)
	if matched && state != "" {
		return taskPresent
	}
	return taskUnknown
}

func (e *PushLifecycleExecutor) readRESTConfig(ctx context.Context, client *attack.HTTPClient,
	configURL string, headers map[string]string, taskID, configID, markerURL, version string) configAccess {
	resp, err := client.GET(ctx, configURL, headers)
	if err != nil || resp == nil {
		return configUnknown
	}
	if resp.StatusCode == http.StatusNotFound {
		return configAbsent
	}
	if !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return configUnknown
	}
	if restLifecycleConfigMatches(resp.Body, taskID, configID, markerURL, version) {
		return configPresent
	}
	return configUnknown
}

func restLifecycleConfigMatches(body []byte, taskID, configID, markerURL, version string) bool {
	id, callback, valid := restLifecycleConfigFields(body, taskID, version)
	return valid && id == configID && callback == markerURL
}

func restLifecycleConfigFields(body []byte, taskID, version string) (string, string, bool) {
	var cfg struct {
		TaskID string `json:"taskId"`
		ID     string `json:"id"`
		Name   string `json:"name"`
		URL    string `json:"url"`
		Nested *struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"pushNotificationConfig"`
	}
	if json.Unmarshal(body, &cfg) != nil || cfg.TaskID != "" && cfg.TaskID != taskID {
		return "", "", false
	}
	if version == "1.0" {
		return cfg.ID, cfg.URL, cfg.ID != "" && cfg.URL != ""
	}
	prefix := "tasks/" + taskID + "/pushNotificationConfigs/"
	if !strings.HasPrefix(cfg.Name, prefix) || cfg.Nested == nil || cfg.Nested.URL == "" {
		return "", "", false
	}
	id := strings.TrimPrefix(cfg.Name, prefix)
	if id == "" || cfg.Nested.ID != "" && cfg.Nested.ID != id {
		return "", "", false
	}
	return id, cfg.Nested.URL, true
}

func (e *PushLifecycleExecutor) listRESTConfigs(ctx context.Context, client *attack.HTTPClient,
	configURL string, headers map[string]string, taskID, configID, markerURL, version string) listAccess {
	token := ""
	seen := map[string]bool{}
	for range 8 {
		requestURL := configURL
		if version == "1.0" {
			parsed, err := url.Parse(configURL)
			if err != nil {
				return listAccess{}
			}
			query := parsed.Query()
			query.Set("pageSize", "25")
			if token != "" {
				query.Set("pageToken", token)
			}
			parsed.RawQuery = query.Encode()
			requestURL = parsed.String()
		}
		resp, err := client.GET(ctx, requestURL, headers)
		if err != nil || resp == nil {
			return listAccess{}
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return listAccess{denied: true, unsupported: resp.StatusCode == http.StatusNotFound}
		}
		if resp.StatusCode == http.StatusMethodNotAllowed || restSubscriptionUnsupported(resp) {
			return listAccess{unsupported: true}
		}
		if !resp.IsSuccess() || !json.Valid(resp.Body) || isJSONRPCError(resp.Body) {
			return listAccess{}
		}
		var entries []json.RawMessage
		if version == "1.0" {
			var result map[string]json.RawMessage
			if json.Unmarshal(resp.Body, &result) != nil || result == nil {
				return listAccess{}
			}
			if raw, ok := result["configs"]; ok {
				raw = bytes.TrimSpace(raw)
				if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &entries) != nil {
					return listAccess{}
				}
			}
			if raw, ok := result["nextPageToken"]; ok {
				raw = bytes.TrimSpace(raw)
				if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &token) != nil {
					return listAccess{}
				}
			} else {
				token = ""
			}
		} else if json.Unmarshal(resp.Body, &entries) != nil || entries == nil {
			return listAccess{}
		}
		for _, entry := range entries {
			entry = bytes.TrimSpace(entry)
			if len(entry) == 0 || entry[0] != '{' {
				return listAccess{}
			}
			id, callback, valid := restLifecycleConfigFields(entry, taskID, version)
			if !valid {
				return listAccess{}
			}
			if id == configID && callback == markerURL {
				return listAccess{found: true}
			}
		}
		if token == "" {
			return listAccess{complete: true}
		}
		if seen[token] {
			return listAccess{}
		}
		seen[token] = true
	}
	return listAccess{}
}

func (e *PushLifecycleExecutor) deleteRESTConfig(ctx context.Context, client *attack.HTTPClient,
	configURL string, headers map[string]string) deleteAccess {
	resp, err := client.DELETE(ctx, configURL, headers)
	if err != nil || resp == nil {
		return deleteUnknown
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return deleteDenied
	}
	if resp.StatusCode == http.StatusMethodNotAllowed || restSubscriptionUnsupported(resp) {
		return deleteUnsupported
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return deleteUnknown
	}
	if body := bytes.TrimSpace(resp.Body); len(body) > 0 {
		if !json.Valid(body) {
			return deleteUnknown
		}
		var result map[string]json.RawMessage
		if json.Unmarshal(body, &result) == nil {
			if _, hasError := result["error"]; hasError {
				return deleteUnknown
			}
		}
	}
	return deleteAccepted
}
