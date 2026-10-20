package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	endpointpkg "github.com/calbebop/batesian/internal/endpoint"
)

type pushRegistration struct {
	endpoint    string
	taskID      string
	configID    string
	callbackURL string
	version     string
	rest        bool
}

func newPushRegistration(endpoint, taskID, version, callbackURL string, resp *attack.Response, rest bool) *pushRegistration {
	return &pushRegistration{
		endpoint:    endpoint,
		taskID:      taskID,
		configID:    pushConfigID(taskID, version, resp),
		callbackURL: callbackURL,
		version:     version,
		rest:        rest,
	}
}

func (p *pushRegistration) finish(ctx context.Context, client *attack.HTTPClient, state *attack.TargetState, manualVerification bool) string {
	if p == nil {
		return ""
	}
	if manualVerification {
		detail := "external OOB delivery pending; remove after manual verification"
		recordPushConfig(state, p.endpoint, p.taskID, p.configID, attack.CleanupNotAttempted, detail)
		return fmt.Sprintf("scanner-created push config %q on task %q: %s", p.configID, p.taskID, detail)
	}
	status := attack.CleanupUnavailable
	detail := "registration did not return a configuration ID"
	if p.configID != "" {
		detail = ""
		if p.rest && !safePushConfigPathID(p.configID) {
			detail = "configuration ID is not a safe URL path segment"
		} else {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
			defer cancel()
			if !p.readbackMatches(cleanupCtx, client) {
				detail = "config readback did not confirm the registered callback"
			} else {
				status, detail = p.delete(cleanupCtx, client)
			}
		}
	}
	recordPushConfig(state, p.endpoint, p.taskID, p.configID, status, detail)
	if status == attack.CleanupCompleted {
		return fmt.Sprintf("scanner-created push config %q on task %q: deleted after probe", p.configID, p.taskID)
	}
	return fmt.Sprintf("scanner-created push config %q on task %q: cleanup %s (%s); verify on target",
		p.configID, p.taskID, status, detail)
}

func (p *pushRegistration) readbackMatches(ctx context.Context, client *attack.HTTPClient) bool {
	var resp *attack.Response
	var err error
	var result []byte
	if p.rest {
		getURL := endpointpkg.AppendPath(p.endpoint, "/"+url.PathEscape(p.configID))
		resp, err = client.GET(ctx, getURL, restVersionHeaders(p.version, nil))
		if err != nil || resp == nil || !resp.IsSuccess() || !resp.IsJSON() {
			return false
		}
		result = resp.Body
	} else {
		method, params, headers := p.rpcRequest("GetTaskPushNotificationConfig", "tasks/pushNotificationConfig/get")
		requestID := "batesian-push-readback-" + p.configID
		resp, err = client.POST(ctx, p.endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0", "id": requestID, "method": method, "params": params,
		})
		if err != nil || resp == nil || !resp.IsSuccess() {
			return false
		}
		var hasError, valid bool
		result, _, hasError, valid = discoveryResponse(resp.Body, requestID)
		if !valid || hasError {
			return false
		}
	}
	var config struct {
		TaskID                 string `json:"taskId"`
		ID                     string `json:"id"`
		Name                   string `json:"name"`
		URL                    string `json:"url"`
		PushNotificationConfig *struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"pushNotificationConfig"`
	}
	if json.Unmarshal(result, &config) != nil || p.callbackURL == "" ||
		(config.TaskID != "" && config.TaskID != p.taskID) ||
		(config.ID != "" && config.ID != p.configID) {
		return false
	}
	if p.version == "0.3.0" {
		if config.PushNotificationConfig == nil || config.PushNotificationConfig.URL != p.callbackURL ||
			(config.PushNotificationConfig.ID != "" && config.PushNotificationConfig.ID != p.configID) {
			return false
		}
		if p.rest {
			return config.Name == "tasks/"+p.taskID+"/pushNotificationConfigs/"+p.configID
		}
		return config.TaskID == p.taskID
	}
	return config.URL == p.callbackURL
}

func (p *pushRegistration) delete(ctx context.Context, client *attack.HTTPClient) (attack.CleanupStatus, string) {
	var resp *attack.Response
	var err error
	if p.rest {
		deleteURL := endpointpkg.AppendPath(p.endpoint, "/"+url.PathEscape(p.configID))
		resp, err = client.DELETE(ctx, deleteURL, restVersionHeaders(p.version, nil))
		if err == nil && resp != nil &&
			(resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent) {
			return attack.CleanupCompleted, ""
		}
	} else {
		method, params, headers := p.rpcRequest("DeleteTaskPushNotificationConfig", "tasks/pushNotificationConfig/delete")
		requestID := "batesian-push-cleanup-" + p.configID
		resp, err = client.POST(ctx, p.endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0", "id": requestID, "method": method, "params": params,
		})
		if err == nil && resp != nil && resp.IsSuccess() {
			_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
			if valid && !hasError {
				return attack.CleanupCompleted, ""
			}
		}
	}
	switch {
	case err != nil:
		return attack.CleanupAttempted, "delete request failed: " + err.Error()
	case resp == nil:
		return attack.CleanupAttempted, "delete returned no response"
	default:
		return attack.CleanupAttempted, fmt.Sprintf("delete returned HTTP %d without confirmation", resp.StatusCode)
	}
}

func (p *pushRegistration) rpcRequest(v1Method, v03Method string) (string, map[string]string, map[string]string) {
	if p.version == "0.3.0" {
		return v03Method, map[string]string{"id": p.taskID, "pushNotificationConfigId": p.configID}, nil
	}
	return v1Method, map[string]string{"taskId": p.taskID, "id": p.configID}, map[string]string{"A2A-Version": "1.0"}
}

func safePushConfigPathID(id string) bool {
	if id == "." || id == ".." {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			continue
		}
		return false
	}
	return id != ""
}
