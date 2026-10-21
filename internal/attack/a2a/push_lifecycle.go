package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// PushLifecycleExecutor checks List and Delete access to a task's push configs.
type PushLifecycleExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-push-lifecycle", func(rc attack.RuleContext) attack.Executor {
		return NewPushLifecycleExecutor(rc)
	})
}

func NewPushLifecycleExecutor(r attack.RuleContext) *PushLifecycleExecutor {
	return &PushLifecycleExecutor{rule: r}
}

func (e *PushLifecycleExecutor) Produces() []attack.ArtifactKind { return nil }
func (e *PushLifecycleExecutor) Requires() []attack.ArtifactKind { return nil }

func (e *PushLifecycleExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

func (e *PushLifecycleExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, _ *attack.Blackboard) (findings []attack.Finding, err error) {
	ctx = withTenantRouting(ctx)
	a, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}
	clientA, clientB := principalClient(opts, vars, a), principalClient(opts, vars, b)
	binding := NewPushBindingExecutor(e.rule)
	taskID, setup := binding.createTask(ctx, clientA, endpoint, a, vars.RandID)
	if taskID == "" {
		return nil, setup.err()
	}
	partial := setup.partialErr()
	defer func() { err = errors.Join(err, partial) }()

	markerURL := "https://batesian-lifecycle-" + vars.RandID + ".example/cb"
	set := binding.setPush(ctx, clientA, endpoint, a.Headers, "configuring the owner's push-notification webhook",
		taskID, markerURL, "lifecycle-"+vars.RandID, "lifecycle-"+vars.RandID, vars.RandID)
	if !set.accepted {
		return nil, set.obs.err()
	}
	partial = errors.Join(partial, set.partialErr("owner push configuration"))
	version := "0.3.0"
	if set.v1 {
		version = "1.0"
	}
	registration := &pushRegistration{
		endpoint: endpoint, taskID: taskID, configID: set.id, callbackURL: markerURL,
		version: version, authHeaders: a.Headers,
	}
	deleted := false
	deletionDetail := "deleted by cross-principal probe"
	defer func() {
		line := ""
		if deleted {
			recordPushConfig(opts.TargetState, endpoint, taskID, set.id, attack.CleanupCompleted, deletionDetail)
			line = fmt.Sprintf("scanner-created push config %q on task %q: %s", set.id, taskID, deletionDetail)
		} else {
			line = registration.finish(ctx, clientA, opts.TargetState, false)
		}
		for i := range findings {
			findings[i].Evidence += "\n" + line
		}
	}()

	ownerConfig := e.readConfig(ctx, clientA, endpoint, a.Headers, taskID, set, markerURL, vars.RandID+"-owner")
	if ownerConfig != configPresent {
		return nil, fmt.Errorf("%w: owner push config was not confirmed after creation", attack.ErrInconclusive)
	}
	ownerTask := e.readTask(ctx, clientA, endpoint, a.Headers, taskID, set.v1, vars.RandID+"-owner")
	if ownerTask != taskPresent {
		return nil, fmt.Errorf("%w: owner could not read the probe task", attack.ErrInconclusive)
	}
	otherTask := e.readTask(ctx, clientB, endpoint, b.Headers, taskID, set.v1, vars.RandID+"-other")
	if otherTask != taskDenied {
		return nil, fmt.Errorf("%w: principal %q was not confirmed outside task %s's access scope", attack.ErrInconclusive, b.Name, taskID)
	}

	ownerList := e.listConfigs(ctx, clientA, endpoint, a.Headers, taskID, set, markerURL, vars.RandID+"-owner")
	if ownerList.found {
		otherList := e.listConfigs(ctx, clientB, endpoint, b.Headers, taskID, set, markerURL, vars.RandID+"-other")
		if otherList.found {
			findings = append(findings, e.finding(endpoint, a, b, taskID, set.id, markerURL, "list"))
		} else if !otherList.complete && !otherList.denied {
			partial = errors.Join(partial, fmt.Errorf("%w: cross-principal push-config list was unjudged", attack.ErrInconclusive))
		}
	} else if !ownerList.unsupported {
		partial = errors.Join(partial, fmt.Errorf("%w: owner push-config list did not confirm the marker", attack.ErrInconclusive))
	}

	if e.readConfig(ctx, clientA, endpoint, a.Headers, taskID, set, markerURL, vars.RandID+"-before-delete") != configPresent {
		return findings, fmt.Errorf("%w: owner marker was not present before the delete probe", attack.ErrInconclusive)
	}
	deleteReply := e.deleteConfig(ctx, clientB, endpoint, b.Headers, taskID, set, vars.RandID)
	readback := e.readConfig(ctx, clientA, endpoint, a.Headers, taskID, set, markerURL, vars.RandID+"-after-delete")
	if readback == configAbsent && e.readTask(ctx, clientA, endpoint, a.Headers, taskID, set.v1, vars.RandID+"-after-delete") == taskPresent {
		deleted = true
		if deleteReply == deleteAccepted {
			findings = append(findings, e.finding(endpoint, a, b, taskID, set.id, markerURL, "delete"))
		} else {
			deletionDetail = "absent after probe; deletion source unconfirmed"
			partial = errors.Join(partial, fmt.Errorf("%w: marker disappeared without a confirmed delete response", attack.ErrInconclusive))
		}
	} else if readback == configPresent && deleteReply != deleteDenied && deleteReply != deleteUnsupported {
		partial = errors.Join(partial, fmt.Errorf("%w: cross-principal delete was not conclusively denied", attack.ErrInconclusive))
	} else if readback == configUnknown {
		partial = errors.Join(partial, fmt.Errorf("%w: delete readback was unjudged", attack.ErrInconclusive))
	}
	return findings, nil
}

type taskAccess uint8

const (
	taskUnknown taskAccess = iota
	taskPresent
	taskDenied
)

func (e *PushLifecycleExecutor) readTask(ctx context.Context, c *attack.HTTPClient, endpoint string, headers map[string]string,
	taskID string, v1 bool, suffix string) taskAccess {
	method := "tasks/get"
	if v1 {
		method = "GetTask"
	}
	requestID := "batesian-pl-task-" + suffix
	resp, err := c.POST(ctx, endpoint, pushBindingHeaders(headers, v1), map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID, "method": method,
		"params": map[string]interface{}{"id": taskID, "historyLength": 1},
	})
	if err != nil || resp == nil {
		return taskUnknown
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return taskDenied
	}
	if !resp.IsSuccess() {
		return taskUnknown
	}
	_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid {
		return taskUnknown
	}
	if hasError {
		message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
		if code == -32001 || attack.AuthFlavoredMessage(message) ||
			strings.Contains(message, "not found") || strings.Contains(message, "not task owner") {
			return taskDenied
		}
		return taskUnknown
	}
	state, matched := taskStateForID(resp.Body, taskID)
	if matched && state != "" {
		return taskPresent
	}
	return taskUnknown
}

type configAccess uint8

const (
	configUnknown configAccess = iota
	configPresent
	configAbsent
)

func (e *PushLifecycleExecutor) readConfig(ctx context.Context, c *attack.HTTPClient, endpoint string, headers map[string]string,
	taskID string, set pushSet, markerURL, suffix string) configAccess {
	method, params := "tasks/pushNotificationConfig/get", map[string]interface{}{"id": taskID, "pushNotificationConfigId": set.id}
	if set.v1 {
		method, params = "GetTaskPushNotificationConfig", map[string]interface{}{"taskId": taskID, "id": set.id}
	}
	requestID := "batesian-pl-config-" + suffix
	resp, err := c.POST(ctx, endpoint, pushBindingHeaders(headers, set.v1), map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID, "method": method, "params": params,
	})
	if err != nil || resp == nil {
		return configUnknown
	}
	if resp.StatusCode == http.StatusNotFound {
		return configAbsent
	}
	if !resp.IsSuccess() {
		return configUnknown
	}
	result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid {
		return configUnknown
	}
	if hasError {
		if code == -32001 || strings.Contains(strings.ToLower(jsonRPCErrorMessage(resp.Body)), "not found") {
			return configAbsent
		}
		return configUnknown
	}
	var cfg struct {
		TaskID string `json:"taskId"`
		ID     string `json:"id"`
		URL    string `json:"url"`
		Nested *struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"pushNotificationConfig"`
	}
	if json.Unmarshal(result, &cfg) != nil || (cfg.TaskID != "" && cfg.TaskID != taskID) {
		return configUnknown
	}
	if set.v1 && cfg.ID == set.id && cfg.URL == markerURL {
		return configPresent
	}
	if !set.v1 && cfg.Nested != nil && cfg.Nested.ID == set.id && cfg.Nested.URL == markerURL {
		return configPresent
	}
	return configUnknown
}

type listAccess struct {
	found       bool
	complete    bool
	denied      bool
	unsupported bool
}

func (e *PushLifecycleExecutor) listConfigs(ctx context.Context, c *attack.HTTPClient, endpoint string, headers map[string]string,
	taskID string, set pushSet, markerURL, suffix string) listAccess {
	method := "tasks/pushNotificationConfig/list"
	if set.v1 {
		method = "ListTaskPushNotificationConfigs"
	}
	token := ""
	seen := map[string]bool{}
	for page := range 8 {
		params := map[string]interface{}{"id": taskID}
		if set.v1 {
			params = map[string]interface{}{"taskId": taskID, "pageSize": 25}
			if token != "" {
				params["pageToken"] = token
			}
		}
		requestID := fmt.Sprintf("batesian-pl-list-%s-%d", suffix, page)
		resp, err := c.POST(ctx, endpoint, pushBindingHeaders(headers, set.v1), map[string]interface{}{
			"jsonrpc": "2.0", "id": requestID, "method": method, "params": params,
		})
		if err != nil || resp == nil {
			return listAccess{}
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return listAccess{denied: true}
		}
		if resp.StatusCode == http.StatusMethodNotAllowed {
			return listAccess{unsupported: true}
		}
		if !resp.IsSuccess() {
			return listAccess{}
		}
		result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return listAccess{}
		}
		if hasError {
			if code == jsonRPCMethodNotFound || code == a2aPushNotSupported || code == a2aUnsupportedOperation {
				return listAccess{unsupported: true}
			}
			message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
			if code == -32001 || attack.AuthFlavoredMessage(message) ||
				strings.Contains(message, "not found") || strings.Contains(message, "not task owner") {
				return listAccess{denied: true}
			}
			return listAccess{}
		}
		var entries []json.RawMessage
		if set.v1 {
			result = bytes.TrimSpace(result)
			var pageResult map[string]json.RawMessage
			if len(result) == 0 || result[0] != '{' || json.Unmarshal(result, &pageResult) != nil {
				return listAccess{}
			}
			if raw, ok := pageResult["configs"]; ok {
				raw = bytes.TrimSpace(raw)
				if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &entries) != nil {
					return listAccess{}
				}
			}
			if raw, ok := pageResult["nextPageToken"]; ok {
				raw = bytes.TrimSpace(raw)
				if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &token) != nil {
					return listAccess{}
				}
			}
		} else if json.Unmarshal(result, &entries) != nil || entries == nil {
			return listAccess{}
		}
		for _, raw := range entries {
			raw = bytes.TrimSpace(raw)
			if len(raw) == 0 || raw[0] != '{' {
				return listAccess{}
			}
			var cfg struct {
				TaskID string `json:"taskId"`
				ID     string `json:"id"`
				URL    string `json:"url"`
				Nested *struct {
					ID  string `json:"id"`
					URL string `json:"url"`
				} `json:"pushNotificationConfig"`
			}
			if json.Unmarshal(raw, &cfg) != nil || (cfg.TaskID != "" && cfg.TaskID != taskID) {
				return listAccess{}
			}
			if set.v1 && cfg.URL == "" || !set.v1 && (cfg.Nested == nil || cfg.Nested.URL == "") {
				return listAccess{}
			}
			if set.v1 && cfg.ID == set.id && cfg.URL == markerURL ||
				!set.v1 && cfg.Nested != nil && cfg.Nested.ID == set.id && cfg.Nested.URL == markerURL {
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

type deleteAccess uint8

const (
	deleteUnknown deleteAccess = iota
	deleteAccepted
	deleteDenied
	deleteUnsupported
)

func (e *PushLifecycleExecutor) deleteConfig(ctx context.Context, c *attack.HTTPClient, endpoint string, headers map[string]string,
	taskID string, set pushSet, suffix string) deleteAccess {
	method, params := "tasks/pushNotificationConfig/delete", map[string]interface{}{"id": taskID, "pushNotificationConfigId": set.id}
	if set.v1 {
		method, params = "DeleteTaskPushNotificationConfig", map[string]interface{}{"taskId": taskID, "id": set.id}
	}
	requestID := "batesian-pl-delete-" + suffix
	resp, err := c.POST(ctx, endpoint, pushBindingHeaders(headers, set.v1), map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID, "method": method, "params": params,
	})
	if err != nil || resp == nil {
		return deleteUnknown
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return deleteDenied
	}
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return deleteUnsupported
	}
	if !resp.IsSuccess() {
		return deleteUnknown
	}
	_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid {
		return deleteUnknown
	}
	if !hasError {
		return deleteAccepted
	}
	if code == jsonRPCMethodNotFound || code == a2aPushNotSupported || code == a2aUnsupportedOperation {
		return deleteUnsupported
	}
	message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
	if code == -32001 || attack.AuthFlavoredMessage(message) ||
		strings.Contains(message, "not found") || strings.Contains(message, "not task owner") {
		return deleteDenied
	}
	return deleteUnknown
}

func (e *PushLifecycleExecutor) finding(endpoint string, owner, other attack.Principal, taskID, configID, markerURL, operation string) attack.Finding {
	title := "A2A push-notification configs listed outside task scope"
	detail := "listed the owner's scanner-created push config, including its callback URL"
	if operation == "delete" {
		title = "A2A push-notification config deleted outside task scope"
		detail = "deleted the owner's scanner-created push config"
	}
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.ConfirmedExploit,
		Title: title,
		Description: fmt.Sprintf("Principal %q could not read principal %q's task %s, but %s using its own credentials.",
			other.Name, owner.Name, taskID, detail),
		Evidence: fmt.Sprintf("owner: %s\nother principal: %s\ntask: %s\nconfig: %s\ncallback URL: %s\nGetTask control: denied for other principal\noperation: %s",
			owner.Name, other.Name, taskID, configID, markerURL, operation),
		Remediation: e.rule.Remediation, TargetURL: endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create task and push config", Outcome: "owner readback confirmed marker"},
			{Hop: 2, Principal: other.Name, Action: "get owner task", Outcome: "denied"},
			{Hop: 3, Principal: other.Name, Action: operation + " owner push config", Outcome: "granted"},
		},
	}
}
