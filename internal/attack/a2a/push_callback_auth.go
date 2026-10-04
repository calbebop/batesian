package a2a

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	endpointpkg "github.com/calbebop/batesian/internal/endpoint"
	"github.com/calbebop/batesian/internal/oob"
)

// PushCallbackAuthExecutor checks whether task notifications carry the
// configured webhook authentication credentials.
type PushCallbackAuthExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-push-callback-auth", func(rc attack.RuleContext) attack.Executor { return NewPushCallbackAuthExecutor(rc) })
}

func NewPushCallbackAuthExecutor(r attack.RuleContext) *PushCallbackAuthExecutor {
	return &PushCallbackAuthExecutor{rule: r}
}

func (e *PushCallbackAuthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)

	listenerURL := opts.OOBListenerURL
	var listener *oob.Listener
	if listenerURL == "" {
		if opts.DryRun {
			listenerURL = attack.DryRunOOBPlaceholderURL
		} else {
			listener = oob.New()
			var err error
			listenerURL, err = listener.Start()
			if err != nil {
				return nil, fmt.Errorf("push-callback-auth: starting OOB listener: %w", err)
			}
			defer func() {
				stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = listener.Stop(stopCtx)
			}()
		}
		vars = attack.NewVars(target, listenerURL)
	}

	client := attack.NewHTTPClient(opts, vars)
	endpoint, endpointOK := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	reached := false

	// Keep the callback marker, optional token, and Bearer credential distinct.
	callbackURL := listenerURL + "/batesian-oob-" + vars.RandID
	token := "batesian-token-" + vars.RandID
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("push-callback-auth: generating webhook credential: %w", err)
	}
	credential := hex.EncodeToString(secret)
	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	var obs setupObservation
	credentialed := client.PresentsCredential(endpoint)
	taskAccepted := false
	acceptedBinding := ""
	acceptedTaskID := ""

	// v1.0: create a task, then register its push configuration.
	sendResp, err := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-sm-" + vars.RandID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1,
				"parts":     []interface{}{map[string]string{"text": "ping"}},
				"messageId": "batesian-" + vars.RandID,
			},
		},
	})
	if err == nil && sendResp.StatusCode != 404 {
		reached = true
	}
	if err != nil || !sendResp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a task to attach a push config to", endpoint, credentialed, sendResp))
	}
	if err == nil && sendResp.IsAccepted() {
		if taskID, _ := extractTaskContext(sendResp.Body); taskID != "" {
			pushResp, pushErr := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-push-" + vars.RandID,
				"method":  "CreateTaskPushNotificationConfig",
				"params": map[string]interface{}{
					"taskId": taskID,
					"url":    callbackURL,
					"token":  token,
					"authentication": map[string]string{
						"scheme": "Bearer", "credentials": credential,
					},
				},
			})
			if pushErr == nil && pushResp.IsAccepted() {
				taskAccepted = true
				acceptedBinding = "JSONRPC/v1.0-CreateTaskPushNotificationConfig"
				acceptedTaskID = taskID
			}
		}
	}

	// Attempt 2: v0.3 wire - inline configuration on message/send, plus the
	// explicit set call for servers that ignore the inline form.
	if !taskAccepted {
		sendResp2, err2 := client.POST(ctx, endpoint, map[string]string{}, buildV03AuthSendRequest(callbackURL, token, credential, vars.RandID))
		if err2 == nil && sendResp2.StatusCode != 404 {
			reached = true
		}
		if err2 != nil || !sendResp2.IsAccepted() {
			obs.observe(classifyTaskSetup("creating a task on the v0.3 wire", endpoint, credentialed, sendResp2))
		}
		if err2 == nil && sendResp2.IsAccepted() {
			if taskID, _ := extractTaskContext(sendResp2.Body); taskID != "" {
				taskAccepted = true
				acceptedBinding = "JSONRPC/v0.3-message-send"
				acceptedTaskID = taskID
				setResp, setErr := client.POST(ctx, endpoint, map[string]string{}, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      "batesian-set-" + vars.RandID,
					"method":  "tasks/pushNotificationConfig/set",
					"params": map[string]interface{}{
						"taskId": taskID,
						"pushNotificationConfig": map[string]interface{}{
							"url":   callbackURL,
							"token": token,
							"authentication": map[string]interface{}{
								"schemes": []string{"Bearer"}, "credentials": credential,
							},
						},
					},
				})
				if setErr == nil && setResp.IsAccepted() {
					acceptedBinding = "JSONRPC/v0.3-pushNotificationConfig-set"
				}
			}
		}
	}

	// Attempt 3: HTTP+JSON binding, driven only where the card advertises one.
	if !taskAccepted {
		for _, restBase := range resolveHTTPJSONBases(ctx, client, vars.BaseURL) {
			sendResp3, err3 := client.POST(ctx, endpointpkg.AppendPath(restBase, "/message:send"), map[string]string{"A2A-Version": "1.0"},
				buildRESTSendRequest(vars.RandID))
			if err3 == nil && sendResp3.StatusCode != 404 {
				reached = true
			}
			if err3 == nil && sendResp3.IsSuccess() && sendResp3.IsJSON() && !isJSONRPCError(sendResp3.Body) {
				if taskID := restTaskID(sendResp3.Body); taskID != "" {
					cfgResp, cfgErr := client.POST(ctx, endpointpkg.AppendPath(restBase, "/tasks/"+taskID+"/pushNotificationConfigs"),
						map[string]string{"A2A-Version": "1.0"},
						map[string]interface{}{
							"url": callbackURL, "token": token,
							"authentication": map[string]string{"scheme": "Bearer", "credentials": credential},
						})
					if cfgErr == nil && cfgResp.IsSuccess() && cfgResp.IsJSON() && !isJSONRPCError(cfgResp.Body) {
						taskAccepted = true
						acceptedBinding = "HTTP+JSON/pushNotificationConfigs"
						acceptedTaskID = taskID
					}
				}
			}
			if taskAccepted {
				break
			}
		}
	}

	if !taskAccepted {
		if !reached {
			return nil, attack.ErrInconclusive
		}
		if err := notTestableGiven(ctx, client, vars.BaseURL, endpointOK); err != nil {
			return nil, err
		}
		return nil, obs.err()
	}

	// The registration was accepted. What the rule has to say depends entirely
	// on what the callback carried - or on whether one can be observed at all.
	if listener == nil {
		if opts.DryRun {
			// A dry run sends nothing and observes nothing; the recorded plan
			// already shows the callback request.
			return nil, nil
		}
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "info",
			Confidence: attack.RiskIndicator,
			Title:      "A2A push config accepted with webhook authentication; manual verification required",
			Description: fmt.Sprintf(
				"The agent accepted a push config via %s. Check your OOB collector for a task %s "+
					"notification to %s with Authorization: Bearer %s.",
				acceptedBinding, acceptedTaskID, callbackURL, credential),
			Evidence:    fmt.Sprintf("registration binding: %s\ncallback url: %s\ntask id: %s\nexpected bearer credential: %s", acceptedBinding, callbackURL, acceptedTaskID, credential),
			Remediation: e.rule.Remediation,
			TargetURL:   target,
		}}, nil
	}

	deadline := time.Now().Add(10 * time.Second)
	var cb *oob.Callback
	for time.Until(deadline) > 0 {
		candidate, received := listener.WaitForMarker(ctx, time.Until(deadline), "/batesian-oob-"+vars.RandID)
		if !received {
			break
		}
		if isTaskNotification(candidate, acceptedTaskID) {
			cb = candidate
			break
		}
	}
	if cb == nil {
		return nil, fmt.Errorf("%w: no task notification for %s reached the listener within 10s", attack.ErrInconclusive, acceptedTaskID)
	}

	authz := callbackHeader(cb, "Authorization")
	if bearerCredentialPresent(authz, credential) {
		return nil, nil
	}

	evidence := fmt.Sprintf(
		"registration binding: %s\ntask id: %s\ncallback received: %s %s\n"+
			"Authorization header present: %s\nconfigured Bearer credential matched: no",
		acceptedBinding, acceptedTaskID, cb.Method, cb.URL, yesNo(authz != ""))

	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A push notification sent without configured webhook authentication",
		Description: fmt.Sprintf(
			"The agent at %s accepted a push config with Bearer authentication, then sent a task "+
				"notification without the configured credential (binding: %s). A receiver expecting "+
				"that credential cannot authenticate the notification.",
			target, acceptedBinding),
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   target,
	}}, nil
}

func buildV03AuthSendRequest(callbackURL, token, credential, randID string) map[string]interface{} {
	request := buildV03SendRequest(callbackURL, token, randID)
	params := request["params"].(map[string]interface{})
	config := params["configuration"].(map[string]interface{})
	config["pushNotificationConfig"] = map[string]interface{}{
		"url": callbackURL, "token": token,
		"authentication": map[string]interface{}{
			"schemes": []string{"Bearer"}, "credentials": credential,
		},
	}
	return request
}

func isTaskNotification(cb *oob.Callback, taskID string) bool {
	if cb == nil || cb.Method != http.MethodPost || taskID == "" {
		return false
	}
	var body struct {
		Kind   string `json:"kind"`
		ID     string `json:"id"`
		TaskID string `json:"taskId"`
		Task   struct {
			ID string `json:"id"`
		} `json:"task"`
		StatusUpdate struct {
			TaskID string `json:"taskId"`
		} `json:"statusUpdate"`
		ArtifactUpdate struct {
			TaskID string `json:"taskId"`
		} `json:"artifactUpdate"`
		Message struct {
			TaskID string `json:"taskId"`
		} `json:"message"`
		Status json.RawMessage `json:"status"`
	}
	if json.Unmarshal(cb.Body, &body) != nil {
		return false
	}
	if body.Task.ID == taskID || body.StatusUpdate.TaskID == taskID ||
		body.ArtifactUpdate.TaskID == taskID || body.Message.TaskID == taskID {
		return true
	}
	return body.TaskID == taskID && (body.Kind == "status-update" || body.Kind == "artifact-update") ||
		body.ID == taskID && (body.Kind == "task" || len(body.Status) > 0)
}

func bearerCredentialPresent(header, credential string) bool {
	parts := strings.Fields(header)
	return len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] == credential
}

// callbackHeader reads a single header value case-insensitively off a
// captured callback.
func callbackHeader(cb *oob.Callback, name string) string {
	for k, vals := range cb.Headers {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
