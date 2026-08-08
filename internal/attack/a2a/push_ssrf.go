package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
func init() {
	attack.Register("push-notification-ssrf", func(rc attack.RuleContext) attack.Executor { return NewPushSSRFExecutor(rc) })
}

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
		if opts.DryRun {
			// A dry run must bind no socket; preview against a non-resolving
			// placeholder so the recorded plan still shows a callback URL.
			listenerURL = attack.DryRunOOBPlaceholderURL
		} else {
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
		}
		vars = attack.NewVars(target, listenerURL)
	}

	client := attack.NewHTTPClient(opts, vars)
	endpoint, endpointOK := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	reached := false
	callbackURL := listenerURL + "/batesian-" + vars.RandID
	token := "batesian-" + vars.RandID

	// Try multiple transport bindings and SDK versions.
	// Note: A JSON-RPC error response (e.g. -32601 Method Not Found) is not a
	// task acceptance. IsAccepted requires a real result envelope, which excludes
	// both error envelopes and non-JSON 2xx bodies (login pages, empty acks).
	var taskAccepted bool
	var acceptedBinding string

	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	// Attempt 1: A2A-sdk v1.0 two-step: SendMessage then CreateTaskPushNotificationConfig
	sendResp, err := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
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
	if err == nil && sendResp.StatusCode != 404 {
		reached = true
	}
	// Why no binding accepted a push registration. Classified from the responses the
	// attempts below already have, so a refused credential is not reported as "this
	// agent does not fetch attacker-controlled callbacks".
	var obs setupObservation
	credentialed := client.PresentsCredential(endpoint)
	if err != nil || !sendResp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a task to attach a push config to", endpoint, credentialed, sendResp))
	}
	if err == nil && sendResp.IsAccepted() {
		// Got a task - try to register push notification config for it
		taskID, _ := extractTaskContext(sendResp.Body)
		if taskID != "" {
			// params IS a TaskPushNotificationConfig, whose fields are taskId,
			// url, token, id, tenant and authentication. The callback is named
			// url; there is no pushNotificationUrl, and sending one earns
			// -32602 "has no field named" from a2a-sdk v1, so this step never
			// registered anything against a real v1 agent.
			pushResp, pushErr := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "batesian-push-" + vars.RandID,
				"method":  "CreateTaskPushNotificationConfig",
				"params": map[string]interface{}{
					"taskId": taskID,
					"url":    callbackURL,
					"token":  token,
				},
			})
			if pushErr == nil && pushResp.IsAccepted() {
				taskAccepted = true
				acceptedBinding = "JSONRPC/v1.0-CreateTaskPushNotificationConfig"
			}
		}
	}

	// Attempt 2: JSON-RPC v0.3. message/send carries the callback inline under
	// configuration, and tasks/pushNotificationConfig/set registers it against a
	// task that already exists. Both are tried because a server may ignore the
	// inline form.
	//
	// This used to send tasks/send, a v0.2-era method name. a2a-sdk answers it
	// -32601 Method not found, so the whole v0.3 path was dead against any
	// current server.
	if !taskAccepted {
		sendResp2, err2 := client.POST(ctx, endpoint, map[string]string{}, buildV03SendRequest(callbackURL, token, vars.RandID))
		if err2 == nil && sendResp2.StatusCode != 404 {
			reached = true
		}
		if err2 != nil || !sendResp2.IsAccepted() {
			obs.observe(classifyTaskSetup("creating a task on the v0.3 wire", endpoint, credentialed, sendResp2))
		}
		if err2 == nil && sendResp2.IsAccepted() {
			// A task id is what makes this a registration rather than a plain
			// echo: an agent that answers with a Message has nothing to attach a
			// push config to, and claiming otherwise would have the rule wait
			// for a callback nobody agreed to send.
			if taskID, _ := extractTaskContext(sendResp2.Body); taskID != "" {
				taskAccepted = true
				acceptedBinding = "JSONRPC/v0.3-message-send"

				setResp, setErr := client.POST(ctx, endpoint, map[string]string{}, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      "batesian-set-" + vars.RandID,
					"method":  "tasks/pushNotificationConfig/set",
					"params": map[string]interface{}{
						"taskId": taskID,
						"pushNotificationConfig": map[string]string{
							"url":   callbackURL,
							"token": token,
						},
					},
				})
				if setErr == nil && setResp.IsAccepted() {
					acceptedBinding = "JSONRPC/v0.3-pushNotificationConfig-set"
				}
			}
		}
	}

	// Attempt 3: the HTTP+JSON (REST) binding, where the card advertises one.
	//
	// This used to POST a fixed /tasks/send. No such route exists: the REST
	// binding names its methods message:send and
	// tasks/{id}/pushNotificationConfigs, and a2a-sdk answers /tasks/send 404.
	// Nor can the prefix be guessed, since the deployment chooses it and chooses
	// which protocol version sits under it. So the base comes from the card, and
	// an agent that advertises no HTTP+JSON interface is not probed at all.
	if restBase := resolveHTTPJSONBase(ctx, client, vars.BaseURL); !taskAccepted && restBase != "" {
		sendResp3, err3 := client.POST(ctx, restBase+"/message:send", map[string]string{"A2A-Version": "1.0"},
			buildRESTSendRequest(vars.RandID))
		if err3 == nil && sendResp3.StatusCode != 404 {
			reached = true
		}
		// The REST binding answers with a task object rather than a JSON-RPC
		// envelope, so IsAccepted is the wrong test. An explicit error body still
		// has to be excluded: without that, any service answering 200 with a JSON
		// error counts as having accepted a task, and the rule goes on to wait
		// for a callback that was never registered.
		if err3 == nil && sendResp3.IsSuccess() && sendResp3.IsJSON() && !isJSONRPCError(sendResp3.Body) {
			// As on JSON-RPC v1.0, the callback cannot ride along with the send:
			// the configuration block has no push field. It is registered against
			// the task that came back.
			if taskID := restTaskID(sendResp3.Body); taskID != "" {
				cfgResp, cfgErr := client.POST(ctx, restBase+"/tasks/"+taskID+"/pushNotificationConfigs",
					map[string]string{"A2A-Version": "1.0"},
					map[string]interface{}{"url": callbackURL, "token": token})
				if cfgErr == nil && cfgResp.IsSuccess() && cfgResp.IsJSON() && !isJSONRPCError(cfgResp.Body) {
					taskAccepted = true
					acceptedBinding = "HTTP+JSON/pushNotificationConfigs"
				}
			}
		}
	}

	if !taskAccepted {
		// Target doesn't accept A2A task requests. If nothing was reachable at all,
		// the rule could not be exercised; otherwise it is simply not applicable.
		if !reached {
			return nil, attack.ErrInconclusive
		}
		// reached only records a response that was not a 404, which any JSON-RPC
		// service satisfies. Confirm the target is an A2A agent before calling
		// this not applicable.
		if err := notTestableGiven(ctx, client, vars.BaseURL, endpointOK); err != nil {
			return nil, err
		}
		// It is an A2A agent that accepted no push registration. "Push is not
		// supported here" is a genuine not-applicable and stays clean; a refused
		// credential is not, because this rule's clean result claims the agent does
		// not fetch attacker-controlled callback URLs and nothing was ever registered
		// to find out.
		return nil, obs.err()
	}

	// Wait for OOB callback.
	var findings []attack.Finding
	if listener != nil {
		cb, received := listener.WaitForMarker(ctx, 10*time.Second, token)
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
		}
		// No callback on our own listener => SSRF was not demonstrated. Accepting
		// a push-notification config is a normal A2A feature, so we deliberately
		// emit NO finding here rather than flag by-design behaviour.
	} else {
		// Using external OOB - report task accepted, user must check their OOB server.
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

// buildV03SendRequest creates a v0.3 message/send carrying the push callback in
// the configuration block, which is where that revision puts it. There is no
// equivalent on the v1.0 side: SendMessageConfiguration has no
// pushNotificationConfig field, so v1.0 registers the callback only through the
// separate CreateTaskPushNotificationConfig call.
func buildV03SendRequest(callbackURL, token, randID string) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-" + randID,
		"method":  "message/send",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      "user",
				"messageId": "batesian-" + randID,
				"parts": []interface{}{
					map[string]string{"kind": "text", "text": "ping"},
				},
			},
			"configuration": map[string]interface{}{
				"pushNotificationConfig": map[string]string{
					"url":   callbackURL,
					"token": token,
				},
			},
		},
	}
}

// restTaskID pulls the task id out of a REST message:send reply. The REST
// binding has no JSON-RPC envelope, so extractTaskContext, which requires a
// result object, finds nothing here. a2a-sdk answers with the SendMessageResponse
// oneof, {"task":{...}}; the bare task object is accepted too, since the wrapper
// is a proto detail rather than something the binding guarantees.
func restTaskID(body []byte) string {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if task, ok := m["task"].(map[string]interface{}); ok {
		if id, _ := task["id"].(string); id != "" {
			return id
		}
	}
	id, _ := m["id"].(string)
	return id
}

// buildRESTSendRequest creates the body for a REST message:send. It is a
// SendMessageRequest, so the message sits under `message` and carries no push
// config; the callback is registered separately against the returned task.
func buildRESTSendRequest(randID string) map[string]interface{} {
	return map[string]interface{}{
		"message": map[string]interface{}{
			"messageId": "batesian-" + randID,
			"role":      "ROLE_USER",
			"parts": []interface{}{
				map[string]string{"text": "ping"},
			},
		},
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
		return strings.Contains(string(b), token)
	}
	return strings.Contains(string(cb.Body), token)
}
