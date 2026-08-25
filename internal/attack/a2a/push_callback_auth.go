package a2a

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/oob"
)

// PushCallbackAuthExecutor tests whether an A2A agent's outgoing push
// notifications carry anything a receiver can use to verify where they came
// from (rule a2a-push-callback-auth-001).
//
// The push flow hands the agent a webhook plus, optionally, a secret token
// the agent is supposed to present when it calls. A receiver that knows the
// token can tell genuine completion events from forged ones; without it,
// anyone who learns the webhook URL can spoof task completions, failures or
// injected results - the notification-side half of the task-hijack class.
//
// The probe registers a callback toward the Batesian listener carrying a
// unique secret, waits for the agent's outbound call, and reads what
// arrived:
//
//   - callback carries the secret (X-A2A-Notification-Token, another header,
//     or the body) -> the transport is verifiable, no finding
//   - callback arrives WITHOUT the secret -> confirmed: the agent ignored the
//     integrity material it accepted at registration, so its notifications
//     are indistinguishable from forgeries
//   - no callback within the window -> the oracle never ran; reported as not
//     tested rather than clean
//
// Registration mechanics are shared with a2a-push-ssrf-001; the marker in the
// URL path and the integrity token are deliberately different values here,
// because conflating them made "the callback arrived" and "the callback was
// authenticated" the same observation.
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

	// Marker and token are separate on purpose: the marker routes the callback
	// to this run, the token is what the agent is expected to present back.
	callbackURL := listenerURL + "/batesian-oob-" + vars.RandID
	token := "batesian-token-" + vars.RandID
	a2aHeaders := map[string]string{"A2A-Version": "1.0"}

	var obs setupObservation
	credentialed := client.PresentsCredential(endpoint)
	taskAccepted := false
	acceptedBinding := ""

	// Attempt 1: v1.0 two-step - SendMessage, then CreateTaskPushNotificationConfig
	// whose params ARE a TaskPushNotificationConfig (flat url + token).
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
				},
			})
			if pushErr == nil && pushResp.IsAccepted() {
				taskAccepted = true
				acceptedBinding = "JSONRPC/v1.0-CreateTaskPushNotificationConfig"
			}
		}
	}

	// Attempt 2: v0.3 wire - inline configuration on message/send, plus the
	// explicit set call for servers that ignore the inline form.
	if !taskAccepted {
		sendResp2, err2 := client.POST(ctx, endpoint, map[string]string{}, buildV03SendRequest(callbackURL, token, vars.RandID))
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

	// Attempt 3: HTTP+JSON binding, driven only where the card advertises one.
	if restBase := resolveHTTPJSONBase(ctx, client, vars.BaseURL); !taskAccepted && restBase != "" {
		sendResp3, err3 := client.POST(ctx, restBase+"/message:send", map[string]string{"A2A-Version": "1.0"},
			buildRESTSendRequest(vars.RandID))
		if err3 == nil && sendResp3.StatusCode != 404 {
			reached = true
		}
		if err3 == nil && sendResp3.IsSuccess() && sendResp3.IsJSON() && !isJSONRPCError(sendResp3.Body) {
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
			Title:      "A2A push config accepted with integrity token; manual verification required",
			Description: fmt.Sprintf(
				"The agent accepted a push config whose callback (%s) carries a unique integrity "+
					"token via %s. Check your OOB collector for the inbound call and confirm it presents "+
					"the token %q (typically as X-A2A-Notification-Token, sometimes in the body). A call "+
					"without it means notifications cannot be authenticated by receivers and forged "+
					"completions are indistinguishable from real ones.",
				callbackURL, acceptedBinding, token),
			Evidence:    fmt.Sprintf("registration binding: %s\ncallback url: %s\nexpected token: %s", acceptedBinding, callbackURL, token),
			Remediation: e.rule.Remediation,
			TargetURL:   target,
		}}, nil
	}

	cb, received := listener.WaitForMarker(ctx, 10*time.Second, "/batesian-oob-"+vars.RandID)
	if !received {
		return nil, fmt.Errorf("%w: the push config was accepted via %s but no callback reached the "+
			"listener within 10s, so the transport's provenance material could not be observed",
			attack.ErrInconclusive, acceptedBinding)
	}

	authz := callbackHeader(cb, "Authorization")
	tokenEchoed := containsToken(cb, token)
	if tokenEchoed {
		// The receiver side can authenticate the call: the boundary held, and a
		// held boundary is exactly the pass sought. Silent.
		return nil, nil
	}

	evidence := fmt.Sprintf(
		"registration binding: %s\nconfigured token: %s\ncallback received: %s %s\n"+
			"token echoed: no\nAuthorization header present: %s\nbody snippet: %.200s",
		acceptedBinding, token, cb.Method, cb.URL, yesNo(authz != ""), string(cb.Body))

	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A push notification sent without the configured integrity token",
		Description: fmt.Sprintf(
			"The agent at %s accepted a push config carrying a unique integrity token, then called the "+
				"webhook WITHOUT presenting it (binding: %s). Receivers have nothing to verify, so any "+
				"party who learns or guesses the webhook URL can forge task completions, failures or "+
				"injected results and they will be indistinguishable from genuine agent output. This is "+
				"the notification-side enabler of task hijacking.",
			target, acceptedBinding),
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   target,
	}}, nil
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
