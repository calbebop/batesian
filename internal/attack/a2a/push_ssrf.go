package a2a

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	endpointpkg "github.com/calbebop/batesian/internal/endpoint"
	"github.com/calbebop/batesian/internal/oob"
)

// PushSSRFExecutor checks delivery to private push callback destinations.
type PushSSRFExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("push-notification-ssrf", func(rc attack.RuleContext) attack.Executor { return NewPushSSRFExecutor(rc) })
}

func NewPushSSRFExecutor(r attack.RuleContext) *PushSSRFExecutor {
	return &PushSSRFExecutor{rule: r}
}

// Execute runs the push-notification SSRF test.
func (e *PushSSRFExecutor) Execute(ctx context.Context, target string, opts attack.Options) (findings []attack.Finding, err error) {
	ctx = withTenantRouting(ctx)
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
	var registration *pushRegistration
	defer func() {
		if line := registration.finish(ctx, client, opts.TargetState, opts.OOBListenerURL != ""); line != "" {
			for i := range findings {
				findings[i].Evidence += "\n" + line
			}
		}
	}()
	endpoint, endpointOK := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	reached := false
	callbackURL := listenerURL + "/batesian-" + vars.RandID
	token := "batesian-" + vars.RandID

	// Try multiple transport bindings and SDK versions.
	// Note: A JSON-RPC error response (e.g. -32601 Method Not Found) is not a
	// task acceptance. IsAccepted requires a real result envelope, which excludes
	// both error envelopes and non-JSON 2xx bodies (login pages, empty acks).
	var taskAccepted bool
	var registrationConfirmed bool
	var acceptedBinding string
	var obs pushSetupObservation
	defer func() {
		if taskAccepted {
			err = errors.Join(err, obs.partialErr())
		}
	}()

	a2aHeaders := map[string]string{"A2A-Version": "1.0"}
	sendID := "batesian-sm-" + vars.RandID
	pushID := "batesian-push-" + vars.RandID
	legacyID := "batesian-" + vars.RandID
	setID := "batesian-set-" + vars.RandID

	// Attempt 1: A2A-sdk v1.0 two-step: SendMessage then CreateTaskPushNotificationConfig
	sendResp, err := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      sendID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role":      1, // USER
				"parts":     []interface{}{map[string]string{"text": "ping"}},
				"messageId": "batesian-" + vars.RandID,
			},
		},
	})
	if err == nil && sendResp != nil && sendResp.StatusCode != 404 {
		reached = true
	}
	// Why no binding accepted a push registration. Classified from the responses the
	// attempts below already have, so a refused credential is not reported as "this
	// agent does not fetch attacker-controlled callbacks".
	credentialed := client.PresentsCredential(endpoint)
	taskID := pushTaskReplyID(sendResp, sendID)
	if err != nil || taskID == "" {
		obs.observe(pushTaskSetupOutcome("creating a task to attach a push config to", endpoint, credentialed, sendResp, sendID))
	}
	if err == nil && taskID != "" {
		// The v1 config uses url, not pushNotificationUrl.
		pushResp, pushErr := client.POST(ctx, endpoint, a2aHeaders, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      pushID,
			"method":  "CreateTaskPushNotificationConfig",
			"params": map[string]interface{}{
				"taskId": taskID,
				"id":     "batesian-" + vars.RandID,
				"url":    callbackURL,
				"token":  token,
			},
		})
		if pushErr == nil && pushRegistrationReplyAccepted(pushResp, pushID, "CreateTaskPushNotificationConfig", taskID, callbackURL) {
			taskAccepted = true
			registrationConfirmed = true
			acceptedBinding = "JSONRPC/v1.0-CreateTaskPushNotificationConfig"
			registration = newPushRegistration(endpoint, taskID, "1.0", callbackURL, pushResp, false)
		} else {
			obs.observe(pushRegistrationOutcome("CreateTaskPushNotificationConfig", pushResp, pushID, taskID, callbackURL))
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
		if err2 == nil && sendResp2 != nil && sendResp2.StatusCode != 404 {
			reached = true
		}
		taskID := pushTaskReplyID(sendResp2, legacyID)
		if err2 != nil || taskID == "" {
			obs.observe(pushTaskSetupOutcome("creating a task on the v0.3 wire", endpoint, credentialed, sendResp2, legacyID))
		}
		if err2 == nil && taskID != "" {
			// Only a Task can carry a push registration.
			taskAccepted = true
			acceptedBinding = "JSONRPC/v0.3-message-send"
			recordPossiblePushConfig(opts.TargetState, endpoint, taskID)

			setResp, setErr := client.POST(ctx, endpoint, map[string]string{}, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      setID,
				"method":  "tasks/pushNotificationConfig/set",
				"params": map[string]interface{}{
					"taskId": taskID,
					"pushNotificationConfig": map[string]string{
						"id":    "batesian-" + vars.RandID,
						"url":   callbackURL,
						"token": token,
					},
				},
			})
			if setErr == nil && pushRegistrationReplyAccepted(setResp, setID, "tasks/pushNotificationConfig/set", taskID, callbackURL) {
				registrationConfirmed = true
				acceptedBinding = "JSONRPC/v0.3-pushNotificationConfig-set"
				registration = newPushRegistration(endpoint, taskID, "0.3.0", callbackURL, setResp, false)
			} else {
				obs.observe(pushRegistrationOutcome("tasks/pushNotificationConfig/set", setResp, setID, taskID, callbackURL))
			}
		}
	}

	// Attempt 3: try the card's REST bases in preference order.
	if !taskAccepted {
		for _, restBase := range resolveHTTPJSONBases(ctx, client, vars.BaseURL) {
			for _, route := range restPushRoutes {
				headers := restVersionHeaders(route.version, nil)
				sendURL := endpointpkg.AppendPath(restBase, route.sendPath)
				sendResp3, err3 := client.POST(ctx, sendURL, headers,
					restTaskSendRequest(vars.RandID, "ping", route.version))
				if err3 == nil && sendResp3 != nil && sendResp3.StatusCode != 404 {
					reached = true
				}
				taskID := ""
				if err3 == nil {
					taskID = restPushTaskID(sendResp3)
				}
				if taskID != "" {
					cfgURL := endpointpkg.AppendPath(restBase, route.configPath(taskID))
					cfgResp, cfgErr := client.POST(ctx, cfgURL, headers,
						restPushConfigRequest(taskID, callbackURL, token, "", vars.RandID, route.version))
					if cfgErr == nil && restPushRegistrationReplyAccepted(cfgResp, taskID, callbackURL, route.version) {
						taskAccepted = true
						registrationConfirmed = true
						acceptedBinding = "HTTP+JSON/" + route.version + "-pushNotificationConfigs"
						registration = newPushRegistration(cfgURL, taskID, route.version, callbackURL, cfgResp, true)
					} else {
						obs.observe(restPushRegistrationOutcome("HTTP+JSON/"+route.version+" pushNotificationConfigs",
							cfgResp, taskID, callbackURL, route.version))
					}
				} else {
					obs.observe(classifyRESTPushTaskSetup("creating a task on the HTTP+JSON/"+route.version+" wire",
						sendURL, client.PresentsCredential(sendURL), sendResp3))
				}
				if taskAccepted {
					break
				}
			}
			if taskAccepted {
				break
			}
		}
	}
	if !taskAccepted && listener != nil {
		inlineID := "batesian-sm-inline-" + vars.RandID
		inlineResp, inlineErr := client.POST(ctx, endpoint, a2aHeaders,
			buildV1InlineSendRequest(callbackURL, token, "", vars.RandID))
		if inlineErr == nil && inlineResp != nil && inlineResp.StatusCode != 404 {
			reached = true
		}
		inlineTaskID := pushTaskReplyID(inlineResp, inlineID)
		if inlineErr == nil && inlineTaskID != "" {
			taskAccepted = true
			acceptedBinding = "JSONRPC/v1.0-SendMessage-inline"
			recordPossiblePushConfig(opts.TargetState, endpoint, inlineTaskID)
		} else {
			obs.observe(pushTaskSetupOutcome("sending a task with inline push configuration", endpoint,
				credentialed, inlineResp, inlineID))
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
	if listener != nil {
		cb, received := listener.WaitForMarker(ctx, 10*time.Second, token)
		if !received {
			return nil, fmt.Errorf("%w: no push callback observed after registration; the listener may be unreachable or delivery delayed",
				attack.ErrInconclusive)
		}
		if privatePushCallbackURL(callbackURL) {
			evidence := fmt.Sprintf(
				"Target accepted task with pushNotificationConfig.url=%q (binding: %s)\n"+
					"OOB callback received: %s %s",
				callbackURL, acceptedBinding, cb.Method, cb.URL,
			)
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      "A2A agent reached a local or private push callback address",
				Description: fmt.Sprintf("The A2A server at %s made an HTTP request to the local or private callback address %s. "+
					"The probe demonstrates reachability to this address; access to other internal services was not tested.",
					target, callbackURL),
				Evidence:    evidence,
				Remediation: e.rule.Remediation,
				TargetURL:   target,
			})
		}
		// A public callback does not prove private reachability.
	} else {
		if !registrationConfirmed && !opts.DryRun {
			return nil, fmt.Errorf("%w: inline push registration was not confirmed and delivery was not observed", attack.ErrInconclusive)
		}
		// Using external OOB - report task accepted, user must check their OOB server.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "info",
			Confidence: attack.RiskIndicator,
			Title:      "A2A push callback registered; delivery unverified",
			Description: fmt.Sprintf("Task submitted with pushNotificationConfig.url=%q (binding: %s). "+
				"Check your OOB server at %s for delivery. A public webhook callback alone does not establish SSRF.",
				callbackURL, acceptedBinding, opts.OOBListenerURL),
			Evidence:    fmt.Sprintf("Task accepted via %s. Callback URL: %s", acceptedBinding, callbackURL),
			Remediation: e.rule.Remediation,
			TargetURL:   target,
		})
	}
	return findings, nil
}

func classifyRESTPushTaskSetup(what, url string, credentialed bool, resp *attack.Response) setupObservation {
	if resp != nil {
		switch resp.StatusCode {
		case 404, 405:
			return setupObservation{rank: setupFeatureAbsent}
		case 401, 403:
			return classifyTaskSetup(what, url, credentialed, resp)
		}
		if !resp.IsSuccess() {
			return setupObservation{rank: setupOtherRefusal,
				reason: fmt.Sprintf("%s at %s returned HTTP %d without a task", what, url, resp.StatusCode)}
		}
	}
	return classifyTaskSetup(what, url, credentialed, resp)
}

func privatePushCallbackURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func buildV1InlineSendRequest(callbackURL, token, credential, randID string) map[string]interface{} {
	config := map[string]interface{}{"url": callbackURL, "token": token}
	if credential != "" {
		config["authentication"] = map[string]string{"scheme": "Bearer", "credentials": credential}
	}
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-sm-inline-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{
				"returnImmediately":          true,
				"taskPushNotificationConfig": config,
			},
			"message": map[string]interface{}{
				"role":      "ROLE_USER",
				"parts":     []interface{}{map[string]string{"text": "ping"}},
				"messageId": "batesian-inline-" + randID,
			},
		},
	}
}

// buildV03SendRequest creates a v0.3 message/send with an inline callback.
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

// restTaskID reads a Task from a REST message:send reply.
func restTaskID(body []byte) string {
	id, _ := taskResultContext(body)
	return id
}

type restPushRoute struct {
	version  string
	sendPath string
	taskPath string
}

var restPushRoutes = []restPushRoute{
	{version: "1.0", sendPath: "/message:send", taskPath: "/tasks"},
	{version: "0.3.0", sendPath: "/v1/message:send", taskPath: "/v1/tasks"},
}

func (r restPushRoute) configPath(taskID string) string {
	return r.taskPath + "/" + url.PathEscape(taskID) + "/pushNotificationConfigs"
}

func restPushConfigRequest(taskID, callbackURL, token, credential, randID, version string) map[string]interface{} {
	if version == "1.0" {
		config := map[string]interface{}{"id": "batesian-" + randID, "url": callbackURL, "token": token}
		if credential != "" {
			config["authentication"] = map[string]string{"scheme": "Bearer", "credentials": credential}
		}
		return config
	}
	push := map[string]interface{}{"id": "batesian-" + randID, "url": callbackURL, "token": token}
	if credential != "" {
		push["authentication"] = map[string]interface{}{"schemes": []string{"Bearer"}, "credentials": credential}
	}
	configID := "batesian-" + randID
	return map[string]interface{}{
		"parent":   "tasks/" + taskID,
		"configId": configID,
		"config": map[string]interface{}{
			"name":                   "tasks/" + taskID + "/pushNotificationConfigs/" + configID,
			"pushNotificationConfig": push,
		},
	}
}
