package a2a

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
	protocola2a "github.com/calbebop/batesian/internal/protocol/a2a"
)

// ExtensionDowngradeExecutor tests whether an A2A server fails OPEN on an
// extension its own agent card marks as required (rule
// a2a-extension-downgrade-001).
//
// A2A cards advertise capabilities.extensions[] with a `uri` and `required`
// flag; clients activate an extension via the A2A-Extensions request header
// (pre-1.0 servers, through v0.3.0, used X-A2A-Extensions; both are sent so the
// activation control works across server versions).
// A server that processes requests which omit its own required extension has
// silently downgraded the negotiated capability set. The executor only reports a
// CONFIRMED downgrade when an extension-activating control request is accepted
// AND the same request with the header omitted is also accepted.
type ExtensionDowngradeExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-extension-downgrade", func(rc attack.RuleContext) attack.Executor {
		return NewExtensionDowngradeExecutor(rc)
	})
}

func NewExtensionDowngradeExecutor(r attack.RuleContext) *ExtensionDowngradeExecutor {
	return &ExtensionDowngradeExecutor{rule: r}
}

// a2aExtensionsHeader is the v1.0+ extension-activation header. The pre-1.0 name
// (a2aExtensionsHeaderLegacy, used through v0.3.0) is still sent alongside it so
// the activation control request lands on servers of either era.
const (
	a2aExtensionsHeader       = "A2A-Extensions"
	a2aExtensionsHeaderLegacy = "X-A2A-Extensions"
	extensionSupportRequired  = -32008
)

// activationHeaders returns the activation header set for the given extension
// URI: both the v1.0 and legacy header names so the control works regardless of
// which A2A version the target implements.
func activationHeaders(uri string) map[string]string {
	return map[string]string{
		a2aExtensionsHeader:       uri,
		a2aExtensionsHeaderLegacy: uri,
	}
}

func (e *ExtensionDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	required, cardServed, cardReadReason := e.requiredExtensions(ctx, client, vars.BaseURL)
	withCardReadReason := func(err error) error {
		if cardReadReason == "" {
			return err
		}
		if err == nil {
			err = attack.ErrInconclusive
		}
		return fmt.Errorf("%w: unobserved Agent Card read: %s", err, cardReadReason)
	}
	endpoint, ok := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	if !cardServed {
		return nil, withCardReadReason(fmt.Errorf("%w: required extensions could not be read from an Agent Card at %s",
			attack.ErrInconclusive, vars.BaseURL))
	}
	if len(required) == 0 {
		return nil, withCardReadReason(nil)
	}
	if !ok {
		return nil, withCardReadReason(attack.ErrInconclusive)
	}

	var observed setupObservation
	tested := false
	for _, uri := range required {
		// Control: activate the required extension. If even this is rejected we
		// cannot exercise the rule (e.g. messaging needs creds we lack).
		accepted, shape, ctrlObs, _ := e.sendMessage(ctx, client, endpoint, activationHeaders(uri), vars.RandID, "")
		if !accepted {
			observed.observe(ctrlObs)
			continue
		}
		if ctrlObs.rank >= setupOtherRefusal {
			observed.observe(ctrlObs)
		}
		// Test: omit the extension header and reuse the shape that worked.
		omitted, _, _, rejectedRequired := e.sendMessage(ctx, client, endpoint, nil, vars.RandID, shape)
		if omitted {
			finding := e.finding(endpoint, uri, shape)
			if cardReadReason != "" {
				finding.Evidence += "\nunobserved Agent Card read: " + cardReadReason
			}
			var incomplete error
			if observed.rank >= setupOtherRefusal {
				incomplete = observed.err()
			}
			return []attack.Finding{finding}, withCardReadReason(incomplete)
		}
		if rejectedRequired {
			tested = true
			continue
		}
		observed.observe(setupObservation{setupOtherRefusal, fmt.Sprintf(
			"request omitting required extension %q at %s did not confirm an extension-policy rejection", uri, endpoint)})
	}
	if tested && observed.rank == setupFeatureAbsent {
		return nil, withCardReadReason(fmt.Errorf("%w: not every required extension could be tested at %s",
			attack.ErrInconclusive, endpoint))
	}
	if tested && observed.rank == setupNothing {
		return nil, withCardReadReason(nil)
	}
	return nil, withCardReadReason(observed.err())
}

// requiredExtensions keeps unreadable card paths separate from absent ones.
func (e *ExtensionDowngradeExecutor) requiredExtensions(ctx context.Context, client *attack.HTTPClient, baseURL string) (uris []string, cardServed bool, readReason string) {
	var failures []string
	for _, path := range []string{cardPathPrimary, cardPathLegacy} {
		cardURL := endpoint.AppendPath(baseURL, path)
		resp, err := client.GET(ctx, cardURL, cardVersionHeaders(cardURL))
		if err != nil || resp == nil {
			failures = append(failures, path+": request failed")
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if !resp.IsSuccess() {
			failures = append(failures, fmt.Sprintf("%s: HTTP %d", path, resp.StatusCode))
			continue
		}
		if !resp.IsJSON() {
			failures = append(failures, path+": response is not JSON")
			continue
		}
		out, err := protocola2a.RequiredCardExtensions(resp.Body)
		if err != nil {
			failures = append(failures, path+": "+err.Error())
			continue
		}
		cardServed = true
		if len(out) > 0 {
			return out, true, strings.Join(failures, "; ")
		}
	}
	return nil, cardServed, strings.Join(failures, "; ")
}

// sendMessage tries both wire shapes, or only forceShape when set.
func (e *ExtensionDowngradeExecutor) sendMessage(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, randID, forceShape string) (accepted bool, shape string, obs setupObservation, rejectedRequired bool) {
	type variant struct {
		name   string
		method string
		role   interface{}
		part   map[string]string
	}
	variants := []variant{
		{"v1.0", "SendMessage", 1, map[string]string{"text": "batesian ext probe " + randID}},
		{"v0.3", "message/send", "user", map[string]string{"kind": "text", "text": "batesian ext probe " + randID}},
	}
	for _, v := range variants {
		if forceShape != "" && v.name != forceShape {
			continue
		}
		headers := map[string]string{"A2A-Version": "1.0"}
		for k, val := range extra {
			headers[k] = val
		}
		params := map[string]interface{}{
			"message": map[string]interface{}{
				"role":      v.role,
				"parts":     []interface{}{v.part},
				"messageId": "batesian-ext-" + randID,
			},
		}
		if v.name == "v1.0" {
			params["configuration"] = map[string]interface{}{"returnImmediately": true}
		}
		requestID := "batesian-ext-" + v.name + "-" + randID
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  v.method,
			"params":  params,
		})
		if err == nil && resp != nil && resp.IsAccepted() {
			return true, v.name, obs, false
		}
		if forceShape != "" && err == nil && resp != nil {
			_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
			if (resp.IsSuccess() || resp.StatusCode == http.StatusBadRequest) &&
				valid && hasError && code == extensionSupportRequired {
				return false, "", setupObservation{}, true
			}
		}
		obs.observe(classifyTaskSetup("activating a required extension", endpoint,
			c.PresentsCredential(endpoint), resp))
	}
	return false, "", obs, false
}

func (e *ExtensionDowngradeExecutor) finding(endpoint, uri, shape string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A server does not enforce its own required extension (negotiation downgrade)",
		Description: fmt.Sprintf(
			"The agent card marks extension %q as required, but the server accepted a SendMessage that "+
				"OMITTED the A2A-Extensions activation header. A request that activates the extension and an "+
				"identical request that does not are both processed, so the required extension's policy or "+
				"capability guarantees can be bypassed simply by not sending the header. The A2A spec requires "+
				"a server to reject a request that does not activate a required extension (ExtensionSupportRequiredError).", uri),
		Evidence: fmt.Sprintf(
			"endpoint: %s (shape %s)\nrequired extension: %s\nwith A2A-Extensions activation: accepted\nwithout activation header: accepted (spec requires rejection: ExtensionSupportRequiredError)",
			endpoint, shape, uri),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
