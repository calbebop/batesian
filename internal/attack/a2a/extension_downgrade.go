package a2a

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
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
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	required := e.requiredExtensions(ctx, client, vars.BaseURL)
	if len(required) == 0 {
		return nil, nil // no required extension advertised => nothing to downgrade
	}
	endpoint := vars.BaseURL + "/"

	for _, uri := range required {
		// Control: activate the required extension. If even this is rejected we
		// cannot exercise the rule (e.g. messaging needs creds we lack).
		accepted, shape := e.sendMessage(ctx, client, endpoint, activationHeaders(uri), vars.RandID, "")
		if !accepted {
			continue
		}
		// Test: omit the extension header and reuse the shape that worked.
		omitted, _ := e.sendMessage(ctx, client, endpoint, nil, vars.RandID, shape)
		if omitted {
			return []attack.Finding{e.finding(endpoint, uri, shape)}, nil
		}
	}
	return nil, nil
}

// requiredExtensions fetches the agent card and returns the URIs of every
// extension the card marks `required: true`.
func (e *ExtensionDowngradeExecutor) requiredExtensions(ctx context.Context, client *attack.HTTPClient, baseURL string) []string {
	for _, path := range []string{cardPathPrimary, cardPathLegacy} {
		resp, err := client.GET(ctx, baseURL+path, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		var card struct {
			Capabilities struct {
				Extensions []struct {
					URI      string `json:"uri"`
					Required bool   `json:"required"`
				} `json:"extensions"`
			} `json:"capabilities"`
		}
		if err := json.Unmarshal(resp.Body, &card); err != nil {
			continue
		}
		var out []string
		for _, ext := range card.Capabilities.Extensions {
			if ext.Required && ext.URI != "" {
				out = append(out, ext.URI)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// sendMessage issues a SendMessage with the given extra headers. When forceShape
// is empty it tries the A2A v1.0 PascalCase shape then the v0.3 slash shape and
// returns which one was accepted; when forceShape is set it uses only that shape
// (so the control and test requests are byte-identical except for the header).
func (e *ExtensionDowngradeExecutor) sendMessage(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, randID, forceShape string) (accepted bool, shape string) {
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
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-ext-" + v.name + "-" + randID,
			"method":  v.method,
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      v.role,
					"parts":     []interface{}{v.part},
					"messageId": "batesian-ext-" + randID,
				},
			},
		})
		if err == nil && resp.IsSuccess() && !isJSONRPCError(resp.Body) {
			return true, v.name
		}
	}
	return false, ""
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
