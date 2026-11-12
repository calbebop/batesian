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

// ExtensionDowngradeExecutor checks enforcement of card-required extensions.
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
	maxExtensionOmissions     = 4
	maxExtensionHeaderBytes   = 4096
)

// activationHeaders covers both supported header names.
func activationHeaders(uris []string) map[string]string {
	if len(uris) == 0 {
		return nil
	}
	value := strings.Join(uris, ",")
	return map[string]string{
		a2aExtensionsHeader:       value,
		a2aExtensionsHeaderLegacy: value,
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

	required = distinctExtensions(required)
	for _, uri := range required {
		if strings.ContainsAny(uri, ",\r\n") {
			return nil, withCardReadReason(fmt.Errorf("%w: a required extension URI cannot be represented in the activation header", attack.ErrInconclusive))
		}
	}
	valueBytes := len(strings.Join(required, ","))
	if 2*valueBytes+len(a2aExtensionsHeader)+len(a2aExtensionsHeaderLegacy) > maxExtensionHeaderBytes {
		return nil, withCardReadReason(fmt.Errorf("%w: required extension activation headers exceed the %d-byte probe limit", attack.ErrInconclusive, maxExtensionHeaderBytes))
	}
	accepted, shape, ctrlObs, _ := e.sendMessage(ctx, client, endpoint, activationHeaders(required), vars.RandID, vars.RandID+"-control", "")
	if !accepted {
		return nil, withCardReadReason(ctrlObs.err())
	}
	var incomplete []string
	if ctrlObs.rank >= setupOtherRefusal {
		incomplete = append(incomplete, ctrlObs.reason)
	}
	limit := min(len(required), maxExtensionOmissions)
	for i := 0; i < limit; i++ {
		remaining := append([]string(nil), required[:i]...)
		remaining = append(remaining, required[i+1:]...)
		omitted, _, _, rejectedRequired := e.sendMessage(ctx, client, endpoint,
			activationHeaders(remaining), vars.RandID, fmt.Sprintf("%s-omitted-%d", vars.RandID, i), shape)
		if omitted {
			finding := e.finding(endpoint, i+1, len(required), shape)
			if cardReadReason != "" {
				finding.Evidence += "\nunobserved Agent Card read: " + cardReadReason
			}
			if i+1 < len(required) {
				incomplete = append(incomplete, fmt.Sprintf("%d of %d required extensions not tested after the finding", len(required)-i-1, len(required)))
			}
			return []attack.Finding{finding}, withCardReadReason(extensionCoverageError(incomplete))
		}
		if !rejectedRequired {
			incomplete = append(incomplete, fmt.Sprintf("omitting required extension %d of %d did not produce a correlated extension-policy rejection", i+1, len(required)))
		}
	}
	if limit < len(required) {
		incomplete = append(incomplete, fmt.Sprintf("tested %d of %d required extensions; probe limit reached", limit, len(required)))
	}
	return nil, withCardReadReason(extensionCoverageError(incomplete))
}

func distinctExtensions(uris []string) []string {
	seen := make(map[string]bool, len(uris))
	var distinct []string
	for _, uri := range uris {
		if !seen[uri] {
			seen[uri] = true
			distinct = append(distinct, uri)
		}
	}
	return distinct
}

func extensionCoverageError(reasons []string) error {
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(reasons, "; "))
}

// requiredExtensions keeps unreadable card paths separate from absent ones.
func (e *ExtensionDowngradeExecutor) requiredExtensions(ctx context.Context, client *attack.HTTPClient, baseURL string) (uris []string, cardServed bool, readReason string) {
	var failures []string
	for _, path := range []string{cardPathPrimary, cardPathLegacy} {
		cardURL := endpoint.AppendPath(baseURL, path)
		headers := cardVersionHeaders(cardURL)
		attempts := []map[string]string{headers}
		if len(headers) > 0 {
			attempts = append(attempts, nil)
		}
		for _, attempt := range attempts {
			resp, err := client.GET(ctx, cardURL, attempt)
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
			break
		}
	}
	return nil, cardServed, strings.Join(failures, "; ")
}

// sendMessage tries both wire shapes, or only forceShape when set.
func (e *ExtensionDowngradeExecutor) sendMessage(ctx context.Context, c *attack.HTTPClient, endpoint string, extra map[string]string, randID, requestScope, forceShape string) (accepted bool, shape string, obs setupObservation, rejectedRequired bool) {
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
		headers := map[string]string{}
		if v.name == "v1.0" {
			headers["A2A-Version"] = "1.0"
		}
		for k, val := range extra {
			headers[k] = val
		}
		requestID := "batesian-ext-" + requestScope + "-" + v.name
		params := map[string]interface{}{
			"message": map[string]interface{}{
				"role":      v.role,
				"parts":     []interface{}{v.part},
				"messageId": requestID + "-message",
			},
		}
		if v.name == "v1.0" {
			params["configuration"] = map[string]interface{}{"returnImmediately": true}
		}
		resp, err := c.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  v.method,
			"params":  params,
		})
		version := "0.3.0"
		if v.name == "v1.0" {
			version = "1.0"
		}
		if err == nil && sendResultProcessed(resp, requestID, requestID+"-message", version) {
			return true, v.name, obs, false
		}
		if forceShape != "" && err == nil && resp != nil {
			_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
			if (resp.IsSuccess() || resp.StatusCode == http.StatusBadRequest) &&
				valid && hasError && code == extensionSupportRequired {
				return false, "", setupObservation{}, true
			}
		}
		obs.observe(correlatedTaskSetup("activating a required extension", endpoint,
			c.PresentsCredential(endpoint), resp, requestID))
	}
	return false, "", obs, false
}

func (e *ExtensionDowngradeExecutor) finding(endpoint string, position, total int, shape string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A server does not enforce its own required extension (negotiation downgrade)",
		Description: fmt.Sprintf(
			"The agent card marks extension %d of %d as required. A control activated all required extensions, "+
				"but the server also processed a SendMessage that omitted this one while retaining the others. "+
				"Reject requests missing any required extension with ExtensionSupportRequiredError.", position, total),
		Evidence: fmt.Sprintf(
			"endpoint: %s (shape %s)\nrequired extension: %d of %d (URI omitted)\nall required extensions activated: accepted\nselected required extension omitted: accepted",
			endpoint, shape, position, total),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
