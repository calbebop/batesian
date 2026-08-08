package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// DNSRebindOriginExecutor tests whether an MCP Streamable HTTP server validates
// the Origin header (rule mcp-dns-rebind-origin-001).
//
// The Streamable HTTP transport requires: "Servers MUST validate the Origin
// header on all incoming connections to prevent DNS rebinding attacks. If the
// Origin header is present and invalid, servers MUST respond with HTTP 403
// Forbidden." A server that processes a request carrying a foreign Origin header
// instead of rejecting it does not validate Origin; a local or same-network
// server is then reachable from a malicious website that rebinds DNS to it
// (driving tool calls and, on some servers, command execution).
type DNSRebindOriginExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-dns-rebind-origin", func(rc attack.RuleContext) attack.Executor {
		return NewDNSRebindOriginExecutor(rc)
	})
}

func NewDNSRebindOriginExecutor(r attack.RuleContext) *DNSRebindOriginExecutor {
	return &DNSRebindOriginExecutor{rule: r}
}

// foreignOrigin is a clearly cross-origin, non-resolving value (RFC 6761
// .invalid) that no server should have on its Origin allowlist.
const foreignOrigin = "https://dns-rebind.batesian.invalid"

func (e *DNSRebindOriginExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Why the baseline never succeeded, classified from the responses this loop
	// already has. Without it a server that answers and refuses the handshake reads
	// the same as a host that is not there.
	var observed initObservation
	for _, ep := range endpointCandidates(vars.BaseURL) {
		// Baseline: a normal initialize with no Origin must be accepted, so we know
		// this endpoint is a responsive MCP server and the probe is meaningful.
		accepted, baseline := e.initAccepted(ctx, client, ep, "")
		if !accepted {
			if baseline != nil {
				observed.observe(classifyInitFailure(ep, client.PresentsCredential(ep), baseline))
			}
			continue
		}
		// Probe: the same initialize with a foreign Origin. A compliant server
		// rejects it with HTTP 403; a server that still processes it does not
		// validate Origin. The only difference from the baseline is the Origin
		// header, so acceptance isolates Origin handling.
		if forged, _ := e.initAccepted(ctx, client, ep, foreignOrigin); forged {
			return []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   e.rule.Severity,
				Confidence: attack.ConfirmedExploit,
				Title:      "MCP server does not validate the Origin header (DNS rebinding protection missing)",
				Description: fmt.Sprintf(
					"The MCP endpoint processed an initialize request carrying a foreign Origin header (%s) "+
						"and returned a JSON-RPC result, instead of rejecting it with HTTP 403. The Streamable "+
						"HTTP transport requires servers to validate the Origin header on every connection and "+
						"respond 403 to an invalid Origin, to prevent DNS rebinding. A server bound to a local "+
						"or private address is then reachable from a victim's browser via a malicious website "+
						"that rebinds DNS to it, which can drive tool calls and, on some servers, reach command "+
						"execution. Validate Origin against an allowlist and bind local servers to localhost.",
					foreignOrigin),
				Evidence: fmt.Sprintf(
					"endpoint: %s\nbaseline initialize (no Origin): accepted\ninitialize with Origin %s: accepted (should be HTTP 403)",
					ep, foreignOrigin),
				Remediation: e.rule.Remediation,
				TargetURL:   ep,
			}}, nil
		}
		// Baseline accepted but the foreign-Origin probe was rejected: Origin is
		// validated. No finding, and no need to try other endpoints.
		return nil, nil
	}
	// No candidate accepted a baseline initialize: not a testable MCP endpoint. Say
	// which of those it was where the target explained itself.
	if observed.rank > rankNothing {
		return nil, inconclusive(handshakeRefusal{observed.reason})
	}
	return nil, attack.ErrInconclusive
}

// initAccepted sends an MCP initialize to ep (optionally with an Origin header)
// and reports whether the server accepted it (HTTP 200 with a JSON-RPC result
// rather than an error envelope or a 403).
// The response is returned alongside the verdict so a failed baseline can be
// explained rather than only counted. It is nil when the request never got an
// answer, which is the one case there is nothing to explain.
func (e *DNSRebindOriginExecutor) initAccepted(ctx context.Context, client *attack.HTTPClient, ep, origin string) (bool, *attack.Response) {
	headers := map[string]string{"Content-Type": "application/json"}
	if origin != "" {
		headers["Origin"] = origin
	}
	resp, err := client.POST(ctx, ep, headers, json.RawMessage(mcpInitBody))
	if err != nil {
		return false, nil
	}
	return resp.IsAccepted(), resp
}
