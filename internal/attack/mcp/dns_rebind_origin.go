package mcp

import (
	"context"
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
//
// Both wires are probed. The requirement is byte-identical in 2026-07-28, where it
// moved to the transports/streamable-http page, is stated for "all incoming
// connections" with no per-method scoping, and is not conditioned on the server
// being local: only the bind-to-localhost SHOULD beside it is. So the rule has the
// same question to ask of a modern-only server, and the wires need not answer it
// alike, since Origin checking is usually middleware and the two wires can sit
// behind different handlers.
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

	// The handshake IS the baseline. Opening a wire means the server accepted, at
	// this endpoint, the very request the probe below repeats with one header added,
	// so the pair differs in the Origin header and nothing else. It is also
	// credential-symmetric: the same client sends both, so a rejection cannot be
	// about a missing token when the baseline it is paired with carried the same one.
	//
	// Reaching the wires through openSessions is also what makes the rule honest
	// about a modern-only server. It used to run its own initialize loop, and a
	// 2026-07-28 server has no initialize at all, so every candidate failed and the
	// rule reported a bare "could not test" against a server it could in fact have
	// probed.
	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		accepted, resp := e.originAccepted(ctx, client, session)
		if resp == nil {
			// Nothing answered, so this wire yielded no verdict either way. Reporting
			// it clean would credit a server with validation on the strength of a
			// request that never arrived.
			return nil, false
		}
		if !accepted {
			// Refused. The specification asks for 403 specifically, and anything else
			// is a lesser kind of compliant, but the security question is only whether
			// the server PROCESSED a foreign-Origin request. It did not, so there is no
			// rebinding exposure to report.
			return nil, true
		}
		return []attack.Finding{e.finding(session)}, true
	})
}

// originAccepted repeats this wire's own handshake request with a foreign Origin
// header and reports whether the server processed it anyway.
//
// The request is chosen per era so that it matches what the baseline was: initialize
// on the handshake wires, server/discover on 2026-07-28, which every server MUST
// implement and which is what opened the modern session in the first place.
//
// The response is returned alongside the verdict so that "refused" can be told from
// "never answered". It is nil only in the second case.
func (e *DNSRebindOriginExecutor) originAccepted(ctx context.Context, client *attack.HTTPClient,
	session mcpSession) (bool, *attack.Response) {
	if session.Era == EraModern {
		resp, err := session.postShaping(ctx, client, "batesian-origin", "server/discover", nil,
			func(h map[string]string) { h["Origin"] = foreignOrigin })
		if err != nil {
			return false, nil
		}
		return resp.IsAccepted(), resp
	}

	// legacyHandshakeBody, not mcpInitBody: the baseline this is paired against is the
	// wire-opening handshake, and mcpInitBody carries different capabilities and
	// clientInfo. A server that refused this probe did so for a reason that had nothing
	// to do with Origin, and the rule read that as Origin validation.
	headers := map[string]string{"Content-Type": "application/json", "Origin": foreignOrigin}
	resp, err := client.POST(ctx, session.Endpoint, headers, legacyHandshakeBody())
	if err != nil {
		return false, nil
	}
	return resp.IsAccepted(), resp
}

// probeMethod names the request the probe sent, for the finding text. The two wires
// are asked the same question with the request each one actually speaks.
func probeMethod(session mcpSession) string {
	if session.Era == EraModern {
		return "server/discover"
	}
	return "initialize"
}

func (e *DNSRebindOriginExecutor) finding(session mcpSession) attack.Finding {
	method := probeMethod(session)
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   e.rule.Severity,
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP server does not validate the Origin header (DNS rebinding protection missing)",
		Description: fmt.Sprintf(
			"The MCP endpoint processed a %s request carrying a foreign Origin header (%s) "+
				"and returned a JSON-RPC result, instead of rejecting it with HTTP 403. The Streamable "+
				"HTTP transport requires servers to validate the Origin header on every connection and "+
				"respond 403 to an invalid Origin, to prevent DNS rebinding. A server bound to a local "+
				"or private address is then reachable from a victim's browser via a malicious website "+
				"that rebinds DNS to it, which can drive tool calls and, on some servers, reach command "+
				"execution. Validate Origin against an allowlist and bind local servers to localhost.",
			method, foreignOrigin),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nbaseline %s (no Origin): accepted\n%s with Origin %s: accepted (should be HTTP 403)",
			session.Endpoint, method, method, foreignOrigin),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}
