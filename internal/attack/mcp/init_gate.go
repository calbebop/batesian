package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// This file backs one control shared by the two forged-token rules
// (mcp-token-replay-001 and mcp-oauth-audience-002): where on a server can a
// bearer token actually be judged?
//
// Both rules present their forged tokens to `initialize`. That was taken to
// mean the token was examined, but plenty of servers leave initialize ungated
// and authorize the calls that follow (session-as-credential documented the
// same posture for its own controls). On such a server every forged token is
// "accepted" for a method that never looked at it, and the rules reported
// absent signature validation - with the operator's own token rules elsewhere
// in this package relying on that posture being common, the false positive was
// not hypothetical.
//
// The control is an anonymous initialize. If it is refused, initialize itself
// gates, and forged-token acceptance there is a genuine finding. If it is
// accepted, initialize proves nothing about tokens; the rule then finds a
// method that DOES gate - the first listing the server advertises - confirms
// it refuses an anonymous caller, and judges the forged tokens there instead.
// A server that answers both anonymously authenticates nothing these rules can
// reach, which is the unauth rules' territory, not a token-validation verdict.

// initGate is what the anonymous-initialize control established about one
// endpoint.
type initGate int

const (
	// gateUnknown: the control could not run, or its answer was neither a clear
	// acceptance nor a clear refusal. A forged token accepted at initialize
	// cannot be attributed either way, so the rule reports not tested rather
	// than guess.
	gateUnknown initGate = iota
	// gateOnInit: initialize itself refuses an anonymous caller, so acceptance
	// of a forged token at initialize is a genuine finding.
	gateOnInit
	// gateAfterInit: initialize accepts anyone, but a method the server serves
	// (its first advertised listing, or ping when nothing is listable) refuses an
	// anonymous caller, so forged tokens must be judged at that method.
	gateAfterInit
	// gateNowhere: initialize and the advertised listing both answer an
	// anonymous caller. The server presents no credential-gated surface for
	// these rules; the unauth rules report the open surface.
	gateNowhere
)

// gateProbe is the outcome of probing one endpoint, with everything the
// follow-up probes need when the gate sits after initialize.
type gateProbe struct {
	gate initGate
	// method is the listing that refused the anonymous caller when
	// gate == gateAfterInit.
	method string
	// session is the anonymous initialize handshake, reusable for follow-ups
	// (its session id and negotiated protocol version, where the server
	// supplied them).
	session mcpSession
	// reason is the not-tested sentence for gateUnknown and gateNowhere.
	reason string
}

// probeInitGate runs the controls that decide where a forged bearer token can
// be judged at one endpoint. anon must be a client with no ambient credential
// (attack.NewUnauthHTTPClient): the control's question is what the server does
// for a caller who presents nothing.
func probeInitGate(ctx context.Context, anon *attack.HTTPClient, ep string) gateProbe {
	resp, err := anon.POST(ctx, ep, nil, json.RawMessage(mcpInitBody))
	if err != nil {
		return gateProbe{gate: gateUnknown, reason: fmt.Sprintf(
			"the anonymous initialize control at %s did not answer, so acceptance of a forged token at initialize could not be attributed", ep)}
	}

	if !resp.IsAccepted() {
		switch classifyAccess(resp, nil) {
		case accessRefused:
			// The endpoint demanded a credential for the handshake itself.
			return gateProbe{gate: gateOnInit}
		default:
			return gateProbe{gate: gateUnknown, reason: fmt.Sprintf(
				"the anonymous initialize control at %s returned neither a result nor a refusal (HTTP %d), so acceptance of a forged token at initialize could not be attributed", ep, resp.StatusCode)}
		}
	}

	// Initialize accepts an anonymous caller. Find a method that gates.
	session := mcpSession{
		Endpoint:        ep,
		SessionID:       resp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(resp.Body),
		RawInit:         resp.Body,
	}
	// The gated-method candidates, in preference order: the listings the
	// server advertises, and then `ping`, which no capability advertises but
	// every MCP server must answer. Without the fallback, a server offering
	// nothing listable had no judgeable surface and the rule reported not
	// tested even when its middleware gates every method equally.
	method := "ping"
	if methods := advertisedListMethods(session); len(methods) > 0 {
		method = methods[0]
	}

	// Complete the handshake the same way initializeMCP does, so a stateful
	// server does not refuse the listing for missing-session reasons that have
	// nothing to do with the credential.
	_, _ = anon.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	listResp, err := session.post(ctx, anon, 9, method, map[string]interface{}{})
	switch classifyAccess(listResp, err) {
	case accessRefused:
		return gateProbe{gate: gateAfterInit, method: method, session: session}
	case accessGranted:
		return gateProbe{gate: gateNowhere, reason: fmt.Sprintf(
			"initialize and %s at %s both answer an anonymous caller, so the server presents no credential-gated surface for this rule (the unauth rules report the open surface)", method, ep)}
	default:
		return gateProbe{gate: gateUnknown, reason: fmt.Sprintf(
			"the anonymous %s control at %s returned neither a result nor a refusal, so no credential-gated surface was confirmed to judge a forged token against", method, ep)}
	}
}

// probeForgedAtMethod judges one forged token at a method the server gates.
//
// initialize at ep is known to be open (the caller only reaches this on
// gateAfterInit), so the probe opens its own handshake presenting the forged
// token - a server may bind what a session may do to the token that opened it,
// and either way an accepted listing after that handshake is the forged token
// being honoured - and then calls method carrying the same token.
//
// Returns the method response (nil on a transport failure) and its verdict.
func probeForgedAtMethod(ctx context.Context, anon *attack.HTTPClient, ep, method, token string) (*attack.Response, accessVerdict) {
	authHeaders := map[string]string{"Authorization": "Bearer " + token}
	initResp, err := anon.POST(ctx, ep, authHeaders, json.RawMessage(mcpInitBody))
	if err != nil {
		return nil, accessUndetermined
	}
	if !initResp.IsAccepted() {
		// Initialize was open for an anonymous caller moments ago; this reply
		// differs only in the forged Authorization header, so whatever it says
		// was said to that token.
		return initResp, classifyAccess(initResp, nil)
	}

	session := mcpSession{
		Endpoint:        ep,
		SessionID:       initResp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(initResp.Body),
		RawInit:         initResp.Body,
	}
	_, _ = anon.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	resp, err := session.postShaping(ctx, anon, 10, method, map[string]interface{}{}, func(h map[string]string) {
		h["Authorization"] = "Bearer " + token
	})
	return resp, classifyAccess(resp, err)
}

// judgedAtLabel names the surface a probe's verdict came from, for evidence.
func judgedAtLabel(method string) string {
	if method == "" {
		return "initialize"
	}
	return method + " (initialize accepts anonymous callers, so the token was judged at the gated method)"
}
