package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// SessionFixationExecutor tests whether an MCP server adopts a CLIENT-supplied
// Mcp-Session-Id instead of minting one server-side (rule mcp-session-fixation-001).
//
// The Streamable HTTP transport requires the server to assign the session id at
// initialize and to reject an unrecognized id with HTTP 404. A server that
// instead trusts a client-chosen id is vulnerable to session fixation (CWE-384).
//
// Confirming this honestly requires distinguishing a fixation-prone server from
// one that simply does not track sessions at all (which accepts any header). The
// executor uses a control: it confirms only when the attacker-chosen id is
// accepted as a live session WHILE a different, never-initialized random id is
// rejected - proving the server does enforce sessions yet trusted a
// client-supplied identifier.
//
// It implements attack.ChainExecutor: when a second principal is configured it
// adds a cross-principal hop (a different identity borrowing the pre-seeded
// session) and publishes the fixed session id to the Blackboard for downstream
// rules.
type SessionFixationExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-session-fixation", func(rc attack.RuleContext) attack.Executor {
		return NewSessionFixationExecutor(rc)
	})
}

func NewSessionFixationExecutor(r attack.RuleContext) *SessionFixationExecutor {
	return &SessionFixationExecutor{rule: r}
}

// Produces declares the artifact kinds this rule may publish.
func (e *SessionFixationExecutor) Produces() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactSession}
}

// Requires declares no upstream dependencies - this rule is a producer.
func (e *SessionFixationExecutor) Requires() []attack.ArtifactKind { return nil }

// Execute satisfies attack.Executor by running the chained logic against a
// throwaway blackboard, so the rule still works outside the engine.
func (e *SessionFixationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	return e.ExecuteChained(ctx, target, opts, attack.NewBlackboard())
}

// ExecuteChained runs the session-fixation check.
func (e *SessionFixationExecutor) ExecuteChained(ctx context.Context, target string, opts attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	fixed := "batesian-fixed-" + vars.RandID
	unseeded := "batesian-unseeded-" + vars.RandID

	// Reachability is established with an ordinary handshake, separately from
	// the attack. A server that refuses the seeded id at initialize is the
	// defence this rule tests for, and reading that refusal as "nothing here"
	// made the rule report inconclusive against exactly the servers it covers:
	// the reference implementation answers the seeded initialize with
	// HTTP 400 -32000 "Bad Request: No valid session ID provided", while a
	// plain initialize on the same endpoint returns 200 and a session id.
	//
	// Going through initializeMCP also gives this rule era detection, so a
	// modern-era target is reported as speaking an unsupported protocol version
	// rather than as unreachable.
	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, inconclusive(err)
	}
	ep := session.Endpoint

	// Step 1: initialize again, this time presenting a client-chosen session id.
	seeded, verdict := e.initWithSession(ctx, client, ep, fixed)
	switch verdict {
	case accessRefused:
		return nil, nil
	case accessUndetermined:
		return nil, fmt.Errorf("%w: initialize with a client-chosen session id at %s returned neither a session nor a session refusal",
			attack.ErrInconclusive, ep)
	}
	// Discriminator: the server returned its OWN session id, ignoring the
	// supplied one. That is the correct, secure behavior - no finding.
	if seeded.SessionID != "" && seeded.SessionID != fixed {
		return nil, nil
	}
	seeded.SessionID = fixed

	initialized, initErr := client.POST(ctx, ep, seeded.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	if initErr != nil || initialized == nil || !initialized.IsSuccess() {
		return nil, fmt.Errorf("%w: notifications/initialized for the client-chosen session at %s did not complete",
			attack.ErrInconclusive, ep)
	}
	if isJSONRPCError(initialized.BodyString()) {
		return nil, fmt.Errorf("%w: notifications/initialized for the client-chosen session at %s returned a JSON-RPC error",
			attack.ErrInconclusive, ep)
	}

	// Step 2: present the attacker-chosen id on a follow-up call.
	switch e.sessionAccepted(ctx, client, seeded, nil) {
	case accessRefused:
		return nil, nil // server did not adopt the pre-seeded id - secure
	case accessUndetermined:
		return nil, fmt.Errorf("%w: the follow-up call presenting the client-chosen session id at %s "+
			"returned neither a result nor a refusal, so whether the server adopted it was never "+
			"observed", attack.ErrInconclusive, ep)
	}

	// Step 3 (control): a never-initialized random id. A spec-compliant server
	// rejects it (404). If it is ALSO accepted, the server tracks no sessions at
	// all - not fixation - so suppress.
	unissued := seeded
	unissued.SessionID = unseeded
	switch e.sessionAccepted(ctx, client, unissued, nil) {
	case accessGranted:
		return nil, nil
	case accessUndetermined:
		return nil, fmt.Errorf("%w: the never-initialized control id at %s returned neither a result "+
			"nor a refusal, so whether this server enforces sessions at all could not be established, "+
			"and without that a client-chosen id being accepted proves nothing",
			attack.ErrInconclusive, ep)
	}

	// Confirmed: sessions ARE enforced (unseeded id rejected) yet the server
	// adopted the client-supplied id.
	bb.Publish(attack.Artifact{Kind: attack.ArtifactSession, Value: fixed, Producer: e.rule.ID})

	chain := []attack.ChainStep{
		{Hop: 1, Action: "initialize with client-chosen Mcp-Session-Id " + fixed, Outcome: "server adopted the client-supplied session id"},
		{Hop: 2, Action: "call tools/list presenting the pre-seeded id", Outcome: "accepted as an established session"},
		{Hop: 3, Action: "call tools/list presenting an un-initialized random id", Outcome: "rejected - server does enforce sessions"},
	}

	crossPrincipal := ""
	if p, ok := crossPrincipalFor(opts); ok {
		o := opts
		o.Token = p.Token
		pClient := attack.NewHTTPClient(o, vars)
		if e.sessionAccepted(ctx, pClient, seeded, p.Headers) == accessGranted {
			crossPrincipal = p.Name
			chain = append(chain, attack.ChainStep{
				Hop:       4,
				Principal: p.Name,
				Action:    "present the pre-seeded id as a different principal",
				Outcome:   "accepted - borrowed the fixed session across principals",
			})
		}
	}

	return []attack.Finding{e.finding(ep, fixed, crossPrincipal, chain)}, nil
}

// initWithSession distinguishes an explicit session refusal from an unknown outcome.
func (e *SessionFixationExecutor) initWithSession(ctx context.Context, client *attack.HTTPClient, endpoint, supplied string) (mcpSession, accessVerdict) {
	resp, err := client.POST(ctx, endpoint, map[string]string{"Mcp-Session-Id": supplied}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": latestStable,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil || resp == nil {
		return mcpSession{}, accessUndetermined
	}
	if !resp.IsSuccess() || !initializeSucceeded(resp.Body) {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden || sessionRefusalError(resp.Body) {
			return mcpSession{}, accessRefused
		}
		return mcpSession{}, accessUndetermined
	}
	return mcpSession{
		Endpoint: endpoint, SessionID: resp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(resp.Body),
	}, accessGranted
}

func sessionRefusalError(body []byte) bool {
	if _, ok := jsonRPCErrorCode(body); !ok {
		return false
	}
	message := strings.ToLower(jsonRPCErrorMessage(body))
	return strings.Contains(message, "invalid session") || strings.Contains(message, "unknown session") ||
		strings.Contains(message, "unrecognized session") || strings.Contains(message, "session not found") ||
		strings.Contains(message, "no valid session") || strings.Contains(message, "not initialized")
}

// sessionAccepted reports whether a follow-up call presenting sessionID is
// accepted as a valid session. Per spec an unrecognized session yields HTTP 404,
// so any non-2xx response counts as rejection. A 2xx response counts as accepted
// UNLESS it carries a JSON-RPC error that references the session (e.g. "session
// not found"); a method-not-found error still means the session passed
// validation and reached method dispatch.
func (e *SessionFixationExecutor) sessionAccepted(ctx context.Context, client *attack.HTTPClient, session mcpSession, extraHeaders map[string]string) accessVerdict {
	headers := session.header()
	for k, v := range extraHeaders {
		headers[k] = v
	}
	resp, err := client.POST(ctx, session.Endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || resp == nil {
		return accessUndetermined
	}
	body := resp.BodyString()
	sessionRefusal := false
	if isJSONRPCError(body) {
		low := strings.ToLower(body)
		sessionRefusal = strings.Contains(low, "session") || strings.Contains(low, "not initialized")
	}
	if !resp.IsSuccess() {
		// 404 is the shape the transport prescribes for an unknown session; an auth
		// status, or any status carrying a session-flavoured error, is also a real
		// refusal. Anything else - a 429, a 502, an empty 400 - refused nothing, and
		// grading it as a refusal is what let this rule fabricate: BOTH of its
		// suppression controls read a non-answer as "the server enforces sessions",
		// which is the direction that enables the finding.
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden || sessionRefusal {
			return accessRefused
		}
		return accessUndetermined
	}
	if sessionRefusal {
		return accessRefused
	}
	// A JSON-RPC error that is not about the session still means the session was
	// accepted: the request reached dispatch.
	return accessGranted
}

// finding builds the confirmed session-fixation finding.
func (e *SessionFixationExecutor) finding(endpoint, fixed, crossPrincipal string, chain []attack.ChainStep) attack.Finding {
	desc := fmt.Sprintf(
		"POST %s adopted a client-supplied Mcp-Session-Id (%q) as a live session: a "+
			"follow-up call presenting that attacker-chosen id was accepted, while a "+
			"different, never-initialized id was rejected - proving the server does enforce "+
			"sessions but trusts an identifier the client dictated. Per the Streamable HTTP "+
			"transport the server must mint the session id itself and reject unrecognized "+
			"ids (HTTP 404). An attacker can fix a known id, lure a victim onto it, and ride "+
			"the victim's authenticated session (CWE-384).", endpoint, fixed)
	if crossPrincipal != "" {
		desc += fmt.Sprintf(" A second principal (%q) successfully presented the same "+
			"pre-seeded id, confirming the fixed session is borrowable across principals.", crossPrincipal)
	}
	evidence := fmt.Sprintf(
		"endpoint: %s\nclient-supplied Mcp-Session-Id: %s\npre-seeded id accepted: yes\n"+
			"un-initialized random id accepted: no (rejected)", endpoint, fixed)
	if crossPrincipal != "" {
		evidence += fmt.Sprintf("\ncross-principal borrow (%s): accepted", crossPrincipal)
	}
	return attack.Finding{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    "high",
		Confidence:  attack.ConfirmedExploit,
		Title:       "MCP server adopts a client-supplied Mcp-Session-Id (session fixation)",
		Description: desc,
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
		Chain:       chain,
	}
}

// crossPrincipalFor returns the first configured principal whose token differs
// from the default identity, to demonstrate a cross-principal session borrow.
func crossPrincipalFor(opts attack.Options) (attack.Principal, bool) {
	for _, p := range opts.Principals {
		if p.Token != opts.Token {
			return p, true
		}
	}
	return attack.Principal{}, false
}
