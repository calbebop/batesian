package mcp

import (
	"context"
	"fmt"
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

	// Step 1: initialize while presenting a client-chosen session id.
	ep, assigned, ok := e.initWithSession(ctx, client, vars.BaseURL, fixed)
	if !ok {
		return nil, nil // not a responsive MCP server
	}
	// Discriminator: the server returned its OWN session id, ignoring the
	// supplied one. That is the correct, secure behavior - no finding.
	if assigned != "" && assigned != fixed {
		return nil, nil
	}

	// Best-effort: complete the handshake for the pre-seeded session.
	_, _ = client.POST(ctx, ep, map[string]string{"Mcp-Session-Id": fixed}, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	// Step 2: present the attacker-chosen id on a follow-up call.
	if !e.sessionAccepted(ctx, client, ep, fixed, nil) {
		return nil, nil // server did not adopt the pre-seeded id - secure
	}

	// Step 3 (control): a never-initialized random id. A spec-compliant server
	// rejects it (404). If it is ALSO accepted, the server tracks no sessions at
	// all - not fixation - so suppress.
	if e.sessionAccepted(ctx, client, ep, unseeded, nil) {
		return nil, nil
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
		if e.sessionAccepted(ctx, pClient, ep, fixed, p.Headers) {
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

// initWithSession sends an initialize request carrying a client-chosen
// Mcp-Session-Id header and returns the working endpoint, the session id the
// server actually assigned (its response header, possibly empty), and whether a
// responsive MCP server was found.
func (e *SessionFixationExecutor) initWithSession(ctx context.Context, client *attack.HTTPClient, baseURL, supplied string) (endpoint, assigned string, ok bool) {
	for _, ep := range endpointCandidates(baseURL) {
		resp, err := client.POST(ctx, ep, map[string]string{"Mcp-Session-Id": supplied}, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil || !resp.IsSuccess() {
			continue
		}
		if !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			continue
		}
		return ep, resp.Headers.Get("Mcp-Session-Id"), true
	}
	return "", "", false
}

// sessionAccepted reports whether a follow-up call presenting sessionID is
// accepted as a valid session. Per spec an unrecognized session yields HTTP 404,
// so any non-2xx response counts as rejection. A 2xx response counts as accepted
// UNLESS it carries a JSON-RPC error that references the session (e.g. "session
// not found"); a method-not-found error still means the session passed
// validation and reached method dispatch.
func (e *SessionFixationExecutor) sessionAccepted(ctx context.Context, client *attack.HTTPClient, ep, sessionID string, extraHeaders map[string]string) bool {
	headers := map[string]string{"Mcp-Session-Id": sessionID}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return false
	}
	body := resp.BodyString()
	if isJSONRPCError(body) {
		low := strings.ToLower(body)
		if strings.Contains(low, "session") || strings.Contains(low, "not initialized") {
			return false
		}
	}
	return true
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
