package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// SessionPrincipalExecutor checks an operator-declared session ownership boundary.
type SessionPrincipalExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-session-principal", func(rc attack.RuleContext) attack.Executor {
		return &SessionPrincipalExecutor{rule: rc}
	})
}

func NewSessionPrincipalExecutor(rc attack.RuleContext) *SessionPrincipalExecutor {
	return &SessionPrincipalExecutor{rule: rc}
}

func (e *SessionPrincipalExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	owner, caller, err := sessionPrincipalPair(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)
	for _, endpoint := range endpointCandidates(vars.BaseURL) {
		session, err := openPrincipalSession(ctx, client, endpoint, owner)
		if session.SessionID != "" {
			defer closePrincipalSession(ctx, client, session, owner)
		}
		if session.RawInit == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		if session.SessionID == "" {
			return nil, fmt.Errorf("%w: the MCP endpoint did not issue a stateful session ID", attack.ErrInconclusive)
		}
		if !knownHandshakeVersion(session.ProtocolVersion) || session.ProtocolVersion < "2025-03-26" {
			return nil, fmt.Errorf("%w: session ownership requires a recognized Streamable HTTP revision", attack.ErrInconclusive)
		}
		return e.probe(ctx, client, session, owner, caller, opts.ExpectedDenials, vars.RandID)
	}
	return nil, fmt.Errorf("%w: no MCP endpoint accepted the owner token for initialize", attack.ErrInconclusive)
}

func sessionPrincipalPair(opts attack.Options) (taskPrincipal, taskPrincipal, error) {
	var policy *attack.ExpectedDenial
	for i := range opts.ExpectedDenials {
		if opts.ExpectedDenials[i].Operation != attack.MCPSessionUse {
			continue
		}
		if policy != nil {
			return taskPrincipal{}, taskPrincipal{}, fmt.Errorf("%w: configure one mcp.sessions.use expected denial per scan", attack.ErrInconclusive)
		}
		policy = &opts.ExpectedDenials[i]
	}
	if policy == nil {
		return taskPrincipal{}, taskPrincipal{}, fmt.Errorf("%w: configure expected_denials with operation mcp.sessions.use and distinct named owner and caller", attack.ErrInconclusive)
	}
	var owner, caller taskPrincipal
	for _, candidate := range opts.Principals {
		if candidate.Name != policy.Owner && candidate.Name != policy.Caller {
			continue
		}
		principal, err := configuredTaskPrincipal(candidate)
		if err != nil {
			return owner, caller, err
		}
		if candidate.Name == policy.Owner {
			owner = principal
		} else {
			caller = principal
		}
	}
	if owner.name == "" || caller.name == "" || owner.name == caller.name ||
		owner.token == "" || caller.token == "" || owner.token == caller.token || samePrincipalIdentity(owner, caller) {
		return owner, caller, fmt.Errorf("%w: session ownership requires two distinct named bearer-token principals", attack.ErrInconclusive)
	}
	for _, p := range []taskPrincipal{owner, caller} {
		for name := range p.headers {
			if strings.EqualFold(name, "Authorization") {
				return owner, caller, fmt.Errorf("%w: principal %s must use its token field for bearer authentication", attack.ErrInconclusive, p.name)
			}
		}
	}
	return owner, caller, nil
}

func openPrincipalSession(ctx context.Context, client *attack.HTTPClient, endpoint string, p taskPrincipal) (mcpSession, error) {
	headers := map[string]string{}
	attachPrincipal(headers, p)
	resp, err := client.POST(ctx, endpoint, headers, json.RawMessage(mcpInitBody))
	if classifyAuthAccess(resp, err, 1) != accessGranted || !initializeSucceeded(resp.Body) {
		return mcpSession{}, fmt.Errorf("%w: initialize did not establish a session for %s", attack.ErrInconclusive, p.name)
	}
	session := mcpSession{
		Endpoint: endpoint, Era: EraLegacy, SessionID: resp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(resp.Body), RawInit: resp.Body,
	}
	if session.SessionID == "" {
		return session, nil
	}
	notifyHeaders := session.header()
	attachPrincipal(notifyHeaders, p)
	initialized, initErr := client.POST(ctx, endpoint, notifyHeaders,
		map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if !initializedNotificationOK(initialized, initErr) {
		return session, fmt.Errorf("%w: notifications/initialized did not complete for %s", attack.ErrInconclusive, p.name)
	}
	return session, nil
}

func closePrincipalSession(ctx context.Context, client *attack.HTTPClient, session mcpSession, p taskPrincipal) {
	closeLegacySessionsWith(ctx, client, []mcpSession{session}, func(h map[string]string) { attachPrincipal(h, p) })
}

func sessionPrincipalList(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	p taskPrincipal, allowMissing bool) accessVerdict {
	resp, err := session.postShaping(ctx, client, 2, "tools/list", map[string]interface{}{}, func(h map[string]string) {
		attachPrincipal(h, p)
	})
	if err != nil || resp == nil {
		return accessUndetermined
	}
	if resp.StatusCode == http.StatusNotFound || (allowMissing && resp.StatusCode == http.StatusBadRequest) {
		return accessRefused
	}
	if sessionRefusalError(resp.Body) {
		body, ok := parseResponseBody(resp.Body)
		if ok && matchesRPCID(body, 2) {
			return accessRefused
		}
	}
	verdict := classifyAuthAccess(resp, nil, 2)
	if verdict != accessGranted {
		return verdict
	}
	if issued := resp.Headers.Get("Mcp-Session-Id"); issued != "" && issued != session.SessionID {
		return accessUndetermined
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok {
		return accessUndetermined
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok {
		return accessUndetermined
	}
	if _, ok := result["tools"].([]interface{}); !ok {
		return accessUndetermined
	}
	return accessGranted
}

func (e *SessionPrincipalExecutor) probe(ctx context.Context, client *attack.HTTPClient,
	ownerSession mcpSession, owner, caller taskPrincipal, denials []attack.ExpectedDenial, random string) ([]attack.Finding, error) {
	callerSession, err := openPrincipalSession(ctx, client, ownerSession.Endpoint, caller)
	if callerSession.SessionID != "" {
		defer closePrincipalSession(ctx, client, callerSession, caller)
	}
	if err != nil || callerSession.SessionID == "" || callerSession.SessionID == ownerSession.SessionID {
		return nil, fmt.Errorf("%w: the caller did not establish a distinct stateful MCP session", attack.ErrInconclusive)
	}
	if sessionPrincipalList(ctx, client, ownerSession, owner, false) != accessGranted ||
		sessionPrincipalList(ctx, client, callerSession, caller, false) != accessGranted {
		return nil, fmt.Errorf("%w: both principals must list tools in their own sessions", attack.ErrInconclusive)
	}
	cross := sessionPrincipalList(ctx, client, ownerSession, caller, false)
	if sessionPrincipalList(ctx, client, ownerSession, owner, false) != accessGranted {
		return nil, fmt.Errorf("%w: the owner session did not remain usable after the comparison", attack.ErrInconclusive)
	}
	switch cross {
	case accessRefused:
		return nil, nil
	case accessUndetermined:
		return nil, fmt.Errorf("%w: the caller's request on the owner session returned no authorization verdict", attack.ErrInconclusive)
	}
	if sessionPrincipalList(ctx, client, ownerSession, anonymousPrincipal, false) != accessRefused {
		return nil, fmt.Errorf("%w: anonymous access to the owner session was not explicitly refused", attack.ErrInconclusive)
	}
	bogus := ownerSession
	bogus.SessionID = "batesian-never-issued-" + random
	if sessionPrincipalList(ctx, client, bogus, caller, false) != accessRefused {
		return nil, fmt.Errorf("%w: the caller's never-issued session control was not refused", attack.ErrInconclusive)
	}
	missing := ownerSession
	missing.SessionID = ""
	if sessionPrincipalList(ctx, client, missing, caller, true) != accessRefused {
		return nil, fmt.Errorf("%w: the caller's missing-session control was not refused", attack.ErrInconclusive)
	}
	finding := attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.RiskIndicator,
		Title: "MCP accepts another principal on an established session",
		Description: "A caller used an owner-created MCP session even though the operator's policy forbids it. " +
			"Both principals had working sessions, the owner's session remained valid, and requests without a valid session or credential were refused. " +
			"Check session ownership at the transport before processing each request.",
		Evidence: fmt.Sprintf("endpoint: %s\nowner: %s\ncaller: %s\nowner session: accepted with owner and caller credentials\ncaller session: accepted\nanonymous on owner session: refused\nnever-issued session: refused\nmissing session: refused\nsession IDs: redacted",
			ownerSession.Endpoint, owner.name, caller.name),
		Remediation: e.rule.Remediation, TargetURL: ownerSession.Endpoint,
		Access: &attack.AccessObservation{Operation: attack.MCPSessionUse, Caller: caller.name,
			CallerTenant: caller.tenant, Owner: owner.name, OwnerTenant: owner.tenant},
	}
	attack.ApplyExpectedDenial(&finding, denials)
	return []attack.Finding{finding}, nil
}
