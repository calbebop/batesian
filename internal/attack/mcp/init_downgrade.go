package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// InitDowngradeExecutor compares unauthenticated access across two handshake
// versions. Accepting an older version alone is not a downgrade bypass.
type InitDowngradeExecutor struct {
	rule attack.RuleContext
}

// NewInitDowngradeExecutor creates an executor for mcp-init-downgrade.
func init() {
	attack.Register("mcp-init-downgrade", func(rc attack.RuleContext) attack.Executor { return NewInitDowngradeExecutor(rc) })
}

func NewInitDowngradeExecutor(r attack.RuleContext) *InitDowngradeExecutor {
	return &InitDowngradeExecutor{rule: r}
}

// Compare the pre-authorization revision with the current auth-enforcing baseline.
const (
	legacyVersion = "2024-11-05"
	modernVersion = latestStable
)

func (e *InitDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	var reachedReason, walkReason string
	findings, err := probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		found, reached, reason := e.probeEndpoint(ctx, client, ep)
		if reached {
			reachedReason = reason
		} else if reason != "" && walkReason == "" {
			walkReason = reason
		}
		return found, reached
	})
	if reachedReason != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, reachedReason)
	}
	if errors.Is(err, attack.ErrInconclusive) && walkReason != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, walkReason)
	}
	return findings, err
}

func (e *InitDowngradeExecutor) probeEndpoint(ctx context.Context, client *attack.HTTPClient, ep string) ([]attack.Finding, bool, string) {
	legacySession, legacyState, legacyReason := e.handshake(ctx, client, ep, legacyVersion)
	switch legacyState {
	case downgradeHandshakeAbsent:
		return nil, false, legacyReason
	case downgradeHandshakeUnsupported:
		return nil, true, ""
	case downgradeHandshakeIncomplete:
		return nil, true, legacyReason
	}

	modernSession, modernState, modernReason := e.handshake(ctx, client, ep, modernVersion)
	switch modernState {
	case downgradeHandshakeUnsupported:
		return nil, true, ""
	case downgradeHandshakeAbsent, downgradeHandshakeIncomplete:
		return nil, true, modernReason
	}

	// ONE list method, advertised by BOTH versions, so the comparison measures the
	// authorization gate and not a capability difference between revisions. A
	// tools-only or prompts-only server has a real downgrade surface on that method;
	// the old hardcoded resources/list probe silently missed it because
	// resources/list returned method-not-found under both versions. era_downgrade
	// compares two wires the same way; here the two versions of one server play
	// that role.
	legacyMethods := advertisedListMethods(legacySession)
	modernMethods := advertisedListMethods(modernSession)
	method := firstCommon(legacyMethods, modernMethods)
	if method == "" {
		if len(legacyMethods) == 0 && len(modernMethods) == 0 {
			// Nothing listable is advertised under either version, so the downgrade
			// concept (a listing gated under one version, open under the other) does
			// not apply here.
			return nil, true, ""
		}
		return nil, true, fmt.Sprintf(
			"the legacy (%s) and modern (%s) versions at %s advertise no listable method in common "+
				"(legacy: %s; modern: %s), so any difference between them would be a capability "+
				"difference rather than an authorization gate",
			legacyVersion, modernVersion, ep, strings.Join(legacyMethods, ", "), strings.Join(modernMethods, ", "))
	}

	legacyAccess, legacyCount := e.probeList(ctx, client, legacySession, method)
	modernAccess, modernCount := e.probeList(ctx, client, modernSession, method)

	// Confirmed downgrade bypass: the modern baseline must be REJECTED (auth
	// enforced) while the legacy session was GRANTED access. If the modern session
	// was also granted access, the server has no auth at all (not a downgrade
	// issue); if legacy was rejected the server is secure.
	//
	// accessUndetermined on EITHER side means there is no comparison to make. It is
	// reported as not tested rather than folded into either verdict: folded into
	// "refused" it invents a critical finding against a server with no authorization at
	// all, and folded into "granted" it hides a real one.
	if legacyAccess == accessUndetermined || modernAccess == accessUndetermined {
		version := legacyVersion
		if legacyAccess != accessUndetermined {
			version = modernVersion
		}
		return nil, true, fmt.Sprintf(
			"%s on the session opened at %s with protocol version %s returned neither a "+
				"result nor a refusal, so the two versions' authorization could not be compared",
			method, ep, version)
	}

	modernEnforced := modernAccess == accessRefused ||
		(modernAccess == accessGranted && modernCount == 0)
	if legacyAccess == accessGranted && legacyCount > 0 && modernEnforced {
		noun := strings.TrimSuffix(method, "/list") // resource, tool, prompt
		modernClause := fmt.Sprintf("%s was REJECTED (authorization enforced)", method)
		modernEvidence := "rejected"
		if modernAccess == accessGranted {
			modernClause = fmt.Sprintf("%s returned 0 %s(s) (authorization enforced via "+
				"result-level filtering)", method, noun)
			modernEvidence = fmt.Sprintf("0 %s(s) returned (filtered)", noun)
		}
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"MCP protocol downgrade to %q bypasses auth enforced under %q", legacyVersion, modernVersion),
			Description: fmt.Sprintf(
				"At %s, %s, but SUCCEEDED (returned %d "+
					"%s(s)) when the session was initialized with the legacy pre-auth version %q. "+
					"This confirms that advertising the outdated protocol version bypasses the server's "+
					"authorization checks.",
				ep, modernClause, legacyCount, noun, legacyVersion),
			Evidence: fmt.Sprintf(
				"Endpoint: %s\nModern (%s) %s: %s\nLegacy (%s) %s: %d %s(s) returned",
				ep, modernVersion, method, modernEvidence, legacyVersion, method, legacyCount, noun),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}}, true, ""
	}

	return nil, true, ""
}

// responsiveMCP accepts negotiated initialization or an MCP-specific, auth, or
// version rejection. It avoids session setup when only responsiveness matters.
func responsiveMCP(ctx context.Context, client *attack.HTTPClient, ep string) bool {
	resp, err := client.POST(ctx, ep, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": modernVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil || !resp.IsSuccess() {
		return false
	}
	return answersMCPInitialize(resp.Body)
}

// mcpMethodNotFound is the JSON-RPC code a server returns for a method it does
// not implement. Real SDKs return it at HTTP 200.
const mcpMethodNotFound = -32601

// answersMCPInitialize accepts a negotiated version, MCP-reserved errors,
// auth-flavored refusals, and protocol-version rejections. Generic JSON-RPC and
// uncertain replies return false so callers report the rule as untested.
func answersMCPInitialize(body []byte) bool {
	// A successful handshake names the negotiated revision. This reads
	// result.protocolVersion directly rather than calling negotiatedVersion, which
	// falls back to latestStable when the server echoed nothing and so never
	// reports absence. That fallback is correct for choosing a header value and
	// wrong for detecting whether this is an MCP server at all.
	var envelope struct {
		Result *struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Result != nil &&
		envelope.Result.ProtocolVersion != "" {
		return true
	}
	code, hasErr := jsonRPCErrorCode(body)
	if !hasErr {
		return false
	}
	// Method not found is the answer from something that does not implement
	// initialize at all, which is what an A2A agent or any other JSON-RPC service
	// returns. It is not an MCP server.
	if code == mcpMethodNotFound {
		return false
	}
	// An error in the range the modern revision reserves is MCP-specific.
	if code >= modernErrCodeMin && code <= modernErrCodeMax {
		return true
	}
	// An auth-flavored MCP error proves the endpoint processed initialize.
	if authFlavoredError(code, jsonRPCErrorMessage(body)) {
		return true
	}
	// Otherwise require the error to be about the protocol version, which is what
	// a legacy server rejecting the offered revision says.
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "protocolversion") ||
		strings.Contains(lower, "protocol version") ||
		strings.Contains(lower, "unsupported protocol")
}

// jsonRPCErrorMessage extracts the error message from a JSON-RPC envelope, or ""
// when there is none.
func jsonRPCErrorMessage(body []byte) string {
	var envelope struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error == nil {
		return ""
	}
	return envelope.Error.Message
}

type downgradeHandshakeState int

const (
	downgradeHandshakeComplete downgradeHandshakeState = iota
	downgradeHandshakeUnsupported
	downgradeHandshakeAbsent
	downgradeHandshakeIncomplete
)

func unsupportedHandshakeVersion(resp *attack.Response) bool {
	if resp == nil {
		return false
	}
	code, ok := jsonRPCErrorCode(resp.Body)
	if !ok {
		return false
	}
	if code == -32022 {
		return true
	}
	message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
	return strings.Contains(message, "version") &&
		(strings.Contains(message, "unsupported") || strings.Contains(message, "not supported"))
}

// handshake opens a session and reports whether the comparison can use it.
func (e *InitDowngradeExecutor) handshake(ctx context.Context, client *attack.HTTPClient, ep, version string) (mcpSession, downgradeHandshakeState, string) {
	initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil || initResp == nil {
		return mcpSession{}, downgradeHandshakeAbsent, fmt.Sprintf(
			"initialize at %s with protocol version %s did not answer", ep, version)
	}
	if endpointAbsent(initResp) {
		return mcpSession{}, downgradeHandshakeAbsent, ""
	}
	if unsupportedHandshakeVersion(initResp) {
		return mcpSession{}, downgradeHandshakeUnsupported, ""
	}
	if initResp.StatusCode == 401 || initResp.StatusCode == 403 {
		return mcpSession{}, downgradeHandshakeIncomplete, fmt.Sprintf(
			"initialize at %s with protocol version %s was refused (HTTP %d)",
			ep, version, initResp.StatusCode)
	}
	if !initResp.IsSuccess() || !initializeSucceeded(initResp.Body) {
		state := downgradeHandshakeIncomplete
		if !answersMCPInitialize(initResp.Body) {
			state = downgradeHandshakeAbsent
		}
		return mcpSession{}, state, fmt.Sprintf(
			"initialize at %s with protocol version %s did not complete (HTTP %d)",
			ep, version, initResp.StatusCode)
	}
	session := mcpSession{
		Endpoint:        ep,
		SessionID:       initResp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(initResp.Body),
		RawInit:         initResp.Body,
	}
	initialized, initErr := client.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	if initErr != nil || initialized == nil || !initialized.IsSuccess() {
		return mcpSession{}, downgradeHandshakeIncomplete, fmt.Sprintf(
			"notifications/initialized at %s with protocol version %s did not complete", ep, version)
	}
	if _, rejected := jsonRPCErrorCode(initialized.Body); rejected {
		return mcpSession{}, downgradeHandshakeIncomplete, fmt.Sprintf(
			"notifications/initialized at %s with protocol version %s returned a JSON-RPC error", ep, version)
	}
	return session, downgradeHandshakeComplete, ""
}

// probeList calls a read-only listing on session and reports its access verdict
// and the number of items returned. The result array is keyed by the capability:
// resources/list -> "resources", tools/list -> "tools", prompts/list -> "prompts".
//
// classifyAccess, not err != nil || !IsSuccess(). Deriving "refused" from the
// absence of acceptance made a transport failure, a 429 from a rate limiter and a
// one-off 502 indistinguishable from an authorization refusal, and "the modern
// version refused" is the finding-enabling half of the comparison in probeEndpoint.
// era_downgrade was fixed for exactly this; this rule kept the collapsed form until
// the probe method became selectable.
func (e *InitDowngradeExecutor) probeList(ctx context.Context, client *attack.HTTPClient, session mcpSession, method string) (accessVerdict, int) {
	resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  method,
		"params":  map[string]interface{}{},
	})
	verdict := classifyAccess(resp, err, 2)
	if verdict != accessGranted {
		return verdict, 0
	}
	var rb map[string]interface{}
	if jsonErr := json.Unmarshal(resp.Body, &rb); jsonErr != nil {
		return accessUndetermined, 0
	}
	result, ok := rb["result"].(map[string]interface{})
	if !ok {
		// Accepted by the transport oracle but carrying no result object: nothing was
		// refused and nothing was listed.
		return accessUndetermined, 0
	}
	items, _ := result[strings.TrimSuffix(method, "/list")].([]interface{})
	return accessGranted, len(items)
}
