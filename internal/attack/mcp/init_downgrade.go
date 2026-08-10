package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// InitDowngradeExecutor probes whether advertising the pre-auth MCP protocol
// version "2024-11-05" lets a caller bypass authorization that the server
// enforces under a modern (post-auth-spec) version (rule mcp-init-downgrade-001).
//
// Accepting/negotiating an older protocol version is itself SPEC-COMPLIANT - the
// MCP version-negotiation rules allow a server to honour a supported older
// version - so it is NOT reported as a finding on its own. The vulnerability is
// specifically a DOWNGRADE AUTH BYPASS, which requires a discriminator:
//
//   - Initialize with a MODERN version (post-auth-spec) and call resources/list:
//     observe it is REJECTED (auth enforced) - this is the baseline.
//   - Initialize with the LEGACY version and call resources/list: observe it
//     SUCCEEDS.
//
// Only modern-rejected + legacy-accepted is a confirmed downgrade bypass. If both
// succeed the server simply has no auth at all (that is mcp-resources-unauth's
// job, not a downgrade), and if both are rejected the server is secure - neither
// produces a finding here.
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

// legacyVersion is the pre-OAuth MCP spec version published before authorization
// was mandated. modernVersion is the auth-enforcing baseline it is compared
// against: the current handshake revision, which specifies authorization.
//
// It tracks latestStable rather than naming a revision, because what the oracle
// needs is a version that mandates authorization AND that a current server will
// accept, and those are the same thing. The comment here used to call it "the
// version that introduced the authorization spec", which it was not: authorization
// arrived before the revision this then pointed at.
const (
	legacyVersion = "2024-11-05"
	modernVersion = latestStable
)

func (e *InitDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Probe UNAUTHENTICATED. This rule detects a server that enforces
	// authorization under the modern protocol version but not under the legacy
	// one. If we attached opts.Token, a server that gates the modern path on a
	// valid token would grant it, so the discriminator (modern REJECTED + legacy
	// GRANTED) could never fire - silently masking the very bug we look for. A
	// downgrade auth bypass is, by definition, reaching protected functionality
	// WITHOUT proper credentials, so the probe must run with no bearer token.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// Why no candidate could be compared, so an undetermined probe does not surface as
	// the generic "could not reach a testable endpoint". The endpoint WAS reached; it
	// answered one of the two baselines with something that refuses nothing.
	var observed initObservation
	findings, err := probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		return e.probeEndpoint(ctx, client, ep, &observed)
	})
	if errors.Is(err, attack.ErrInconclusive) && observed.rank > rankNothing {
		return nil, inconclusive(handshakeRefusal{observed.reason})
	}
	return findings, err
}

func (e *InitDowngradeExecutor) probeEndpoint(ctx context.Context, client *attack.HTTPClient, ep string,
	observed *initObservation) ([]attack.Finding, bool) {
	// Legacy path: initialize with the pre-auth version. The probe method is
	// chosen below from the server's advertised capabilities, not hardcoded.
	legacyOK, legacySession := e.handshake(ctx, client, ep, legacyVersion)
	if !legacyOK {
		// The legacy initialize did not succeed. Distinguish "not an MCP
		// endpoint" from "a server that speaks MCP but rejects this version" by
		// probing whether the endpoint answers initialize with a JSON-RPC
		// response at all. A version-rejection error still counts as reached:
		// the endpoint is testable, it just declined the offered version.
		if !responsiveMCP(ctx, client, ep) {
			return nil, false // not a responsive MCP endpoint
		}
		return nil, true // reached, but the offered version was rejected - nothing to confirm
	}

	// Modern baseline: does the server enforce auth under the post-auth version?
	// A server that does not speak the modern revision has no modern baseline to
	// compare against; an old server that only supports the legacy version is not a
	// downgrade bypass. The rule requires the modern path to exist and be rejected
	// while the legacy path is granted.
	modernOK, modernSession := e.handshake(ctx, client, ep, modernVersion)
	if !modernOK {
		return nil, true
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
			return nil, true
		}
		observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
			"the legacy (%s) and modern (%s) versions at %s advertise no listable method in common "+
				"(legacy: %s; modern: %s), so any difference between them would be a capability "+
				"difference rather than an authorization gate",
			legacyVersion, modernVersion, ep, strings.Join(legacyMethods, ", "), strings.Join(modernMethods, ", "))})
		return nil, false
	}

	legacyAccess, legacyCount := e.probeList(ctx, client, legacySession, method)
	modernAccess, _ := e.probeList(ctx, client, modernSession, method)

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
		observed.observe(initObservation{rankStatusOnly, fmt.Sprintf(
			"%s on the session opened at %s with protocol version %s returned neither a "+
				"result nor a refusal, so the two versions' authorization could not be compared",
			method, ep, version)})
		return nil, false
	}

	if legacyAccess == accessGranted && modernAccess == accessRefused {
		noun := strings.TrimSuffix(method, "/list") // resource, tool, prompt
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"MCP protocol downgrade to %q bypasses auth enforced under %q", legacyVersion, modernVersion),
			Description: fmt.Sprintf(
				"At %s, %s was REJECTED when the session was initialized with the "+
					"modern protocol version %q (authorization enforced), but SUCCEEDED (returned %d "+
					"%s(s)) when the session was initialized with the legacy pre-auth version %q. "+
					"This confirms that advertising the outdated protocol version bypasses the server's "+
					"authorization checks.",
				ep, method, modernVersion, legacyCount, noun, legacyVersion),
			Evidence: fmt.Sprintf(
				"Endpoint: %s\nModern (%s) %s: rejected\nLegacy (%s) %s: %d %s(s) returned",
				ep, modernVersion, method, legacyVersion, method, legacyCount, noun),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}}, true
	}

	return nil, true
}

// responsiveMCP reports whether ep answered an MCP initialize with a JSON-RPC
// response (a result OR an error envelope). A version-rejection error still
// counts: the endpoint speaks MCP, it just declined the offered version, so the
// rule reached a testable endpoint (clean) rather than being unable to test.
//
// One request, and no session bookkeeping, which is why the OAuth-gated rules use
// it rather than a full handshake to answer "is this even an MCP server".
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

// answersMCPInitialize reports whether a reply to an MCP initialize came from
// something that actually implements MCP.
//
// This used to be looksJSONRPC, which matches any body containing "jsonrpc",
// "result", "error" or "protocolVersion" — that is every JSON-RPC service in
// existence. Since this oracle decides clean-versus-skipped for five rules, an A2A
// agent answering `-32601 Method not found` to initialize was accepted as an MCP
// server and mcp-oauth-dcr-001, mcp-confused-deputy-001,
// mcp-oauth-metadata-ssrf-001, mcp-token-replay-001 and mcp-init-downgrade-001 all
// reported it clean, with nothing skipped. The A2A side already guards the mirror
// of this with answersMCPInitialize in a2a/endpoint.go; the MCP side never did.
//
// A version rejection still counts, deliberately: the endpoint speaks MCP and only
// declined the offered revision, which is a reachable endpoint rather than an
// untestable one. That is why this cannot simply require a result envelope.
//
// Uncertain cases resolve to false, so the rule reports not-tested rather than
// clean. That is the direction this project errs in.
// mcpMethodNotFound is the JSON-RPC code a server returns for a method it does
// not implement. Real SDKs return it at HTTP 200.
const mcpMethodNotFound = -32601

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
	// An auth rejection also proves an endpoint is listening and processing the
	// request, which is what this oracle asks. Excluding it would give every
	// credential-gated MCP server a spurious "not tested" on all five OAuth rules
	// when the honest answer is that it publishes no OAuth metadata and there is
	// nothing for them to test. Measured against
	// testdata/mcp_secret_canary_server.py, which answers initialize with
	// -32000 "authentication failed for token".
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

// handshake opens an MCP session at ep with the given protocol version and
// returns it with the server's advertised capabilities captured in RawInit, so
// the probe method can be chosen from what the server actually implements.
// initOK is false when the initialize was rejected (version unsupported) or did
// not yield a valid MCP response.
func (e *InitDowngradeExecutor) handshake(ctx context.Context, client *attack.HTTPClient, ep, version string) (bool, mcpSession) {
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
	if err != nil || !initResp.IsSuccess() {
		return false, mcpSession{}
	}
	body := initResp.BodyString()
	// Explicit version rejection (error without a negotiated version).
	if strings.Contains(body, `"error"`) && !strings.Contains(body, `"protocolVersion"`) {
		return false, mcpSession{}
	}
	if !initResp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
		return false, mcpSession{}
	}
	session := mcpSession{
		Endpoint:        ep,
		SessionID:       initResp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(initResp.Body),
		RawInit:         initResp.Body,
	}
	_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	return true, session
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
	verdict := classifyAccess(resp, err)
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
