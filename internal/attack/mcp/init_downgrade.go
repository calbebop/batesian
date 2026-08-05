package mcp

import (
	"context"
	"encoding/json"
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
// was mandated. modernVersion is the version that introduced the authorization
// spec, used as the auth-enforcing baseline.
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

	return probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		return e.probeEndpoint(ctx, client, ep)
	})
}

func (e *InitDowngradeExecutor) probeEndpoint(ctx context.Context, client *attack.HTTPClient, ep string) ([]attack.Finding, bool) {
	// Legacy path: initialize with the pre-auth version, then probe resources/list.
	legacyInitOK, legacyAccess, legacyCount := e.initAndList(ctx, client, ep, legacyVersion)
	if !legacyInitOK {
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
	modernInitOK, modernAccess, _ := e.initAndList(ctx, client, ep, modernVersion)

	// Confirmed downgrade bypass: the modern baseline must exist and be REJECTED
	// (auth enforced) while the legacy session was GRANTED access. If the modern
	// session was also granted access, the server has no auth at all (not a
	// downgrade issue); if legacy was rejected the server is secure.
	if legacyAccess && modernInitOK && !modernAccess {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"MCP protocol downgrade to %q bypasses auth enforced under %q", legacyVersion, modernVersion),
			Description: fmt.Sprintf(
				"At %s, resources/list was REJECTED when the session was initialized with the "+
					"modern protocol version %q (authorization enforced), but SUCCEEDED (returned %d "+
					"resource(s)) when the session was initialized with the legacy pre-auth version %q. "+
					"This confirms that advertising the outdated protocol version bypasses the server's "+
					"authorization checks.",
				ep, modernVersion, legacyCount, legacyVersion),
			Evidence: fmt.Sprintf(
				"Endpoint: %s\nModern (%s) resources/list: rejected\nLegacy (%s) resources/list: %d resource(s) returned",
				ep, modernVersion, legacyVersion, legacyCount),
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
	return looksJSONRPC(resp.BodyString())
}

// initAndList performs an MCP initialize with the given protocol version, sends
// notifications/initialized, then calls resources/list. It returns:
//   - initOK: the initialize produced a valid MCP response (not a version rejection);
//   - access: resources/list passed authorization (HTTP success, a JSON-RPC
//     result, and no JSON-RPC error envelope);
//   - count: number of resources returned (for evidence).
func (e *InitDowngradeExecutor) initAndList(ctx context.Context, client *attack.HTTPClient, ep, version string) (initOK, access bool, count int) {
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
		return false, false, 0
	}
	body := initResp.BodyString()
	// Explicit version rejection (error without a negotiated version).
	if strings.Contains(body, `"error"`) && !strings.Contains(body, `"protocolVersion"`) {
		return false, false, 0
	}
	if !initResp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
		return false, false, 0
	}

	session := mcpSession{Endpoint: ep, SessionID: initResp.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(initResp.Body)}
	_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	listResp, err := client.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "resources/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !listResp.IsSuccess() {
		return true, false, 0
	}
	var rb map[string]interface{}
	if jsonErr := json.Unmarshal(listResp.Body, &rb); jsonErr != nil {
		return true, false, 0
	}
	if _, hasErr := rb["error"]; hasErr {
		return true, false, 0
	}
	result, ok := rb["result"].(map[string]interface{})
	if !ok {
		return true, false, 0
	}
	resources, _ := result["resources"].([]interface{})
	return true, true, len(resources)
}
