package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

type JSONKeyAliasExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-json-key-alias", func(rc attack.RuleContext) attack.Executor {
		return &JSONKeyAliasExecutor{rule: rc}
	})
}

func NewJSONKeyAliasExecutor(rc attack.RuleContext) *JSONKeyAliasExecutor {
	return &JSONKeyAliasExecutor{rule: rc}
}

type keyAliasVerdict int

const (
	keyAliasUnknown keyAliasVerdict = iota
	keyAliasRejected
	keyAliasListed
)

func (e *JSONKeyAliasExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	var incomplete []string
	findings, err := runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		f, determined, reason := e.probeSession(ctx, client, session)
		if reason != "" {
			incomplete = append(incomplete, session.Era.String()+": "+reason)
		}
		return f, determined
	})
	if len(incomplete) != 0 {
		return findings, errors.Join(err, fmt.Errorf("%w: JSON key alias probe incomplete: %s", attack.ErrInconclusive, strings.Join(incomplete, "; ")))
	}
	return findings, err
}

func (e *JSONKeyAliasExecutor) probeSession(ctx context.Context, client *attack.HTTPClient,
	session mcpSession) ([]attack.Finding, bool, string) {
	if !session.ServerSupports("tools") {
		return nil, false, "tools are not advertised"
	}
	if listWithMethodKey(ctx, client, session, 20, "method") != keyAliasListed {
		return nil, false, "canonical tools/list did not return a correlated listing"
	}
	var findings []attack.Finding
	var unknown []string
	for i, variant := range []struct{ key, label, identity string }{
		{"Method", "case-folded", "case-folded"},
		{"method\x00", "NUL-suffixed", "nul-suffixed"},
	} {
		switch listWithMethodKey(ctx, client, session, 21+i, variant.key) {
		case keyAliasListed:
			findings = append(findings, e.finding(session, variant.label, variant.identity))
		case keyAliasUnknown:
			unknown = append(unknown, variant.label)
		}
	}
	if len(unknown) != 0 {
		return findings, false, "ambiguous " + strings.Join(unknown, " and ") + " response"
	}
	return findings, true, ""
}

func listWithMethodKey(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	id int, key string) keyAliasVerdict {
	headers, body := session.request(id, "tools/list", nil)
	if key != "method" {
		delete(body, "method")
		body[key] = "tools/list"
	}
	resp, err := client.POST(ctx, session.Endpoint, headers, body)
	if err != nil || resp == nil {
		return keyAliasUnknown
	}
	// A parsed request without an exact method may be discarded as a notification.
	if resp.StatusCode == http.StatusAccepted && len(resp.Body) == 0 {
		return keyAliasRejected
	}
	parsed, ok := parseResponseBody(resp.Body)
	if !ok {
		return keyAliasUnknown
	}
	if matchesRPCID(parsed, id) && validRPCError(parsed) {
		errObj := parsed["error"].(map[string]interface{})
		switch rpcErrorCode(errObj["code"]) {
		case -32600, -32601, headerMismatchCode:
			return keyAliasRejected
		}
	}
	if !resp.IsSuccess() || !matchesRPCID(parsed, id) || !validRPCResult(parsed) {
		return keyAliasUnknown
	}
	if session.Era == EraModern {
		if modernListProof(resp, nil, id, "tools") {
			return keyAliasListed
		}
		return keyAliasUnknown
	}
	result, ok := parsed["result"].(map[string]interface{})
	if !ok {
		return keyAliasUnknown
	}
	if _, ok := result["tools"].([]interface{}); !ok {
		return keyAliasUnknown
	}
	return keyAliasListed
}

func (e *JSONKeyAliasExecutor) finding(session mcpSession, variant, identity string) attack.Finding {
	endpoint := session.Endpoint
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "low", Confidence: attack.RiskIndicator,
		Title:       "MCP server accepts a " + variant + " JSON-RPC method key",
		Description: "A canonical tools/list request and the same read-only request with a noncanonical method key both returned correlated listings. This is an interpretation difference that could matter when an intermediary enforces policy using exact keys. No intermediary bypass or SDK version was established.",
		Evidence:    "endpoint: " + endpoint + "\ncanonical tools/list: listed\n" + variant + " method key: listed\ntool names and response content omitted",
		Remediation: e.rule.Remediation, TargetURL: endpoint,
		FingerprintKey: session.Era.String() + ":method-key:" + identity,
	}
}
