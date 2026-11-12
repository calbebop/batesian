package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// HeaderBodySplitExecutor checks modern MCP header/body consistency.
type HeaderBodySplitExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-header-body-split", func(rc attack.RuleContext) attack.Executor {
		return NewHeaderBodySplitExecutor(rc)
	})
}

func NewHeaderBodySplitExecutor(r attack.RuleContext) *HeaderBodySplitExecutor {
	return &HeaderBodySplitExecutor{rule: r}
}

func (e *HeaderBodySplitExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	sessions, sessionErr := openSessions(ctx, client, vars.BaseURL)
	defer closeLegacySessions(ctx, client, sessions)
	if len(sessions) == 0 {
		return nil, sessionErr
	}

	modernSeen := false
	var blocked []string
	anyTested := false
	var findings []attack.Finding
	for _, session := range sessions {
		if session.Era != EraModern || session.ProtocolVersion != headerValidationVersion {
			continue
		}
		modernSeen = true
		record := func(f []attack.Finding, tested bool, reason string) {
			findings = append(findings, labelEra(session, f)...)
			anyTested = anyTested || tested
			if reason != "" {
				blocked = append(blocked, reason)
			}
		}
		record(e.probe(ctx, client, session))
		record(e.probeVersion(ctx, client, session))
		record(e.probeName(ctx, client, session))
	}
	if !modernSeen {
		return nil, errors.Join(sessionErr, fmt.Errorf("%w: header validation requires the %s wire", attack.ErrInconclusive, headerValidationVersion))
	}
	if len(findings) > 0 {
		return findings, nil
	}
	if len(blocked) > 0 {
		return findings, errors.Join(sessionErr, fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(blocked, "; ")))
	}
	if sessionErr != nil {
		return nil, sessionErr
	}
	if !anyTested {
		return nil, attack.ErrInconclusive
	}
	return nil, nil
}

// headerValidationVersion is the revision that introduced Mcp-Method mirroring
// and the -32020 HeaderMismatch rejection this rule tests for.
const headerValidationVersion = modernEraVersion

// probe compares matched and mismatched Mcp-Method requests.
func (e *HeaderBodySplitExecutor) probe(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, tested bool, blocked string) {
	if e.toolsList(ctx, client, session, nil) != accessGranted {
		return nil, false, "matching tools/list control did not return a listing"
	}
	switch e.toolsList(ctx, client, session, mismatchMethodHeader) {
	case accessUndetermined:
		return nil, false, "mismatched Mcp-Method request returned neither a listing nor 400/-32020"
	case accessRefused:
		switch e.toolsList(ctx, client, session, caseFoldedMethodHeader) {
		case accessGranted:
			return []attack.Finding{e.caseFoldedFinding(session)}, true, ""
		case accessUndetermined:
			return nil, false, "case-folded Mcp-Method request returned neither a listing nor 400/-32020"
		}
		return nil, true, ""
	}
	return []attack.Finding{
		{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "MCP server accepts a mismatched Mcp-Method header",
			Description: fmt.Sprintf(
				"At %s, a matching tools/list control returned a listing, and the same body with "+
					"Mcp-Method: tools/call also returned a listing. MCP 2026-07-28 requires "+
					"400/-32020 for this mismatch. Header-based gateway policy was not tested.",
				session.Endpoint),
			Evidence: fmt.Sprintf(
				"endpoint: %s\nmatching tools/list: listed\nMcp-Method: tools/call with body tools/list: listed",
				session.Endpoint),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		},
	}, true, ""
}

func mismatchMethodHeader(h map[string]string) { h["Mcp-Method"] = "tools/call" }

const mismatchedHeaderVersion = "2025-11-25"

func (e *HeaderBodySplitExecutor) probeVersion(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]attack.Finding, bool, string) {
	if e.toolsList(ctx, client, session, nil) != accessGranted {
		return nil, false, "matching MCP-Protocol-Version control did not return a listing"
	}
	verdict := e.toolsList(ctx, client, session, func(h map[string]string) {
		h["MCP-Protocol-Version"] = mismatchedHeaderVersion
	})
	switch verdict {
	case accessRefused:
		return nil, true, ""
	case accessUndetermined:
		return nil, false, "mismatched MCP-Protocol-Version request returned neither a listing nor 400/-32020"
	}
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title:      "MCP server accepts a mismatched protocol-version header",
		Description: fmt.Sprintf(
			"At %s, a tools/list request using the advertised %s version returned a listing. "+
				"The same body also returned a listing when MCP-Protocol-Version was %s. "+
				"MCP 2026-07-28 requires 400/-32020 for this mismatch. Gateway policy was not tested.",
			session.Endpoint, headerValidationVersion, mismatchedHeaderVersion),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nmatching version: listed\nbody version: %s\nheader version: %s\nmismatch: listed",
			session.Endpoint, headerValidationVersion, mismatchedHeaderVersion),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}, true, ""
}

// toolsList accepts only a matching listing or an explicit header-mismatch rejection.
func (e *HeaderBodySplitExecutor) toolsList(ctx context.Context, client *attack.HTTPClient, session mcpSession, shape func(map[string]string)) accessVerdict {
	resp, err := session.postShaping(ctx, client, 2, "tools/list", nil, shape)
	if err != nil || resp == nil {
		return accessUndetermined
	}
	b, ok := parseResponseBody(resp.Body)
	if !ok || !matchesRPCID(b, 2) {
		return accessUndetermined
	}
	if resp.StatusCode == http.StatusBadRequest && validRPCError(b) {
		if rpcErrorCode(b["error"].(map[string]interface{})["code"]) == headerMismatchCode {
			return accessRefused
		}
	}
	if resp.IsSuccess() && validRPCResult(b) {
		result, ok := b["result"].(map[string]interface{})
		if ok {
			if _, ok := result["tools"].([]interface{}); ok {
				return accessGranted
			}
		}
	}
	return accessUndetermined
}

// nameProbeSubject is absent from the target, keeping name probes read-only.
const nameProbeSubject = "batesian-nonexistent-subject"

// tools/call is excluded because a mismatched header could execute the tool.
type nameBearingProbe struct {
	method     string
	field      string
	capability string
}

var nameBearingProbes = []nameBearingProbe{
	{"resources/read", "uri", "resources"},
	{"prompts/get", "name", "prompts"},
}

// probeName compares matching and mismatched Mcp-Name reads.
func (e *HeaderBodySplitExecutor) probeName(ctx context.Context, client *attack.HTTPClient,
	session mcpSession) (findings []attack.Finding, tested bool, blocked string) {
	for _, np := range nameBearingProbes {
		if !session.ServerSupports(np.capability) {
			continue
		}
		params := map[string]interface{}{np.field: nameProbeSubject}

		control := e.nameVerdict(ctx, client, session, np, params, nil)
		switch control {
		case nameNotImplemented:
			blocked = "the server advertised " + np.capability + " but " + np.method + " returned method not found"
			continue
		case nameUndetermined, nameRejected:
			blocked = "matching " + np.method + " control did not reach the named subject"
			continue
		}

		mismatched := e.nameVerdict(ctx, client, session, np, params, func(h map[string]string) {
			h["Mcp-Name"] = nameProbeSubject + "-different"
		})
		switch mismatched {
		case nameRejected:
			tested = true
		case nameDispatched:
			return []attack.Finding{e.nameMismatchFinding(session, np)}, true, ""
		default:
			blocked = "mismatched Mcp-Name request for " + np.method + " returned neither a dispatched answer nor 400/-32020"
		}
	}
	return nil, tested, blocked
}

// nameVerdict grades one shaped name-bearing call by which error came back.
type nameVerdict int

const (
	// nameUndetermined: a transport failure, or an answer that settles nothing.
	nameUndetermined nameVerdict = iota
	// nameRejected: -32020 HeaderMismatch, so the header was validated.
	nameRejected
	// nameDispatched: the server acted on the body rather than rejecting the
	// header, whether it answered a result or a subject-not-found error.
	nameDispatched
	// nameNotImplemented: -32601, so this method is not a surface here.
	nameNotImplemented
)

func (e *HeaderBodySplitExecutor) nameVerdict(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, np nameBearingProbe, params map[string]interface{},
	shape func(map[string]string)) nameVerdict {
	resp, err := session.postShaping(ctx, client, 3, np.method, params, shape)
	if err != nil || resp == nil {
		return nameUndetermined
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok || !matchesRPCID(body, 3) {
		return nameUndetermined
	}
	if resp.IsSuccess() && validRPCResult(body) {
		// A result for a subject that does not exist is odd, but it is still the
		// server acting on the body rather than rejecting the header.
		return nameDispatched
	}
	if !validRPCError(body) {
		return nameUndetermined
	}
	code := rpcErrorCode(body["error"].(map[string]interface{})["code"])
	if resp.StatusCode == http.StatusBadRequest && code == headerMismatchCode {
		return nameRejected
	}
	if !resp.IsSuccess() {
		return nameUndetermined
	}
	if code == mcpMethodNotFound {
		return nameNotImplemented
	}
	message, _ := body["error"].(map[string]interface{})["message"].(string)
	if strings.Contains(strings.ToLower(message), "not found") && strings.Contains(message, nameProbeSubject) {
		return nameDispatched
	}
	return nameUndetermined
}

// Method values are case-sensitive even though HTTP header names are not.
func caseFoldedMethodHeader(h map[string]string) { h["Mcp-Method"] = "TOOLS/LIST" }

func (e *HeaderBodySplitExecutor) nameMismatchFinding(session mcpSession, np nameBearingProbe) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title:      "MCP server accepts a mismatched Mcp-Name header",
		Description: fmt.Sprintf(
			"At %s, matching and mismatched Mcp-Name requests both reached %s for the same "+
				"nonexistent params.%s subject. MCP 2026-07-28 requires 400/-32020 for the "+
				"mismatch. Header-based gateway policy was not tested.",
			session.Endpoint, np.method, np.field),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nmethod: %s\nmatching Mcp-Name: subject reached\n"+
				"Mcp-Name disagreeing with params.%s: subject reached\nsubject: nonexistent control",
			session.Endpoint, np.method, np.field),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}

func (e *HeaderBodySplitExecutor) caseFoldedFinding(session mcpSession) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title:      "MCP server compares the Mcp-Method value case-insensitively (SEP-2243)",
		Description: fmt.Sprintf(
			"At %s, a tools/list request with Mcp-Method: tools/call was rejected, but "+
				"the same body with Mcp-Method: TOOLS/LIST returned a listing. MCP 2026-07-28 "+
				"requires a case-sensitive value match and 400/-32020 on mismatch. "+
				"Header-based gateway policy was not tested.",
			session.Endpoint),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nMcp-Method: tools/call with body tools/list: 400/-32020\n"+
				"Mcp-Method: TOOLS/LIST with body tools/list: listed",
			session.Endpoint),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}
