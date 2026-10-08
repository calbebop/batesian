package mcp

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

type ParamHeaderMismatchExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-param-header-mismatch", func(rc attack.RuleContext) attack.Executor {
		return &ParamHeaderMismatchExecutor{rule: rc}
	})
}

func (e *ParamHeaderMismatchExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	sessions, err := openSessions(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, err
	}

	modernSeen := false
	var reason string
	for _, session := range sessions {
		if session.Era != EraModern {
			continue
		}
		modernSeen = true
		if !session.ServerSupports("tools") {
			reason = "the modern wire does not advertise tools"
			continue
		}
		findings, why := e.probe(ctx, client, session, opts.MCPInvokeTools, vars.RandID)
		if why == "" {
			return labelEra(session, findings), nil
		}
		reason = why
	}
	if !modernSeen {
		return nil, fmt.Errorf("%w: no MCP %s wire was found at %s", attack.ErrInconclusive, modernEraVersion, vars.BaseURL)
	}
	return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, reason)
}

func (e *ParamHeaderMismatchExecutor) probe(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	approved []string, randID string) ([]attack.Finding, string) {
	tool, ok, pending, listed := teFindSafeToolFiltered(ctx, client, session, approved, true)
	if !listed {
		return nil, "tools/list returned no usable answer on the modern wire"
	}
	if !ok {
		if len(pending) > 0 {
			sort.Strings(pending)
			return nil, "approve an exact annotated read-only tool with --mcp-invoke-tool: " + strings.Join(pending, ", ")
		}
		return nil, "no annotated read-only tool was available for parameter-header probes"
	}

	args := synthesizeArgs(tool.schema, randID)
	header, original, changed, ok := mismatchedParamHeader(tool.schema, args)
	if !ok {
		return nil, "the approved tool had no usable annotated argument"
	}
	params := map[string]interface{}{"name": tool.name, "arguments": args}
	baseline, baseErr := session.postToolShaping(ctx, client, 31, params, tool.schema, nil)
	if !completedToolCall(baseline, baseErr, 31) {
		return nil, fmt.Sprintf("matching parameter headers did not complete %q", tool.name)
	}

	mismatch, mismatchErr := session.postToolShaping(ctx, client, 32, params, tool.schema, func(headers map[string]string) {
		headers[header] = changed
	})
	if rejectedParamMismatch(mismatch, mismatchErr, 32) {
		return nil, ""
	}
	if !completedToolCall(mismatch, mismatchErr, 32) {
		return nil, fmt.Sprintf("mismatched %s returned neither a completed tool result nor 400/-32020", header)
	}
	return []attack.Finding{{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    "medium",
		Confidence:  attack.RiskIndicator,
		Title:       "MCP annotated parameter header/body mismatch accepted",
		Description: fmt.Sprintf("The server completed %q even though %s disagreed with the tool argument. A gateway that routes or applies policy using that header may disagree with the tool's actual input.", tool.name, header),
		Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\nmatching %s: %s (completed)\nmismatched %s: %s (completed)", session.Endpoint, tool.name, header, original, header, changed),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}, ""
}

func mismatchedParamHeader(schema, args map[string]interface{}) (name, original, changed string, ok bool) {
	var bindings []toolHeaderBinding
	if collectToolHeaderBindings(schema, nil, true, map[string]bool{}, &bindings) != nil {
		return "", "", "", false
	}
	headers, err := toolParamHeaders(schema, args)
	if err != nil {
		return "", "", "", false
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].name < bindings[j].name })
	for _, binding := range bindings {
		name = "Mcp-Param-" + binding.name
		original, ok = headers[name]
		if !ok {
			continue
		}
		switch binding.kind {
		case "string":
			changed = "batesian-header-mismatch"
			if original == changed {
				changed += "-2"
			}
		case "integer":
			changed = "0"
			if original == "0" {
				changed = "1"
			}
		case "boolean":
			changed = "true"
			if original == "true" {
				changed = "false"
			}
		default:
			continue
		}
		return name, original, changed, true
	}
	return "", "", "", false
}

func completedToolCall(resp *attack.Response, err error, id int) bool {
	verdict, body := classifyProbe(resp, err, id)
	if verdict != probeAnswered || !validRPCResult(body) {
		return false
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" || result["isError"] == true {
		return false
	}
	_, ok = result["content"].([]interface{})
	return ok
}

func rejectedParamMismatch(resp *attack.Response, err error, id int) bool {
	if err != nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		return false
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok || !matchesRPCID(body, id) || !validRPCError(body) {
		return false
	}
	errorBody := body["error"].(map[string]interface{})
	return rpcErrorCode(errorBody["code"]) == headerMismatchCode
}
