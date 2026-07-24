package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/calbebop/batesian/internal/attack"
)

// CompletionUnauthExecutor probes whether the MCP completion/complete method is
// reachable without authentication (rule mcp-completion-unauth-001).
//
// completion/complete returns autocompletion suggestions for prompt arguments
// and resource-template URIs. The MCP spec requires implementations to "control
// access to sensitive suggestions" and "prevent completion-based information
// disclosure". An unauthenticated completion endpoint is therefore an access
// control failure and, more concretely, an enumeration oracle: an anonymous
// caller can fuzz argument values or URI-template segments and read back valid
// completions (usernames, file paths, identifiers) the operator never meant to
// expose.
//
// SAFETY: completion/complete is read-only; it never executes a tool or mutates
// state. The probe sends a benign empty argument value.
type CompletionUnauthExecutor struct {
	rule attack.RuleContext
}

// register the executor for the mcp-completion-unauth attack type.
func init() {
	attack.Register("mcp-completion-unauth", func(rc attack.RuleContext) attack.Executor { return NewCompletionUnauthExecutor(rc) })
}

// NewCompletionUnauthExecutor creates an executor for mcp-completion-unauth.
func NewCompletionUnauthExecutor(r attack.RuleContext) *CompletionUnauthExecutor {
	return &CompletionUnauthExecutor{rule: r}
}

// maxRealRefs bounds how many discovered prompt/resource references the rule
// probes, so a server with many prompts does not turn one rule into a flood.
const maxRealRefs = 8

// completionRef is a completion/complete reference paired with the argument name
// to complete. real marks refs discovered from the live server (prompt or
// resource template), which can yield an actual disclosure oracle; synthetic
// refs only establish that the method dispatches without auth.
type completionRef struct {
	params  map[string]interface{}
	argName string
	real    bool
	label   string
}

// completionOutcome records the result of a single reachable completion probe.
type completionOutcome struct {
	ref    completionRef
	status int
	reason string
	values []string
}

// templateVar extracts the first RFC 6570 variable name from a URI template,
// e.g. "file:///{path}" -> "path", "db://{+table}/{id}" -> "table". Returns no
// match when the template declares no variable.
var templateVar = regexp.MustCompile(`\{[+#./;?&]?([A-Za-z0-9_]+)`)

func (e *CompletionUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token - the rule tests whether completion is
	// reachable WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, attack.ErrInconclusive // not an MCP server
	}

	// Skip servers that do not advertise the completions capability; probing them
	// would produce meaningless noise. Read from the captured handshake object
	// rather than substring-matching the body.
	if !session.ServerSupports("completions") {
		return nil, nil
	}

	// Probe real refs discovered from the live server first, preferring one that
	// actually leaks suggestion values (the disclosure oracle). Track the first
	// reachable probe so reachability is reported even when no ref discloses.
	var firstReachable, disclosure *completionOutcome
	for _, ref := range e.discoverRefs(ctx, client, session) {
		out := e.probe(ctx, client, session, ref)
		if out == nil {
			continue
		}
		if firstReachable == nil {
			firstReachable = out
		}
		if len(out.values) > 0 {
			disclosure = out
			break
		}
	}

	// If no real ref was reachable (e.g. prompts/resources listing is itself
	// auth-gated, or the server exposes none), fall back to a synthetic prompt
	// reference so the rule still establishes reachability. A server that gates
	// completion answers this with 401/403 or an auth error and stays silent.
	if firstReachable == nil {
		synth := completionRef{
			params:  map[string]interface{}{"type": "ref/prompt", "name": "batesian-nonexistent-" + vars.RandID},
			argName: "batesian_probe",
			real:    false,
			label:   "synthetic probe ref",
		}
		firstReachable = e.probe(ctx, client, session, synth)
	}

	if firstReachable == nil {
		return nil, nil
	}

	// Base the reachability finding on the disclosure probe when one was found, so
	// both findings describe the same reference.
	base := firstReachable
	if disclosure != nil {
		base = disclosure
	}

	findings := []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP completion/complete reachable without authentication",
		Description: fmt.Sprintf(
			"completion/complete at %s dispatched an unauthenticated request (probed via %s). The MCP "+
				"spec requires servers to control access to completion suggestions and prevent "+
				"completion-based information disclosure; an anonymous caller can use this endpoint as an "+
				"enumeration oracle, fuzzing argument values or URI-template segments to recover valid "+
				"completions.", session.Endpoint, base.ref.label),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprobe: %s\n%s", base.status, session.Endpoint, base.ref.label, base.reason),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}

	// Escalate when a real ref returned actual suggestion values: the endpoint is
	// not just reachable but is leaking valid completions to an anonymous caller.
	if disclosure != nil {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      fmt.Sprintf("MCP completion/complete disclosed suggestion values without authentication (%s)", disclosure.ref.label),
			Description: fmt.Sprintf(
				"completion/complete for %s at %s returned %d suggestion value(s) to an unauthenticated "+
					"caller. Completions expose valid argument values and URI-template segments (identifiers, "+
					"file paths, usernames), giving an attacker a live enumeration oracle over the server's "+
					"internal namespace.", disclosure.ref.label, session.Endpoint, len(disclosure.values)),
			Evidence:    fmt.Sprintf("HTTP %d from %s\n%s\nvalues (%d): %v", disclosure.status, session.Endpoint, disclosure.ref.label, len(disclosure.values), sampleValues(disclosure.values)),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
	}

	return findings, nil
}

// probe sends a single unauthenticated completion/complete request for ref and
// returns the outcome if the handler was reached, or nil on an HTTP auth gate,
// transport error, or a non-dispatching JSON-RPC error. Suggestion values are
// captured only for real refs (synthetic refs never disclose real data).
func (e *CompletionUnauthExecutor) probe(ctx context.Context, client *attack.HTTPClient, session mcpSession, ref completionRef) *completionOutcome {
	resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "completion/complete",
		// An empty value asks the server to enumerate all suggestions for the
		// argument. Fuzzy/prefix matchers (the common implementation) return their
		// full candidate set for the empty prefix, which is exactly the
		// enumerate-everything behavior an attacker abuses; a non-empty probe value
		// would be silently filtered out against namespaces that do not share its
		// prefix (e.g. numeric identifiers).
		"params": map[string]interface{}{
			"ref":      ref.params,
			"argument": map[string]interface{}{"name": ref.argName, "value": ""},
		},
	})
	if err != nil || !resp.IsSuccess() {
		return nil
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil
	}
	reachable, reason := completionDispatchReachable(body)
	if !reachable {
		return nil
	}
	out := &completionOutcome{ref: ref, status: resp.StatusCode, reason: reason}
	if ref.real {
		out.values = completionValues(body)
	}
	return out
}

// discoverRefs returns real completion references built from the server's live
// prompts and resource templates (capped at maxRealRefs). Each requires an
// argument name to complete: a prompt argument, or a URI-template variable.
func (e *CompletionUnauthExecutor) discoverRefs(ctx context.Context, client *attack.HTTPClient, session mcpSession) []completionRef {
	var refs []completionRef

	if session.ServerSupports("prompts") {
		refs = append(refs, promptRefs(ctx, client, session)...)
	}
	if session.ServerSupports("resources") {
		refs = append(refs, resourceTemplateRefs(ctx, client, session)...)
	}

	if len(refs) > maxRealRefs {
		refs = refs[:maxRealRefs]
	}
	return refs
}

// promptRefs lists prompts and builds a completion ref for every prompt argument.
func promptRefs(ctx context.Context, client *attack.HTTPClient, session mcpSession) []completionRef {
	body, ok := rpcResult(ctx, client, session, "prompts/list")
	if !ok {
		return nil
	}
	prompts, _ := body["prompts"].([]interface{})
	var refs []completionRef
	for _, p := range prompts {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := pm["name"].(string)
		if name == "" {
			continue
		}
		args, _ := pm["arguments"].([]interface{})
		for _, a := range args {
			am, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			an, _ := am["name"].(string)
			if an == "" {
				continue
			}
			refs = append(refs, completionRef{
				params:  map[string]interface{}{"type": "ref/prompt", "name": name},
				argName: an,
				real:    true,
				label:   fmt.Sprintf("prompt %q argument %q", name, an),
			})
		}
	}
	return refs
}

// resourceTemplateRefs lists resource templates and builds a completion ref for
// the first variable of every template that declares one.
func resourceTemplateRefs(ctx context.Context, client *attack.HTTPClient, session mcpSession) []completionRef {
	body, ok := rpcResult(ctx, client, session, "resources/templates/list")
	if !ok {
		return nil
	}
	templates, _ := body["resourceTemplates"].([]interface{})
	var refs []completionRef
	for _, t := range templates {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		ut, _ := tm["uriTemplate"].(string)
		m := templateVar.FindStringSubmatch(ut)
		if m == nil {
			continue
		}
		refs = append(refs, completionRef{
			params:  map[string]interface{}{"type": "ref/resource", "uri": ut},
			argName: m[1],
			real:    true,
			label:   fmt.Sprintf("resource template %q variable %q", ut, m[1]),
		})
	}
	return refs
}

// rpcResult issues a paramless JSON-RPC call without auth and returns the
// result object, or ok=false on any transport failure, non-2xx, or JSON-RPC
// error (which means the listing itself is gated and yields no usable ref).
func rpcResult(ctx context.Context, client *attack.HTTPClient, session mcpSession, method string) (map[string]interface{}, bool) {
	resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  method,
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return nil, false
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, false
	}
	if _, hasErr := body["error"]; hasErr {
		return nil, false
	}
	result, ok := body["result"].(map[string]interface{})
	return result, ok
}

// completionDispatchReachable reports whether a completion/complete response
// shows the handler was reached without auth. A completion result, any result
// envelope, or a -32602 (invalid params / invalid prompt name) protocol error
// all mean the call dispatched. A -32601 (capability not supported), an
// auth-flavored error, or any other error does not. The reason is used as
// finding evidence.
func completionDispatchReachable(body map[string]interface{}) (bool, string) {
	if errObj, ok := body["error"].(map[string]interface{}); ok {
		code, _ := errObj["code"].(float64)
		if int(code) == -32602 {
			return true, "JSON-RPC error -32602 (invalid params) returned for the completion probe, so completion/complete was dispatched without auth"
		}
		return false, ""
	}
	if res, ok := body["result"].(map[string]interface{}); ok {
		if _, ok := res["completion"]; ok {
			return true, "completion/complete returned a completion result without auth"
		}
		return true, "completion/complete returned a result envelope without auth"
	}
	return false, ""
}

// completionValues extracts the string suggestion values from a
// completion/complete result.
func completionValues(body map[string]interface{}) []string {
	res, _ := body["result"].(map[string]interface{})
	comp, _ := res["completion"].(map[string]interface{})
	raw, _ := comp["values"].([]interface{})
	var out []string
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sampleValues caps disclosed values for evidence so a large completion list
// does not bloat the report.
func sampleValues(values []string) []string {
	const max = 10
	if len(values) <= max {
		return values
	}
	return append(values[:max:max], "...")
}
