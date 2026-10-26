package mcp

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/calbebop/batesian/internal/attack"
)

// CompletionUnauthExecutor checks anonymous completion access without mutating state.
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

// completionRef identifies an argument in a live or synthetic reference.
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
	signal dispatchSignal
}

type completionDiscoveryVerdict int

const (
	completionDiscoveryIncomplete completionDiscoveryVerdict = iota
	completionDiscoveryAuthGated
	completionDiscoveryComplete
)

// templateVar extracts the first RFC 6570 variable name from a URI template,
// e.g. "file:///{path}" -> "path", "db://{+table}/{id}" -> "table". Returns no
// match when the template declares no variable.
var templateVar = regexp.MustCompile(`\{[+#./;?&]?([A-Za-z0-9_]+)`)

func (e *CompletionUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token - the rule tests whether completion is
	// reachable WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// A server may expose completion on both protocol wires, and need not gate it
	// the same way on each, so every wire it serves is probed.
	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session, vars.RandID)
	})
}

// probeSession runs the rule against one already-opened wire. determined reports
// whether the wire established anything; see classifyProbe.
func (e *CompletionUnauthExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession, randID string) (findings []attack.Finding, determined bool) {
	// Skip servers that do not advertise the completions capability; probing them
	// would produce meaningless noise. Read from the captured handshake object
	// rather than substring-matching the body. Determined: the server says it has
	// no completion surface, so none can be open.
	if !session.ServerSupports("completions") {
		return nil, true
	}

	// Probe real refs discovered from the live server first, preferring one that
	// actually leaks suggestion values (the disclosure oracle). Track the first
	// reachable probe so reachability is reported even when no ref discloses.
	var firstReachable, disclosure *completionOutcome
	refs, refsComplete, discovery := e.discoverRefs(ctx, client, session)
	allProbesDetermined := true
	var attempts []string
	for _, ref := range refs {
		out, probed := e.probe(ctx, client, session, ref)
		attempts = append(attempts, completionAttemptOutcome(out, probed))
		if probed {
			determined = true
		} else {
			allProbesDetermined = false
		}
		if out == nil {
			continue
		}
		if firstReachable == nil || (firstReachable.signal == dispatchError && out.signal == dispatchResult) {
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
			params:  map[string]interface{}{"type": "ref/prompt", "name": "batesian-nonexistent-" + randID},
			argName: "batesian_probe",
			real:    false,
			label:   "synthetic probe ref",
		}
		var probed bool
		firstReachable, probed = e.probe(ctx, client, session, synth)
		attempts = append(attempts, completionAttemptOutcome(firstReachable, probed))
		if probed {
			determined = true
		} else {
			allProbesDetermined = false
		}
	}

	if firstReachable == nil {
		return nil, determined && refsComplete && allProbesDetermined
	}

	// Base the reachability finding on the disclosure probe when one was found, so
	// both findings describe the same reference.
	base := firstReachable
	if disclosure != nil {
		base = disclosure
	}

	title := "MCP completion/complete returned a result without authentication"
	description := fmt.Sprintf("completion/complete at %s returned a result for an anonymous request (probed via %s). The result alone does not establish that sensitive suggestions were disclosed.", session.Endpoint, base.ref.label)
	if base.signal == dispatchError {
		title = "MCP completion/complete returned a non-authentication error to an anonymous request"
		description = fmt.Sprintf("completion/complete at %s returned a non-authentication JSON-RPC error for an anonymous request (probed via %s). The error may have come from validation before method dispatch; access to completion suggestions was not demonstrated.", session.Endpoint, base.ref.label)
	}
	findings = []attack.Finding{{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    "info",
		Confidence:  attack.RiskIndicator,
		Title:       title,
		Description: description,
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprobe: %s\n%s", base.status, session.Endpoint, base.ref.label, base.reason),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}
	if len(discovery) > 0 {
		findings[0].Evidence += "\nreference discovery:"
		for _, outcome := range discovery {
			findings[0].Evidence += "\n  " + outcome
		}
	}
	findings[0].Evidence += "\ncompletion attempts:"
	for i, outcome := range attempts {
		findings[0].Evidence += fmt.Sprintf("\n  %d: %s", i+1, outcome)
	}
	if !refsComplete || !allProbesDetermined {
		findings[0].Evidence += "\ncompletion assessment incomplete"
	}

	// Escalate when a real ref returned actual suggestion values: the endpoint is
	// not just reachable but is leaking valid completions to an anonymous caller.
	if disclosure != nil {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      fmt.Sprintf("MCP completion/complete disclosed suggestion values without authentication (%s)", disclosure.ref.label),
			Description: fmt.Sprintf(
				"completion/complete for %s at %s returned %d suggestion value(s) to an unauthenticated "+
					"caller. Values may include identifiers, file paths, or usernames. Review whether these "+
					"suggestions should be public; this does not establish a policy violation.",
				disclosure.ref.label, session.Endpoint, len(disclosure.values)),
			Evidence:    fmt.Sprintf("HTTP %d from %s\n%s\nvalues (%d): %v", disclosure.status, session.Endpoint, disclosure.ref.label, len(disclosure.values), sampleValues(disclosure.values)),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
	}

	return findings, true
}

func completionAttemptOutcome(out *completionOutcome, determined bool) string {
	if out != nil {
		return "reachable"
	}
	if determined {
		return "not reachable in observed response"
	}
	return "incomplete (no verdict)"
}

// probe returns any reachability evidence and whether the response was conclusive.
func (e *CompletionUnauthExecutor) probe(ctx context.Context, client *attack.HTTPClient, session mcpSession, ref completionRef) (out *completionOutcome, determined bool) {
	// An empty value asks the server to enumerate all suggestions for the
	// argument. Fuzzy/prefix matchers (the common implementation) return their
	// full candidate set for the empty prefix, which is exactly the
	// enumerate-everything behavior an attacker abuses; a non-empty probe value
	// would be silently filtered out against namespaces that do not share its
	// prefix (e.g. numeric identifiers).
	resp, err := session.post(ctx, client, 7, "completion/complete", map[string]interface{}{
		"ref":      ref.params,
		"argument": map[string]interface{}{"name": ref.argName, "value": ""},
	})
	verdict, body := classifyProbe(resp, err, 7)
	if verdict == probeRejected {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, true
		}
		if rpcErr, ok := body["error"].(map[string]interface{}); ok {
			msg, _ := rpcErr["message"].(string)
			if attack.AuthFlavoredMessage(msg) {
				return nil, true
			}
		}
		return nil, false
	}
	if verdict != probeAnswered {
		return nil, false
	}
	signal, reason := completionDispatchReachable(body)
	if signal == dispatchNone {
		return nil, true
	}
	out = &completionOutcome{ref: ref, status: resp.StatusCode, reason: reason, signal: signal}
	if ref.real {
		out.values = completionValues(body)
	}
	return out, true
}

// discoverRefs returns real completion references built from the server's live
// prompts and resource templates (capped at maxRealRefs). Each requires an
// argument name to complete: a prompt argument, or a URI-template variable.
func (e *CompletionUnauthExecutor) discoverRefs(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]completionRef, bool, []string) {
	var refs []completionRef
	complete := true
	var outcomes []string
	nextID := 8

	if session.ServerSupports("prompts") {
		found, verdict := promptRefs(ctx, client, session, &nextID)
		refs = append(refs, found...)
		complete = complete && verdict != completionDiscoveryIncomplete
		outcomes = append(outcomes, fmt.Sprintf("prompts/list: %s", completionDiscoveryOutcome(verdict)))
	}
	if session.ServerSupports("resources") {
		found, verdict := resourceTemplateRefs(ctx, client, session, &nextID)
		refs = append(refs, found...)
		complete = complete && verdict != completionDiscoveryIncomplete
		outcomes = append(outcomes, fmt.Sprintf("resources/templates/list: %s", completionDiscoveryOutcome(verdict)))
	}

	if len(refs) > maxRealRefs {
		outcomes = append(outcomes, fmt.Sprintf("reference limit: %d of %d", maxRealRefs, len(refs)))
		complete = false
		refs = refs[:maxRealRefs]
	}
	return refs, complete, outcomes
}

func completionDiscoveryOutcome(verdict completionDiscoveryVerdict) string {
	switch verdict {
	case completionDiscoveryComplete:
		return "complete"
	case completionDiscoveryAuthGated:
		return "auth-gated"
	default:
		return "incomplete"
	}
}

// promptRefs lists prompts and builds a completion ref for every prompt argument.
func promptRefs(ctx context.Context, client *attack.HTTPClient, session mcpSession, nextID *int) ([]completionRef, completionDiscoveryVerdict) {
	prompts, verdict := completionListItems(ctx, client, session, nextID, "prompts/list", "prompts")
	if verdict == completionDiscoveryAuthGated {
		return nil, verdict
	}
	var refs []completionRef
	complete := verdict == completionDiscoveryComplete
	for _, p := range prompts {
		pm, ok := p.(map[string]interface{})
		if !ok {
			complete = false
			continue
		}
		name, _ := pm["name"].(string)
		if name == "" {
			complete = false
			continue
		}
		args, hasArgs := pm["arguments"]
		if !hasArgs {
			continue
		}
		arguments, ok := args.([]interface{})
		if !ok {
			complete = false
			continue
		}
		for _, a := range arguments {
			am, ok := a.(map[string]interface{})
			if !ok {
				complete = false
				continue
			}
			an, _ := am["name"].(string)
			if an == "" {
				complete = false
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
	if !complete {
		return refs, completionDiscoveryIncomplete
	}
	return refs, completionDiscoveryComplete
}

// resourceTemplateRefs lists resource templates and builds a completion ref for
// the first variable of every template that declares one.
func resourceTemplateRefs(ctx context.Context, client *attack.HTTPClient, session mcpSession, nextID *int) ([]completionRef, completionDiscoveryVerdict) {
	templates, verdict := completionListItems(ctx, client, session, nextID, "resources/templates/list", "resourceTemplates")
	if verdict == completionDiscoveryAuthGated {
		return nil, verdict
	}
	var refs []completionRef
	complete := verdict == completionDiscoveryComplete
	for _, t := range templates {
		tm, ok := t.(map[string]interface{})
		if !ok {
			complete = false
			continue
		}
		ut, _ := tm["uriTemplate"].(string)
		if ut == "" {
			complete = false
			continue
		}
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
	if !complete {
		return refs, completionDiscoveryIncomplete
	}
	return refs, completionDiscoveryComplete
}

// completionListItems retains observed entries when a later page fails.
func completionListItems(ctx context.Context, client *attack.HTTPClient, session mcpSession, nextID *int, method, field string) ([]interface{}, completionDiscoveryVerdict) {
	const maxPages = 10
	var items []interface{}
	var params map[string]interface{}
	seen := map[string]bool{}
	for page := 0; page < maxPages; page++ {
		id := *nextID
		*nextID = id + 1
		body, verdict := rpcResult(ctx, client, session, id, method, params)
		if verdict != completionDiscoveryComplete {
			if page == 0 {
				return nil, verdict
			}
			return items, completionDiscoveryIncomplete
		}
		pageItems, ok := body[field].([]interface{})
		if !ok {
			return items, completionDiscoveryIncomplete
		}
		items = append(items, pageItems...)
		cursor, more, valid := resourcesListCursor(body)
		if !valid {
			return items, completionDiscoveryIncomplete
		}
		if !more {
			return items, completionDiscoveryComplete
		}
		if seen[cursor] {
			return items, completionDiscoveryIncomplete
		}
		seen[cursor] = true
		params = map[string]interface{}{"cursor": cursor}
	}
	return items, completionDiscoveryIncomplete
}

// rpcResult returns a correlated, complete result object from a list call.
func rpcResult(ctx context.Context, client *attack.HTTPClient, session mcpSession, id int, method string, params map[string]interface{}) (map[string]interface{}, completionDiscoveryVerdict) {
	resp, err := session.post(ctx, client, id, method, params)
	verdict, body := classifyProbe(resp, err, id)
	if verdict == probeRejected {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, completionDiscoveryAuthGated
		}
		if rpcErr, ok := body["error"].(map[string]interface{}); ok {
			msg, _ := rpcErr["message"].(string)
			if attack.AuthFlavoredMessage(msg) {
				return nil, completionDiscoveryAuthGated
			}
		}
		return nil, completionDiscoveryIncomplete
	}
	if verdict != probeAnswered {
		return nil, completionDiscoveryIncomplete
	}
	if rpcErr, hasErr := body["error"].(map[string]interface{}); hasErr {
		msg, _ := rpcErr["message"].(string)
		if attack.AuthFlavoredMessage(msg) {
			return nil, completionDiscoveryAuthGated
		}
		return nil, completionDiscoveryIncomplete
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok {
		return nil, completionDiscoveryIncomplete
	}
	if result["resultType"] != nil && result["resultType"] != "complete" {
		return nil, completionDiscoveryIncomplete
	}
	return result, completionDiscoveryComplete
}

func completionDispatchReachable(body map[string]interface{}) (dispatchSignal, string) {
	sig, code := classifyDispatch(body)
	switch sig {
	case dispatchResult:
		if res, ok := body["result"].(map[string]interface{}); ok {
			if _, ok := res["completion"]; ok {
				return dispatchResult, "completion/complete returned a completion result without auth"
			}
		}
		return dispatchResult, "completion/complete returned a result envelope without auth"
	case dispatchError:
		return dispatchError, fmt.Sprintf("JSON-RPC error %d returned for the completion probe; dispatch was not verified", code)
	}
	return dispatchNone, ""
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
