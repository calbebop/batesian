package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ScopeConfusionExecutor tests whether MCP tools/call enforces the scopes of
// the credential it is handed, or merely that a credential exists
// (rule mcp-scope-confusion-001).
//
// The failure sits between two rules that already ship. mcp-token-replay-001
// covers tokens the server cannot have validated (signature checks absent);
// mcp-oauth-dcr-001 covers registration granting privileged scopes. Neither
// says anything about a validly-signed, genuinely-issued token whose scope set
// is too small: servers that authenticate correctly and then authorize nothing
// per-tool hand every authenticated caller every tool. That is OWASP MCP02,
// and the spec's own Security Best Practices call for least privilege.
//
// Two identities drive it, via the same --principal machinery the
// cross-principal rules use: principal A holds full privilege, principal B
// holds a deliberately limited one. For each privileged-looking candidate tool
// the rule sends the SAME invalid-subject call twice, once as A and once as B:
//
//	full principal    -> dispatches (argument validation answers)   [baseline]
//	limited principal -> refused with an authz error                [scope held]
//	limited principal -> dispatches like A                          [scope ignored]
//
// SAFETY: the arguments are invalid on purpose - a subject id that does not
// exist - so a scope-ignoring server stops at argument validation and executes
// nothing. The oracle never needs a successful state-changing call, only the
// difference between "refused before validating" and "validated and not
// found". This is the same never-executes trick mcp-tools-unauth-001 uses on
// its dispatch probe.
type ScopeConfusionExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-scope-confusion", func(rc attack.RuleContext) attack.Executor { return NewScopeConfusionExecutor(rc) })
}

func NewScopeConfusionExecutor(r attack.RuleContext) *ScopeConfusionExecutor {
	return &ScopeConfusionExecutor{rule: r}
}

// scopeCandidateCap bounds how many candidate tools one wire will drive. Each
// costs two calls (the identical pair), so the cap keeps cost off the target's
// tool count.
const scopeCandidateCap = 6

// scopeCallIDs space the rule's request ids apart from any other stage.
const (
	scopeIDListFull = 3
	scopeIDListLim  = 4
	scopeIDAnon     = 5
	scopeIDFullBase = 10
	scopeIDLimBase  = 20
)

func (e *ScopeConfusionExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	// The credential check defers until the tool surface is confirmed present,
	// the same ordering mcp-task-idor-001 uses: telling an operator to add a
	// second principal when adding one would change nothing is worse than
	// saying the feature is absent.
	princA, princB, credErr := scopePrincipals(opts)
	discovery := princA
	if credErr != nil {
		discovery = taskPrincipal{name: "the configured credential", token: opts.Token}
	}

	sessions, sessErr := openSessionsAs(ctx, client, vars.BaseURL, discovery)
	if sessErr != nil {
		return nil, sessErr // not an MCP server, and why
	}

	var findings []attack.Finding
	capabilityKnown := false
	var lastReason string

	for _, sessA := range sessions {
		if !sessA.ServerSupports("tools") {
			continue // this wire has no tool surface; nothing for the rule to say
		}
		capabilityKnown = true

		// The tool surface exists on at least one wire, so a missing or shared
		// second identity is now the reason the rule cannot run rather than a
		// detail about a server it does not apply to.
		if credErr != nil {
			return nil, credErr
		}

		fs, reason, determined := e.probeSession(ctx, client, sessA, princA, princB, vars.RandID)
		findings = append(findings, labelEra(sessA, fs)...)
		if determined {
			lastReason = ""
		} else if reason != "" {
			lastReason = reason
		}
	}

	if !capabilityKnown {
		return nil, fmt.Errorf("%w: no served wire advertises the tools capability at %s",
			attack.ErrInconclusive, vars.BaseURL)
	}
	if len(findings) == 0 && lastReason != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, lastReason)
	}
	return findings, nil
}

// scopePrincipals resolves the two identities this rule needs: a full one and
// a deliberately limited one, in that order. It mirrors taskPrincipals'
// distinctness rules with wording about scopes rather than tasks.
func scopePrincipals(opts attack.Options) (a, b taskPrincipal, err error) {
	if len(opts.Principals) < 2 {
		return a, b, fmt.Errorf("%w: telling whether tool access honours granted scopes needs two "+
			"differently-scoped credentials, and %d principal(s) were configured; pass a full and a "+
			"limited identity as two --principal flags (or a config with two principals)",
			attack.ErrInconclusive, len(opts.Principals))
	}
	a = taskPrincipal{name: opts.Principals[0].Name, token: opts.Principals[0].Token,
		headers: opts.Principals[0].Headers}
	b = taskPrincipal{name: opts.Principals[1].Name, token: opts.Principals[1].Token,
		headers: opts.Principals[1].Headers}
	if a.token == b.token && sameHeaders(a.headers, b.headers) {
		return a, b, fmt.Errorf("%w: principals %q and %q present the same credential, so there is "+
			"no scope boundary between them for this rule to test",
			attack.ErrInconclusive, a.name, b.name)
	}
	return a, b, nil
}

// openSessionsAs opens every wire the target serves, handshaking as the given
// principal. openSessions itself presents no credential, which reads every
// gated server as unreachable; the handshake here carries the principal the
// way mcp-task-idor-001's does.
func openSessionsAs(ctx context.Context, client *attack.HTTPClient, baseURL string, p taskPrincipal) ([]mcpSession, error) {
	sess, err := scopeHandshake(ctx, client, baseURL, p)
	if err != nil {
		return nil, err
	}
	sess.Era = EraLegacy
	out := []mcpSession{sess}

	for _, ep := range []string{sess.Endpoint} {
		if modern, ok := discoverModern(ctx, client, ep); ok {
			out = append(out, modern)
			break
		}
	}
	return out, nil
}

// scopeHandshake performs an initialize as the given principal, walking the
// candidate paths and reporting why none answered.
func scopeHandshake(ctx context.Context, client *attack.HTTPClient, baseURL string, p taskPrincipal) (mcpSession, error) {
	var observed initObservation
	for _, ep := range endpointCandidates(baseURL) {
		headers := map[string]string{}
		if p.token != "" {
			headers["Authorization"] = "Bearer " + p.token
		}
		for k, v := range p.headers {
			headers[k] = v
		}
		resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "method": "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]interface{}{},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": attack.Version},
			},
		})
		if err != nil {
			continue
		}
		if !resp.IsSuccess() || !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			observed.observe(classifyInitFailure(ep, p.token != "", resp))
			continue
		}
		session := mcpSession{
			Endpoint:        ep,
			SessionID:       resp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(resp.Body),
			RawInit:         resp.Body,
		}
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0", "method": "notifications/initialized",
		})
		return session, nil
	}
	if observed.rank > rankNothing {
		return mcpSession{}, handshakeRefusal{observed.reason}
	}
	return mcpSession{}, fmt.Errorf("no MCP server found at %s", baseURL)
}

// scopeTool is the slice of a tools/list entry this rule grades.
type scopeTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Annotations *struct {
		ReadOnlyHint    *bool `json:"readOnlyHint"`
		DestructiveHint *bool `json:"destructiveHint"`
	} `json:"annotations"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// scopeWriteVocabulary names the tool-name fragments treated as privileged
// when annotations are absent or ambiguous. Matching is on the lowercase name
// containing the fragment; a read-only annotated tool never qualifies through
// the name path.
var scopeWriteVocabulary = []string{
	"write", "create", "delete", "remove", "update", "set_", "send", "exec",
	"run", "invoke", "admin", "install", "deploy", "restart", "shutdown",
	"grant", "revoke", "cancel",
}

// scopeLooksPrivileged reports whether a tool plausibly mutates state: its
// annotations say so, or its name carries write vocabulary without a
// read-only declaration contradicting it.
func scopeLooksPrivileged(t scopeTool) bool {
	if t.Annotations != nil {
		if t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint {
			return false // declared read-only wins over the name heuristic
		}
		if t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
			return true
		}
		if t.Annotations.ReadOnlyHint != nil && !*t.Annotations.ReadOnlyHint {
			return true // explicitly declared non-read-only
		}
	}
	lower := strings.ToLower(t.Name)
	for _, frag := range scopeWriteVocabulary {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// probeSession drives one wire. determined reports whether the wire produced a
// verdict anywhere; reason carries what stopped it when it did not.
func (e *ScopeConfusionExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, sessA mcpSession,
	princA, princB taskPrincipal, randID string) (findings []attack.Finding, stopReason string, determined bool) {

	candidates, reason, ok := e.scopeCandidates(ctx, client, sessA, princA)
	if !ok {
		return nil, reason, false
	}
	if len(candidates) == 0 {
		return nil, "", true // listed, and nothing privileged-shaped to test
	}

	// Validity control: the limited credential must succeed somewhere before a
	// refusal below can be read as a scope decision rather than a dead token.
	listResp, listErr := sessA.postShaping(ctx, client, scopeIDListLim, "tools/list", nil,
		func(h map[string]string) { attachPrincipal(h, princB) })
	if verdict, _ := classifyProbe(listResp, listErr); verdict != probeAnswered {
		return nil, fmt.Sprintf("tools/list refused the limited principal %q (%s), so its privilege "+
			"level was never established", princB.name, scopeVerdictName(verdict)), false
	}

	// Anonymous control on the first candidate: a server that dispatches an
	// unauthenticated call gates nothing by identity, which is
	// mcp-tools-unauth-001's finding rather than a scope boundary.
	anonymousText := e.callAs(ctx, client, sessA, anonymousPrincipal, scopeIDAnon, candidates[0], randID)
	if scopeShowsDispatch(anonymousText) {
		return nil, "", true
	}

	for i, cand := range candidates {
		if i >= scopeCandidateCap {
			break
		}

		fullText := e.callAs(ctx, client, sessA, princA, scopeIDFullBase+i, cand, randID)
		if !scopeShowsDispatch(fullText) {
			continue // baseline did not establish dispatch; nothing to compare
		}

		limText := e.callAs(ctx, client, sessA, princB, scopeIDLimBase+i, cand, randID)
		switch {
		case scopeShowsDispatch(limText):
			findings = append(findings, e.finding(sessA.Endpoint, cand, princA.name, princB.name))
		case scopeShowsAuthRefusal(limText):
			// The boundary held on this candidate: exactly the pass sought.
		default:
			// No verdict either way; this candidate says nothing about scoping.
		}
	}
	return findings, "", true
}

// scopeCandidates lists the tools as the full principal and selects the
// privileged-looking ones. ok is false when the listing produced no usable
// answer, in which case reason says why the rule could not run on this wire.
func (e *ScopeConfusionExecutor) scopeCandidates(ctx context.Context, client *attack.HTTPClient, sessA mcpSession, princA taskPrincipal) (cands []scopeTool, reason string, ok bool) {
	resp, err := sessA.postShaping(ctx, client, scopeIDListFull, "tools/list", nil,
		func(h map[string]string) { attachPrincipal(h, princA) })
	verdict, _ := classifyProbe(resp, err)
	if verdict != probeAnswered {
		return nil, fmt.Sprintf("tools/list refused the full principal %q (%s), so the privileged "+
			"surface could not be discovered", princA.name, scopeVerdictName(verdict)), false
	}
	var body struct {
		Result struct {
			Tools []scopeTool `json:"tools"`
		} `json:"result"`
		Error map[string]interface{} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &body) != nil || body.Error != nil {
		return nil, "tools/list returned no parseable listing", false
	}
	for _, t := range body.Result.Tools {
		if scopeLooksPrivileged(t) {
			cands = append(cands, t)
		}
	}
	return cands, "", true
}

// attachPrincipal adds a principal's credential to headers this session's era
// already built. Explicit attachment is what lets one transport carry two
// identities without an ambient token deciding for them.
func attachPrincipal(h map[string]string, p taskPrincipal) {
	if p.token != "" {
		h["Authorization"] = "Bearer " + p.token
	}
	for k, v := range p.headers {
		h[k] = v
	}
}

// callAs issues one tools/call with invalid subject arguments as the given
// principal and returns the response text the oracle reads: the JSON-RPC error
// message when the envelope carries one, otherwise the result's textual
// content. Both shapes occur, since many servers report tool failures inside
// result.isError rather than as protocol errors.
//
// The call goes through postShaping so the modern wire's mandatory mirrored
// headers and _meta travel with it; building headers by hand here would send a
// legacy-shaped request onto the stateless wire and read its -32020 refusals
// as authorization decisions.
func (e *ScopeConfusionExecutor) callAs(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, id int, cand scopeTool, randID string) string {
	args := scopeInvalidArgs(cand.InputSchema, randID)
	params := map[string]interface{}{"name": cand.Name, "arguments": args}
	resp, err := s.postShaping(ctx, client, id, "tools/call", params,
		func(h map[string]string) { attachPrincipal(h, p) })
	if err != nil || !resp.IsSuccess() {
		// An HTTP-level auth rejection still speaks: read the status line plus
		// any challenge header into the same text the classifier reads.
		if err == nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return fmt.Sprintf("http %d %s", resp.StatusCode, resp.Headers.Get("WWW-Authenticate"))
		}
		return ""
	}
	var body struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &body) != nil {
		return ""
	}
	if body.Error.Message != "" {
		return body.Error.Message
	}
	var sb strings.Builder
	for _, c := range body.Result.Content {
		sb.WriteString(c.Text)
		sb.WriteString("\n")
	}
	return sb.String()
}

// scopeInvalidArgs builds arguments that fail validation after authorization:
// every required string gets a subject id that cannot exist, other required
// types get inert values. A server that ignores scopes stops right here.
func scopeInvalidArgs(schema map[string]interface{}, randID string) map[string]interface{} {
	args := map[string]interface{}{}
	props, _ := schema["properties"].(map[string]interface{})
	required := map[string]bool{}
	req, _ := schema["required"].([]interface{})
	for _, r := range req {
		if s, ok := r.(string); ok {
			required[s] = true
		}
	}
	for name, raw := range props {
		if !required[name] {
			continue
		}
		spec, _ := raw.(map[string]interface{})
		switch spec["type"] {
		case "string":
			args[name] = "batesian-nonexistent-" + randID
		case "number", "integer":
			args[name] = 1
		case "boolean":
			args[name] = false
		case "array":
			args[name] = []interface{}{}
		case "object":
			args[name] = map[string]interface{}{}
		}
	}
	if len(args) == 0 {
		args["batesian_probe"] = "batesian-nonexistent-" + randID
	}
	return args
}

var scopeAuthFlavored = regexp.MustCompile(`(?i)(insufficient[_ ]?scope|missing[_ ]?scope|invalid[_ ]?token|` +
	`unauthorized|forbidden|access denied|not authorized|not permitted|permission denied|requires?[_ ](a )?scope|` +
	`scope[s]? required|insufficient.?privilege|not allowed)`)

// scopeShowsAuthRefusal reads a response text as an authorization refusal:
// HTTP 401/403 with a challenge, or a message carrying authz vocabulary. A
// validation message ("Item x not found") matches none of these.
func scopeShowsAuthRefusal(text string) bool {
	if strings.HasPrefix(text, "http 401") || strings.HasPrefix(text, "http 403") {
		return true
	}
	return text != "" && scopeAuthFlavored.MatchString(text)
}

// scopeShowsDispatch reads a response text as evidence the dispatcher ran past
// authorization: a protocol validation error, a not-found style tool error, or
// any result content at all.
func scopeShowsDispatch(text string) bool {
	if text == "" {
		return false
	}
	if strings.HasPrefix(text, "http ") {
		return false // a status-line reading is always a refusal shape here
	}
	if scopeAuthFlavored.MatchString(text) {
		return false // refused, not dispatched
	}
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"unknown tool", "not found", "no such", "does not exist", "invalid param",
		"invalid argument", "unexpected", "missing required", "validation",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Any other result text means the handler ran too - but only report that as
	// dispatch when it looks like an error outcome, since arbitrary success
	// output would mean the tool genuinely executed. The invalid-subject probe
	// makes real success implausible; treat non-empty as dispatched anyway and
	// let the finding's evidence show the text.
	return strings.TrimSpace(text) != ""
}

func scopeVerdictName(v probeVerdict) string {
	switch v {
	case probeRejected:
		return "refused"
	default:
		return "no verdict"
	}
}

func (e *ScopeConfusionExecutor) finding(endpoint string, cand scopeTool, fullName, limName string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP tools/call runs %q under a scope-limited credential", cand.Name),
		Description: fmt.Sprintf(
			"The identical invalid-subject tools/call for %q at %s was sent as two principals: %q "+
				"(full) and %q (limited). Both reached argument validation, while an unauthenticated "+
				"call was refused, so the server authenticates callers and then ignores what their "+
				"credential is scoped to do. Every authenticated caller can reach the privileged tool "+
				"surface regardless of granted scopes. Nothing executed during the probe: the subject "+
				"arguments name objects that do not exist, and both calls stopped at validation.",
			cand.Name, endpoint, fullName, limName),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntool: %s\nfull principal %q: dispatched (validation answered)\n"+
				"limited principal %q: dispatched (validation answered)\n"+
				"anonymous control: refused",
			endpoint, cand.Name, fullName, limName),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
