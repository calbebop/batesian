package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ScopeConfusionExecutor checks whether tools/call enforces credential scopes.
// Mutating tools run only when named in Options.MCPScopeTools.
type ScopeConfusionExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-scope-confusion", func(rc attack.RuleContext) attack.Executor { return NewScopeConfusionExecutor(rc) })
}

func NewScopeConfusionExecutor(r attack.RuleContext) *ScopeConfusionExecutor {
	return &ScopeConfusionExecutor{rule: r}
}

const scopeCandidateCap = 6
const scopePageCap = 10
const scopeCanaryPrefix = "batesian-nonexistent-"

const (
	scopeIDListFull     = 3
	scopeIDListLim      = 4
	scopeIDAnon         = 5
	scopeIDListPageBase = 100
	scopeIDFullBase     = 10
	scopeIDLimBase      = 20
)

func (e *ScopeConfusionExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	// Check credentials only after confirming a tool surface.
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

		if credErr != nil {
			return nil, credErr
		}

		fs, reason, determined := e.probeSession(ctx, client, sessA, princA, princB, vars.RandID, opts.MCPScopeTools)
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

func scopePrincipals(opts attack.Options) (a, b taskPrincipal, err error) {
	if len(opts.Principals) < 2 {
		return a, b, fmt.Errorf("%w: telling whether tool access honours granted scopes needs two "+
			"differently-scoped credentials, and %d principal(s) were configured; pass a full and a "+
			"limited identity as two --principal flags (or a config with two principals)",
			attack.ErrInconclusive, len(opts.Principals))
	}
	a, err = configuredTaskPrincipal(opts.Principals[0])
	if err != nil {
		return a, b, err
	}
	b, err = configuredTaskPrincipal(opts.Principals[1])
	if err != nil {
		return a, b, err
	}
	if len(principalIdentityHeaders(a)) == 0 || len(principalIdentityHeaders(b)) == 0 {
		return a, b, fmt.Errorf("%w: principals %q and %q each need a credential or identity header",
			attack.ErrInconclusive, a.name, b.name)
	}
	if samePrincipalIdentity(a, b) {
		return a, b, fmt.Errorf("%w: principals %q and %q present the same credential, so there is "+
			"no scope boundary between them for this rule to test",
			attack.ErrInconclusive, a.name, b.name)
	}
	return a, b, nil
}

func openSessionsAs(ctx context.Context, client *attack.HTTPClient, baseURL string, p taskPrincipal) ([]mcpSession, error) {
	legacy, legacyErr := scopeHandshake(ctx, client, baseURL, p)
	var out []mcpSession
	endpoints := endpointCandidates(baseURL)
	if legacyErr == nil {
		legacy.Era = EraLegacy
		out = append(out, legacy)
		endpoints = []string{legacy.Endpoint}
	}

	for _, ep := range endpoints {
		if modern, ok := scopeDiscoverModern(ctx, client, ep, p); ok {
			out = append(out, modern)
			break
		}
	}
	if len(out) == 0 {
		return nil, inconclusive(legacyErr)
	}
	return out, nil
}

func scopeDiscoverModern(ctx context.Context, client *attack.HTTPClient, endpoint string, p taskPrincipal) (mcpSession, bool) {
	const requestID = "batesian-scope-discover"
	probe := mcpSession{Endpoint: endpoint, Era: EraModern}
	resp, err := probe.postShaping(ctx, client, requestID, "server/discover", nil,
		func(h map[string]string) { attachPrincipal(h, p) })
	if err != nil || !resp.IsAccepted() || !modernWireAdvertised(resp.Body) {
		return mcpSession{}, false
	}
	var envelope map[string]interface{}
	if json.Unmarshal(resp.Body, &envelope) != nil ||
		envelope["jsonrpc"] != "2.0" || envelope["id"] != requestID {
		return mcpSession{}, false
	}
	return mcpSession{
		Endpoint:        endpoint,
		Era:             EraModern,
		ProtocolVersion: modernEraVersion,
		RawInit:         resp.Body,
	}, true
}

func scopeHandshake(ctx context.Context, client *attack.HTTPClient, baseURL string, p taskPrincipal) (mcpSession, error) {
	return scopeHandshakeCandidates(ctx, client, baseURL, endpointCandidates(baseURL), p)
}

func scopeHandshakeAt(ctx context.Context, client *attack.HTTPClient, endpoint string, p taskPrincipal) (mcpSession, error) {
	return scopeHandshakeCandidates(ctx, client, endpoint, []string{endpoint}, p)
}

func scopeHandshakeCandidates(ctx context.Context, client *attack.HTTPClient, baseURL string, endpoints []string, p taskPrincipal) (mcpSession, error) {
	var observed initObservation
	for _, ep := range endpoints {
		headers := map[string]string{}
		attachPrincipal(headers, p)
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
		if !resp.IsSuccess() || !initializeSucceeded(resp.Body) {
			observed.observe(classifyInitFailure(ep, len(principalIdentityHeaders(p)) != 0, resp))
			continue
		}
		if !scopeResponseMatches(resp.Body, 1) {
			observed.observe(initObservation{rankRefused, fmt.Sprintf(
				"the MCP initialize response at %s did not match its request", ep)})
			continue
		}
		session := mcpSession{
			Endpoint:        ep,
			SessionID:       resp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(resp.Body),
			RawInit:         resp.Body,
		}
		initializedHeaders := session.header()
		attachPrincipal(initializedHeaders, p)
		initialized, err := client.POST(ctx, ep, initializedHeaders, map[string]interface{}{
			"jsonrpc": "2.0", "method": "notifications/initialized",
		})
		if err != nil || initialized == nil {
			observed.observe(initObservation{rankRefused, fmt.Sprintf(
				"the MCP initialized notification at %s could not be delivered", ep)})
			continue
		}
		if !initialized.IsSuccess() {
			rank := rankRefused
			if initialized.StatusCode == http.StatusUnauthorized || initialized.StatusCode == http.StatusForbidden {
				rank = rankUnauthorized
			}
			observed.observe(initObservation{rank, fmt.Sprintf(
				"the MCP initialized notification at %s was refused with HTTP %d", ep, initialized.StatusCode)})
			continue
		}
		return session, nil
	}
	if observed.rank > rankNothing {
		return mcpSession{}, handshakeRefusal{observed.reason}
	}
	return mcpSession{}, fmt.Errorf("no MCP server found at %s", baseURL)
}

type scopeTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Annotations *struct {
		ReadOnlyHint    *bool `json:"readOnlyHint"`
		DestructiveHint *bool `json:"destructiveHint"`
	} `json:"annotations"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

var scopeWriteVocabulary = []string{
	"write", "create", "delete", "remove", "update", "set_", "send", "exec",
	"run", "invoke", "admin", "install", "deploy", "restart", "shutdown",
	"grant", "revoke", "cancel",
}

func scopeLooksPrivileged(t scopeTool) bool {
	if t.Annotations != nil {
		if t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
			return true
		}
		if t.Annotations.ReadOnlyHint != nil && !*t.Annotations.ReadOnlyHint {
			return true
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

func (e *ScopeConfusionExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, sessA mcpSession,
	princA, princB taskPrincipal, randID string, allowedTools []string) (findings []attack.Finding, stopReason string, determined bool) {

	candidates, reason, ok := e.scopeCandidates(ctx, client, sessA, princA)
	if !ok {
		return nil, reason, false
	}
	if len(candidates) == 0 {
		return nil, "", true // listed, and nothing privileged-shaped to test
	}
	if len(candidates) > scopeCandidateCap {
		candidates = candidates[:scopeCandidateCap]
	}
	if missing := unapprovedScopeTools(candidates, allowedTools); len(missing) > 0 {
		return nil, fmt.Sprintf("active scope probes require explicit approval for: %s; pass --mcp-scope-tool for each exact name",
			strings.Join(missing, ", ")), false
	}
	sessB := sessA
	if sessA.Era == EraLegacy {
		var err error
		sessB, err = scopeHandshakeAt(ctx, client, sessA.Endpoint, princB)
		if err != nil {
			return nil, fmt.Sprintf("the limited principal %q could not open a session at %s (%v)",
				princB.name, sessA.Endpoint, err), false
		}
		sessB.Era = EraLegacy
	}

	// Confirm the limited credential works before grading its refusals.
	listResp, listErr := sessB.postShaping(ctx, client, scopeIDListLim, "tools/list", nil,
		func(h map[string]string) { attachPrincipal(h, princB) })
	if verdict, _ := classifyProbe(listResp, listErr, scopeIDListLim); verdict != probeAnswered {
		return nil, fmt.Sprintf("tools/list refused the limited principal %q (%s), so its privilege "+
			"level was never established", princB.name, scopeVerdictName(verdict)), false
	}
	if !scopeResponseMatches(listResp.Body, scopeIDListLim) {
		return nil, fmt.Sprintf("tools/list returned no correlated response for the limited principal %q", princB.name), false
	}
	if _, _, ok := scopeListedTools(listResp.Body); !ok {
		return nil, fmt.Sprintf("tools/list returned no successful listing for the limited principal %q", princB.name), false
	}

	// Anonymous dispatch rules out a scope-specific bypass.
	anonymousCall := e.callAs(ctx, client, sessA, anonymousPrincipal, scopeIDAnon, candidates[0], randID)
	if anonymousCall.headerMismatch {
		return nil, fmt.Sprintf("tools/call for %q returned HeaderMismatch on the anonymous control", candidates[0].Name), false
	}
	if scopeShowsDispatch(anonymousCall, randID) {
		return nil, "", true
	}
	if !scopeShowsAuthRefusal(anonymousCall) {
		return nil, fmt.Sprintf("the anonymous control at %s returned no authorization verdict", sessA.Endpoint), false
	}

	var unanswered string
	for i, cand := range candidates {
		fullCall := e.callAs(ctx, client, sessA, princA, scopeIDFullBase+i, cand, randID)
		if fullCall.headerMismatch {
			return findings, fmt.Sprintf("tools/call for %q returned HeaderMismatch for the full principal", cand.Name), false
		}
		if !fullCall.answered {
			unanswered = fmt.Sprintf("tools/call returned no correlated response for the full principal %q", princA.name)
			continue
		}
		if !scopeShowsDispatch(fullCall, randID) {
			continue // baseline did not establish dispatch; nothing to compare
		}

		limCall := e.callAs(ctx, client, sessB, princB, scopeIDLimBase+i, cand, randID)
		if limCall.headerMismatch {
			return findings, fmt.Sprintf("tools/call for %q returned HeaderMismatch for the limited principal", cand.Name), false
		}
		if !limCall.answered {
			unanswered = fmt.Sprintf("tools/call returned no correlated response for the limited principal %q", princB.name)
			continue
		}
		switch {
		case scopeShowsDispatch(limCall, randID):
			findings = append(findings, e.finding(sessA.Endpoint, cand, princA.name, princB.name))
		case scopeShowsAuthRefusal(limCall):
			// Scope enforcement held.
		default:
			// No verdict.
		}
	}
	if unanswered != "" {
		return findings, unanswered, false
	}
	return findings, "", true
}

func unapprovedScopeTools(candidates []scopeTool, allowed []string) []string {
	allow := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allow[name] = true
	}
	var missing []string
	for _, candidate := range candidates {
		if !allow[candidate.Name] {
			missing = append(missing, candidate.Name)
		}
	}
	return missing
}

func (e *ScopeConfusionExecutor) scopeCandidates(ctx context.Context, client *attack.HTTPClient, sessA mcpSession, princA taskPrincipal) (cands []scopeTool, reason string, ok bool) {
	var params map[string]interface{}
	seen := map[string]bool{}
	for page := 0; page < scopePageCap; page++ {
		id := scopeIDListFull
		if page > 0 {
			id = scopeIDListPageBase + page
		}
		resp, err := sessA.postShaping(ctx, client, id, "tools/list", params,
			func(h map[string]string) { attachPrincipal(h, princA) })
		verdict, _ := classifyProbe(resp, err, id)
		if verdict != probeAnswered {
			return nil, fmt.Sprintf("tools/list refused the full principal %q (%s), so the privileged "+
				"surface could not be discovered", princA.name, scopeVerdictName(verdict)), false
		}
		if !scopeResponseMatches(resp.Body, id) {
			return nil, "tools/list returned no correlated response for the full principal", false
		}
		tools, cursor, ok := scopeListedTools(resp.Body)
		if !ok {
			return nil, "tools/list returned no parseable listing", false
		}
		for _, t := range tools {
			if sessA.Era == EraModern {
				if _, err := toolParamHeaders(t.InputSchema, nil); err != nil {
					continue
				}
			}
			if scopeLooksPrivileged(t) {
				cands = append(cands, t)
				if len(cands) == scopeCandidateCap {
					return cands, "", true
				}
			}
		}
		if cursor == nil {
			return cands, "", true
		}
		if seen[*cursor] {
			return nil, "tools/list repeated a pagination cursor", false
		}
		seen[*cursor] = true
		params = map[string]interface{}{"cursor": *cursor}
	}
	return nil, "tools/list pagination exceeded the page limit", false
}

func scopeListedTools(raw []byte) ([]scopeTool, *string, bool) {
	var body struct {
		Result struct {
			Tools      []scopeTool `json:"tools"`
			NextCursor *string     `json:"nextCursor"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil || len(body.Error) != 0 || body.Result.Tools == nil {
		return nil, nil, false
	}
	return body.Result.Tools, body.Result.NextCursor, true
}

type scopeCallOutcome struct {
	text           string
	protocolError  bool
	answered       bool
	headerMismatch bool
}

func scopeResponseMatches(body []byte, id int) bool {
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &response) != nil || response.JSONRPC != "2.0" {
		return false
	}
	return string(response.ID) == strconv.Itoa(id)
}

// callAs invokes an approved tool and returns its response shape and text.
func (e *ScopeConfusionExecutor) callAs(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, id int, cand scopeTool, randID string) scopeCallOutcome {
	args := scopeProbeArgs(cand.InputSchema, randID)
	params := map[string]interface{}{"name": cand.Name, "arguments": args}
	resp, err := s.postToolShaping(ctx, client, id, params, cand.InputSchema,
		func(h map[string]string) { attachPrincipal(h, p) })
	if isMCPHeaderMismatch(resp) {
		return scopeCallOutcome{headerMismatch: true}
	}
	if err != nil || !resp.IsSuccess() {
		// Preserve HTTP authorization failures for the classifier.
		if err == nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return scopeCallOutcome{text: fmt.Sprintf("http %d %s", resp.StatusCode, resp.Headers.Get("WWW-Authenticate")), answered: true}
		}
		return scopeCallOutcome{}
	}
	if !scopeResponseMatches(resp.Body, id) {
		return scopeCallOutcome{}
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
		return scopeCallOutcome{}
	}
	if body.Error.Message != "" {
		return scopeCallOutcome{text: body.Error.Message, protocolError: true, answered: true}
	}
	var sb strings.Builder
	for _, c := range body.Result.Content {
		sb.WriteString(c.Text)
		sb.WriteString("\n")
	}
	return scopeCallOutcome{text: sb.String(), answered: true}
}

// scopeProbeArgs fills required fields with canary values.
func scopeProbeArgs(schema map[string]interface{}, randID string) map[string]interface{} {
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
			args[name] = scopeCanaryPrefix + randID
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
		args["batesian_probe"] = scopeCanaryPrefix + randID
	}
	return args
}

var scopeAuthFlavored = regexp.MustCompile(`(?i)(insufficient[_ ]?scope|missing[_ ]?scope|invalid[_ ]?token|` +
	`unauthorized|forbidden|access denied|not authorized|not permitted|permission denied|requires?[_ ](a )?scope|` +
	`scope[s]? required|insufficient.?privilege|not allowed)`)

// scopeShowsAuthRefusal detects HTTP and protocol-level authorization failures.
func scopeShowsAuthRefusal(call scopeCallOutcome) bool {
	text := call.text
	if strings.HasPrefix(text, "http 401") || strings.HasPrefix(text, "http 403") {
		return true
	}
	return call.protocolError && text != "" && scopeAuthFlavored.MatchString(text)
}

// scopeShowsDispatch requires a tool result or a protocol error that echoes the probe canary.
func scopeShowsDispatch(call scopeCallOutcome, randID string) bool {
	text := call.text
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
	if strings.Contains(lower, "unknown tool") || strings.Contains(lower, "no such tool") ||
		strings.Contains(lower, "method not found") ||
		(strings.Contains(lower, "tool ") && strings.Contains(lower, "not found")) {
		return false
	}
	if call.protocolError {
		return strings.Contains(text, scopeCanaryPrefix+randID)
	}
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
			"The same approved tools/call for %q at %s was sent as two principals: %q "+
				"(full) and %q (limited). Both reached argument validation, while an unauthenticated "+
				"call was refused, so the server authenticates callers and then ignores what their "+
				"credential is scoped to do. Every authenticated caller can reach the privileged tool "+
				"surface regardless of granted scopes.",
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
