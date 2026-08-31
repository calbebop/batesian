package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/calbebop/batesian/internal/attack"
)

// credentialPatterns detects secrets and credentials in resource content.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),                              // AWS access key
	regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{32,}`),                           // OpenAI API key
	regexp.MustCompile(`(?i)(api[_-]?key|api[_-]?secret)\s*[=:]\s*\S{10,}`), // Generic API key
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S{6,}`),         // Password
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),   // Private keys
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),                           // GitHub token
	// The optional "Bearer " after the separator is what lets this match the
	// canonical header form, Authorization: Bearer <token>. Without it the
	// pattern reached "Bearer", six characters, and gave up against the
	// \S{10,} it needs; the one shape most likely to appear in a leaked config
	// was the one shape it could not see. The separator stays required, because
	// making it optional would match any long word following the keyword, as in
	// "Authorization requirements documented".
	//
	// The quote class is not cosmetic: content is matched against the raw
	// JSON-RPC response body, so a resource holding `authorization: "Bearer x"`
	// arrives with the quote escaped, as \" , sitting between the separator and
	// the value.
	regexp.MustCompile(`(?i)(bearer|authorization)\s*[=:]\s*[\\"']*\s*(bearer\s+)?\S{10,}`), // Bearer/auth token
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}`),                     // JWT
	// Credentials in a URI userinfo section, as in
	// postgresql://admin:hunter2@db.internal:5432/prod. Connection strings are
	// a routine thing to expose through a resource and the password pattern
	// above cannot see one, because it looks for password=value rather than a
	// positional secret. Requiring the @ is what keeps an ordinary
	// http://host:8080/path from matching on its port.
	regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^/\s:@]*:[^/\s:@]+@[^/\s]+`), // URI userinfo credentials
}

// maxResourceReads bounds how many resources one run will read. A server may
// list hundreds, and reading all of them makes a scan's cost a function of the
// target rather than of the rule. The count actually read is reported in the
// evidence, so a bounded run never reads as an exhaustive one.
const maxResourceReads = 5

// ResourcesUnauthExecutor probes MCP resources/list and resources/read without
// authentication (rule mcp-resources-unauth-001).
//
// Unlike tool poisoning (LLM-mediated), resource disclosure is immediate:
// the attacker retrieves data directly. Resources can contain file system
// contents, database records, environment variables, or API credentials.
type ResourcesUnauthExecutor struct {
	rule attack.RuleContext
}

// NewResourcesUnauthExecutor creates an executor for the mcp-resources-unauth attack type.
func init() {
	attack.Register("mcp-resources-unauth", func(rc attack.RuleContext) attack.Executor { return NewResourcesUnauthExecutor(rc) })
}

func NewResourcesUnauthExecutor(r attack.RuleContext) *ResourcesUnauthExecutor {
	return &ResourcesUnauthExecutor{rule: r}
}

func (e *ResourcesUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token so the probe represents unauthenticated
	// access. Findings claim resources are accessible WITHOUT authentication; if
	// opts.Token were injected the finding would be misleading.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// A server may expose resources on both protocol wires, and need not gate them
	// the same way on each, so every wire it serves is probed.
	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session)
	})
}

// probeSession runs the rule against one already-opened wire. determined reports
// whether the wire established anything; see classifyProbe.
//
// Only the listing decides that. The per-resource reads below feed the credential
// escalation, and they run after the listing finding is already confirmed, so a
// read that fails cannot turn a confirmed finding into "not tested".
func (e *ResourcesUnauthExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, determined bool) {
	// Step 1: resources/list - enumerate available resources
	listResp, err := session.post(ctx, client, 3, "resources/list", nil)
	verdict, listBody := classifyProbe(listResp, err)
	if verdict != probeAnswered {
		return nil, verdict == probeRejected
	}

	// JSON-RPC error means the endpoint exists but rejected the call - not vulnerable.
	if _, hasErr := listBody["error"]; hasErr {
		return nil, true
	}

	result, _ := listBody["result"].(map[string]interface{})
	resourcesRaw, _ := result["resources"].([]interface{})

	// Follow nextCursor pagination so a secret-bearing resource on a later
	// page is not missed. The listing finding is already confirmed from the
	// first page; subsequent pages only collect more resources.
	cursor, _ := result["nextCursor"].(string)
	for p := 1; p < 10 && cursor != ""; p++ {
		pageResp, pageErr := session.post(ctx, client, 3+p, "resources/list",
			map[string]interface{}{"cursor": cursor})
		if pageErr != nil {
			break
		}
		_, pageBody := classifyProbe(pageResp, pageErr)
		if pageResult, ok := pageBody["result"].(map[string]interface{}); ok {
			if pageResources, ok := pageResult["resources"].([]interface{}); ok {
				resourcesRaw = append(resourcesRaw, pageResources...)
			}
			cursor, _ = pageResult["nextCursor"].(string)
			continue
		}
		break
	}

	if len(resourcesRaw) == 0 {
		return nil, true
	}

	// Build a display list of resource URIs
	var uris []string
	for _, r := range resourcesRaw {
		if rm, ok := r.(map[string]interface{}); ok {
			if uri, ok := rm["uri"].(string); ok {
				uris = append(uris, uri)
			}
		}
	}

	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP resources/list accessible without authentication (%d resources)", len(uris)),
		Description: fmt.Sprintf(
			"resources/list at %s returned %d resources without any authentication. "+
				"An attacker can enumerate all available data sources and then read their contents "+
				"using resources/read.", session.Endpoint, len(uris)),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nresources (%d): %v", listResp.StatusCode, session.Endpoint, len(uris), uris),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	// Step 2: read resources, preferring one that demonstrates a credential leak.
	//
	// Reading only the first resource made the escalation to critical an accident
	// of list order: a server that lists a public README ahead of its database
	// credentials was reported as merely readable. The listing order is the
	// server's choice, so the rule cannot let it decide the severity.
	read, examined := e.readResources(ctx, client, session, uris)
	if read == nil {
		return findings, true
	}

	// Baseline: unauthenticated read of resource content is high. Escalate to
	// critical only when the content actually contains a detected secret -
	// severity should track demonstrated impact, not be flat-critical for every
	// readable resource (which may be benign, e.g. a public README).
	sev := "high"
	if read.credEvidence != "" {
		sev = "critical"
	}

	evidenceLines := fmt.Sprintf("HTTP %d from %s\nresource URI: %s\nresources examined: %d of %d listed\ncontent snippet: %.400s",
		read.statusCode, session.Endpoint, read.uri, examined, len(uris), read.content)
	title := fmt.Sprintf("MCP resource %q content readable without authentication", read.uri)
	description := fmt.Sprintf("resources/read for %s returned content without authentication. "+
		"Resource data is directly accessible to any unauthenticated caller.", read.uri)

	if read.credEvidence != "" {
		title = fmt.Sprintf("MCP resource %q contains potential credentials and is readable without authentication", read.uri)
		description += "\n\nCredential pattern detected in content: " + read.credEvidence
		evidenceLines += "\n" + read.credEvidence
	}

	findings = append(findings, attack.Finding{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    sev,
		Confidence:  attack.ConfirmedExploit,
		Title:       title,
		Description: description,
		Evidence:    evidenceLines,
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	return findings, true
}

// resourceRead is one successfully read resource.
type resourceRead struct {
	uri          string
	statusCode   int
	content      string
	credEvidence string
}

// readResources reads resources until one yields a credential, up to
// maxResourceReads. It returns that resource if any content matched, otherwise
// the first resource that could be read at all, along with the number of
// resources it attempted. A nil result means nothing could be read.
//
// examined is reported in the finding's evidence, because a run that stopped at
// the cap has not looked at everything and must not read as though it had.
func (e *ResourcesUnauthExecutor) readResources(ctx context.Context, client *attack.HTTPClient, session mcpSession, uris []string) (result *resourceRead, examined int) {
	var first *resourceRead

	for i, uri := range uris {
		if examined >= maxResourceReads {
			break
		}
		examined++

		read := e.readResource(ctx, client, session, uri, i)
		if read == nil {
			continue
		}
		// A credential is the strongest evidence available, so stop as soon as
		// one turns up rather than spending the remaining budget.
		if read.credEvidence != "" {
			return read, examined
		}
		if first == nil {
			first = read
		}
	}

	return first, examined
}

// readResource performs one resources/read and classifies its content. It
// returns nil when the read did not produce content, which covers a transport
// failure, a non-2xx reply, an unparseable body and a JSON-RPC error.
func (e *ResourcesUnauthExecutor) readResource(ctx context.Context, client *attack.HTTPClient, session mcpSession, uri string, i int) *resourceRead {
	// Distinct ids per read: reusing one id across requests makes a server's
	// replies ambiguous to correlate.
	resp, err := session.post(ctx, client, 4+i, "resources/read", map[string]interface{}{"uri": uri})
	if err != nil || !resp.IsSuccess() {
		return nil
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil
	}
	if _, hasErr := body["error"]; hasErr {
		return nil
	}

	content := string(resp.Body)
	read := &resourceRead{uri: uri, statusCode: resp.StatusCode, content: content}
	for _, re := range credentialPatterns {
		if loc := re.FindStringIndex(content); loc != nil {
			read.credEvidence = fmt.Sprintf("Pattern matched: %s at byte offset %d", re.String(), loc[0])
			break
		}
	}
	return read
}

// initializeMCP performs the MCP initialize handshake and returns a session
// containing the working endpoint and the Mcp-Session-Id header value (if any).
// Servers implementing MCP 2025-03-26 require the session ID on all follow-up
// requests; omitting it causes 4xx errors that silently suppress findings.
func initializeMCP(ctx context.Context, client *attack.HTTPClient, baseURL string) (mcpSession, error) {
	// A sibling rule may already have resolved which path completes a
	// handshake. Try it first and skip the remaining candidates; if that one
	// endpoint stops answering mid-scan (restart, flake), fall through to the
	// full walk rather than trusting a stale resolution.
	endpoints := endpointCandidates(baseURL)
	cachedEp, hadCached := client.Discovery().LegacyEndpoint(baseURL)
	if hadCached {
		endpoints = append([]string{cachedEp}, endpoints...)
	}
	// Why the walk failed, so a rule that could not run can say what happened
	// instead of sending the operator to check their network. Classified from the
	// responses this loop already has, so it costs no extra requests.
	var observed initObservation
	for _, ep := range endpoints {
		initResp, err := client.POST(ctx, ep, nil, legacyHandshakeBody())
		if err != nil {
			continue // transport failure: nothing answered, so nothing to explain
		}
		if !initResp.IsSuccess() || !initializeSucceeded(initResp.Body) {
			if hadCached && ep == cachedEp {
				// The remembered endpoint has gone stale: forget it and let
				// this walk continue over every candidate as before.
				client.Discovery().RememberLegacy(baseURL, "")
			}
			observed.observe(classifyInitFailure(ep, client.PresentsCredential(ep), initResp))
			continue
		}

		session := mcpSession{
			Endpoint:        ep,
			SessionID:       initResp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(initResp.Body),
			RawInit:         initResp.Body,
		}

		// First successful resolution wins for the whole scan: later rules
		// start here instead of re-walking every candidate.
		client.Discovery().RememberLegacy(baseURL, ep)

		// notifications/initialized - fire and forget
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})

		return session, nil
	}

	// No candidate path completed a legacy handshake. Before reporting the target
	// as unreachable, check whether it is actually a modern (2026-07-28) server,
	// which has no initialize method at all.
	if err := modernEraReason(ctx, client, endpoints); err != nil {
		return mcpSession{}, err
	}

	// Something answered and explained itself. Era detection still gets first say,
	// because "your server speaks a revision we do not" is a better answer than the
	// refusal that revision produced.
	if observed.rank > rankNothing {
		return mcpSession{}, handshakeRefusal{observed.reason}
	}

	return mcpSession{}, fmt.Errorf("no MCP server found at %s", baseURL)
}

// modernEraReason returns the error to carry forward when none of endpoints
// completed a legacy handshake but one of them turns out to speak the modern
// (2026-07-28) revision, and nil when none does.
//
// Distinguishing the two is the difference between telling an operator "this
// scanner does not speak your protocol version" and a bare "could not connect".
// It runs only on a failure path, so a legacy server, still the norm, pays
// nothing for it.
func modernEraReason(ctx context.Context, client *attack.HTTPClient, endpoints []string) error {
	for _, ep := range endpoints {
		if detectEra(ctx, client, ep) == EraModern {
			return fmt.Errorf("%w: %s speaks MCP %s (stateless era), which these rules do not yet support",
				errModernEra, ep, modernEraVersion)
		}
	}
	return nil
}
