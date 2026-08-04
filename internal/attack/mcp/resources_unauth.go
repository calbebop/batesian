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
	regexp.MustCompile(`(?i)(bearer|authorization)\s*[=:]\s*\S{10,}`),       // Bearer/auth token
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}`),     // JWT
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

	// MCP requires an initialize handshake before any method calls.
	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		// Not reachable as a legacy MCP server; inconclusive carries the reason
		// when the target turned out to be a modern-era server.
		return nil, inconclusive(err)
	}

	var findings []attack.Finding

	// Step 1: resources/list - enumerate available resources
	listResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "resources/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !listResp.IsSuccess() {
		return nil, nil
	}

	var listBody map[string]interface{}
	if err := json.Unmarshal(listResp.Body, &listBody); err != nil {
		return nil, nil
	}

	// JSON-RPC error means the endpoint exists but rejected the call - not vulnerable.
	if _, hasErr := listBody["error"]; hasErr {
		return nil, nil
	}

	result, _ := listBody["result"].(map[string]interface{})
	resourcesRaw, _ := result["resources"].([]interface{})
	if len(resourcesRaw) == 0 {
		return nil, nil
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
		return findings, nil
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

	return findings, nil
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
	resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		// Distinct ids per read: reusing one id across requests makes a
		// server's replies ambiguous to correlate.
		"id":     4 + i,
		"method": "resources/read",
		"params": map[string]interface{}{"uri": uri},
	})
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
	endpoints := endpointCandidates(baseURL)
	for _, ep := range endpoints {
		initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": latestStable,
				"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil || !initResp.IsSuccess() {
			continue
		}
		if !initResp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			continue
		}

		session := mcpSession{
			Endpoint:        ep,
			SessionID:       initResp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(initResp.Body),
			RawInit:         initResp.Body,
		}

		// notifications/initialized - fire and forget
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})

		return session, nil
	}

	// No candidate path completed a legacy handshake. Before reporting the target
	// as unreachable, check whether it is actually a modern (2026-07-28) server,
	// which has no initialize method at all. Distinguishing the two is the
	// difference between "this scanner does not speak your protocol version" and
	// a bare "could not connect".
	//
	// This runs only on the failure path, so a legacy server, still the norm,
	// pays no extra request.
	for _, ep := range endpoints {
		if detectEra(ctx, client, ep) == EraModern {
			return mcpSession{}, fmt.Errorf("%w: %s speaks MCP %s (stateless era), which these rules do not yet support",
				errModernEra, ep, modernEraVersion)
		}
	}

	return mcpSession{}, fmt.Errorf("no MCP server found at %s", baseURL)
}
