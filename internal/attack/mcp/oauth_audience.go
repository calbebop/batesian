package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// OAuthAudienceExecutor implements rule mcp-oauth-audience-002.
//
// It complements mcp-token-replay-001 by probing whether the server's `aud`
// matching logic is robust to common implementation bugs (substring match,
// case canonicalization, array-shape branch skip) once the operator's expected
// audience value is known. The expected value is taken from
// opts.AudienceClaim or, when unset, RFC 9728 protected-resource-metadata.
//
// Because probes are forged HS256 self-signed tokens, acceptance indicates a
// compound failure: signature validation AND audience matching both inadequate.
// The "validly signed cross-resource token" class (Parse CVE-2026-30863) is
// out of scope for v1 and is tracked as a follow-up issue.
type OAuthAudienceExecutor struct {
	rule attack.RuleContext
}

// NewOAuthAudienceExecutor creates an executor for mcp-oauth-audience.
func init() {
	attack.Register("mcp-oauth-audience", func(rc attack.RuleContext) attack.Executor { return NewOAuthAudienceExecutor(rc) })
}

func NewOAuthAudienceExecutor(r attack.RuleContext) *OAuthAudienceExecutor {
	return &OAuthAudienceExecutor{rule: r}
}

// canaryDomain is appended to the operator's expected audience to construct an
// unmistakably wrong substring-trap value. Using `.invalid` (RFC 6761 section 6.4)
// guarantees the canary cannot resolve to a real resource.
const canaryDomain = ".canary-batesian-mismatch.invalid"

// audienceProbe describes one forged-JWT probe and its assertion semantics.
type audienceProbe struct {
	name        string
	audClaim    interface{} // string or []string
	titleSuffix string
	descSuffix  string
	// isControl marks the negative-control probe: a forged token carrying an
	// audience that is plainly unrelated to the expected value. Because every
	// probe is forged with the same (bad) signature, the control isolates the
	// audience-matching logic - if the control is accepted, the server accepts
	// any forged token regardless of `aud`, so a trap acceptance cannot be
	// attributed to a specific matching bug.
	isControl bool
}

// audVerdict is the per-probe classification used during coalescing.
type audVerdict int

const (
	verdictRejected audVerdict = iota
	verdictAcceptedVulnerable
	verdictInconclusive
)

// probeOutcome captures the per-probe result against a chosen endpoint.
type probeOutcome struct {
	probe    audienceProbe
	verdict  audVerdict
	status   int
	bodySnip string
	tokenHP  string // header.payload (signature redacted)
}

// Execute runs the audience-matching probes against the target.
func (e *OAuthAudienceExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	expected := strings.TrimSpace(opts.AudienceClaim)
	if expected == "" {
		discovered, mcpReached := discoverExpectedAudience(ctx, client, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
		if discovered == "" {
			// Precondition not met: no operator input and no discoverable
			// resource metadata. Operators who want this rule to run should pass
			// --audience-claim or expose RFC 9728 metadata on the target.
			//
			// Which of two things happened decides how that is reported. An MCP
			// server that answered but advertises no metadata is genuinely not
			// applicable, and clean is honest. A target where nothing answered
			// was never exercised, and clean there would claim coverage the scan
			// does not have.
			if !mcpReached {
				return nil, attack.ErrInconclusive
			}
			return nil, nil
		}
		expected = discovered
	}

	probes := buildProbes(expected)

	endpoint, outcomes, err := runProbesAgainstEndpoint(ctx, client, vars.BaseURL, probes)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		// No candidate endpoint produced a usable response for any probe.
		return nil, attack.ErrInconclusive
	}

	finding := coalesceOutcomes(e.rule, endpoint, expected, outcomes)
	if finding == nil {
		return nil, nil
	}
	return []attack.Finding{*finding}, nil
}

// buildProbes constructs the v1 probe set from the operator's expected audience.
//
// The substring trap appends a clearly-different invalid-TLD canary so any
// validator using strings.Contains/HasPrefix/HasSuffix accepts the wrapped
// value. The case-canonicalization trap toggles case (or default-port presence
// when the value is already lowercase). The array probe submits two canaries
// in JSON-array form so validators that branch on the claim shape and skip
// the array path are exposed.
func buildProbes(expected string) []audienceProbe {
	substringTrap := expected + canaryDomain

	caseTrap := caseCanonicalizationVariant(expected)

	arrayCanaries := []string{
		"https://canary-batesian-a" + canaryDomain,
		"https://canary-batesian-b" + canaryDomain,
	}

	return []audienceProbe{
		{
			name:        "aud-control-unrelated",
			audClaim:    "https://batesian-control" + canaryDomain,
			isControl:   true,
			titleSuffix: "accepted a forged token whose aud is entirely unrelated to the expected audience",
			descSuffix: "The server accepted a forged HS256 bearer token whose `aud` claim does not " +
				"contain or resemble the expected audience at all. The token is not validly signed, so " +
				"acceptance means the server is not enforcing token signature and/or audience validation " +
				"on this endpoint - any forged token is accepted regardless of audience. Because the " +
				"control was accepted, no specific aud-matching bug can be isolated; see mcp-token-replay-001.",
		},
		{
			name:        "aud-substring-trap",
			audClaim:    substringTrap,
			titleSuffix: "accepted JWT whose aud is a substring-wrapped mismatch",
			descSuffix: "The server accepted a bearer token whose `aud` claim wraps the " +
				"expected audience inside a clearly-different value (`" + substringTrap + "`). " +
				"This is consistent with a validator that uses `Contains` / `HasPrefix` / " +
				"`HasSuffix` instead of the strict StringOrURI compare required by RFC 7519 section 4.1.3.",
		},
		{
			name:        "aud-case-canonicalization-trap",
			audClaim:    caseTrap,
			titleSuffix: "accepted JWT whose aud differs only in case or default-port presence",
			descSuffix: "The server accepted a bearer token whose `aud` claim is the expected " +
				"audience with case folding or default-port canonicalization applied (`" + caseTrap + "`). " +
				"RFC 7519 audience comparison must be exact and case-sensitive; canonicalization " +
				"performed by the validator inflates the set of accepted values.",
		},
		{
			name:        "aud-array-canary-only",
			audClaim:    arrayCanaries,
			titleSuffix: "accepted JWT whose aud is an array of mismatched canaries",
			descSuffix: "The server accepted a bearer token whose `aud` claim is a JSON array " +
				"containing only canaries that do not match the expected audience. This is " +
				"consistent with a validator that inspects only string-form `aud` and treats " +
				"array-shape claims as pre-validated.",
		},
	}
}

// caseCanonicalizationVariant returns a value that differs from `expected`
// only in case or default-port presence. RFC 7519 requires strict comparison,
// so a server that accepts the variant is mishandling the claim.
func caseCanonicalizationVariant(expected string) string {
	if hasUpper(expected) {
		return strings.ToLower(expected)
	}
	// Already lowercase: toggle default-port presence to provoke
	// canonicalizing URL parsers.
	if strings.HasPrefix(expected, "https://") && !defaultPortRE.MatchString(expected) {
		return injectDefaultPort(expected, "https", "443")
	}
	if strings.HasPrefix(expected, "http://") && !defaultPortRE.MatchString(expected) {
		return injectDefaultPort(expected, "http", "80")
	}
	// Last resort: append uppercase suffix; still differs only by case.
	return expected + "/X"
}

// defaultPortRE matches a host:port suffix anywhere in the URL authority.
// We use it to detect whether a default port has already been embedded.
var defaultPortRE = regexp.MustCompile(`://[^/]+:\d+`)

// injectDefaultPort places :port immediately after the host, producing a
// URL that canonicalizes back to `expected` per RFC 3986 section 3.2.3 if a server
// runs the value through a URL parser before comparing.
func injectDefaultPort(expected, scheme, port string) string {
	prefix := scheme + "://"
	rest := strings.TrimPrefix(expected, prefix)
	slash := strings.Index(rest, "/")
	host := rest
	tail := ""
	if slash >= 0 {
		host = rest[:slash]
		tail = rest[slash:]
	}
	return prefix + host + ":" + port + tail
}

func hasUpper(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

// discoverExpectedAudience implements the RFC 9728 fallback chain.
//
//  1. Probe POST {base}/mcp without auth and parse
//     `WWW-Authenticate: ... resource_metadata="<url>"`.
//  2. GET that URL and read `resource`.
//  3. Fall back to GET {base}/.well-known/oauth-protected-resource.
//
// Returns the resource URI on success, or an empty string if nothing
// usable was found (caller treats that as "skip").
// metaClient is unauthenticated because step 2 follows a URL the target chose.
func discoverExpectedAudience(ctx context.Context, client, metaClient *attack.HTTPClient, baseURL string) (audience string, mcpReached bool) {
	metaURL, mcpReached := probeWWWAuthenticateResourceMetadata(ctx, client, baseURL)
	if metaURL != "" {
		if resource := fetchResourceFromMetadata(ctx, metaClient, metaURL); resource != "" {
			return resource, mcpReached
		}
	}
	wellKnown := baseURL + "/.well-known/oauth-protected-resource"
	return fetchResourceFromMetadata(ctx, metaClient, wellKnown), mcpReached
}

// probeWWWAuthenticateResourceMetadata sends an unauth initialize request to
// the first responsive endpoint candidate and returns the resource_metadata
// URL advertised in the WWW-Authenticate response header, if any.
// mcpReached reports whether any candidate answered the handshake, which is what
// separates "this MCP server exposes no OAuth" from "nothing here answered at
// all". The first is a clean result for an OAuth-gated rule; the second is a
// target that was never tested.
func probeWWWAuthenticateResourceMetadata(ctx context.Context, client *attack.HTTPClient, baseURL string) (metadataURL string, mcpReached bool) {
	body := json.RawMessage(mcpInitBody)
	for _, ep := range endpointCandidates(baseURL) {
		// Use no Authorization header (override any opts.Token) so the server
		// emits its 401 challenge with resource_metadata advertisement.
		resp, err := client.POST(ctx, ep, map[string]string{
			"Authorization": "",
			"Content-Type":  "application/json",
		}, body)
		if err != nil {
			continue
		}
		// 401 is the expected discovery response; some servers also emit the
		// header on 403. We accept any response that carries the header.
		if u := parseResourceMetadataURL(resp.Headers.Get("WWW-Authenticate")); u != "" {
			// A challenge is itself proof the endpoint is live and gated.
			return u, true
		}
		// An endpoint that answered the handshake is the server, and it issued no
		// challenge. The remaining candidates are the same server at paths it does
		// not serve, so walking them only adds 404s.
		if isMCPInitialize(resp) {
			return "", true
		}
	}
	return "", false
}

// resourceMetadataRE extracts the resource_metadata="..." parameter from a
// WWW-Authenticate header per RFC 9728 section 5.1.
var resourceMetadataRE = regexp.MustCompile(`(?i)resource_metadata\s*=\s*"([^"]+)"`)

func parseResourceMetadataURL(header string) string {
	if header == "" {
		return ""
	}
	m := resourceMetadataRE.FindStringSubmatch(header)
	if len(m) != 2 {
		return ""
	}
	parsed, err := url.Parse(m[1])
	if err != nil || !parsed.IsAbs() {
		return ""
	}
	return parsed.String()
}

// fetchResourceFromMetadata GETs the metadata document and returns the
// `resource` field if present and absolute.
//
// metaURL may come from the target's own WWW-Authenticate challenge, so it can
// name any host. Protected-resource metadata is public per RFC 9728 and needs no
// credential, and the caller therefore passes an unauthenticated client: a target
// that points resource_metadata at a host it controls must not be handed the
// operator's bearer token. The transport enforces this as well, so this is
// defence in depth plus a statement of intent at the call site.
func fetchResourceFromMetadata(ctx context.Context, client *attack.HTTPClient, metaURL string) string {
	resp, err := client.GET(ctx, metaURL, nil)
	if err != nil || !resp.IsSuccess() {
		return ""
	}
	resource := resp.JSONField("resource")
	if resource == "" {
		return ""
	}
	parsed, err := url.Parse(resource)
	if err != nil || !parsed.IsAbs() {
		return ""
	}
	return parsed.String()
}

// runProbesAgainstEndpoint sends every probe to each candidate endpoint and
// returns the outcomes for the first endpoint that produced a usable response.
//
// "Usable" means the endpoint actually engaged with the token. A transport
// failure does not count, and neither does a reply that only says the path is
// not there: this loop used to accept any response that was not a transport
// error, so an unrouted candidate answering 404 ended the walk immediately and
// the real endpoint further down the list was never probed. Combined with 404
// classifying as a rejection, that made the rule report a target secure on the
// strength of four requests to a path that did not exist. A stray /api path must
// not be able to hide a real /mcp finding, which is what the old comment here
// claimed and the code did not do.
func runProbesAgainstEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string, probes []audienceProbe) (string, []probeOutcome, error) {
	for _, ep := range endpointCandidates(baseURL) {
		outcomes := make([]probeOutcome, 0, len(probes))
		anyResponse := false
		for _, p := range probes {
			tok, err := forgeHS256JWT(map[string]interface{}{
				"iss": "https://attacker.example.com",
				"sub": "batesian-probe",
				"aud": p.audClaim,
				"iat": 1700000000,
				"exp": 9999999999,
			})
			if err != nil {
				return "", nil, fmt.Errorf("forging token for probe %s: %w", p.name, err)
			}
			resp, err := client.POST(ctx, ep, map[string]string{
				"Authorization": "Bearer " + tok,
				"Content-Type":  "application/json",
			}, json.RawMessage(mcpInitBody))
			if err != nil {
				outcomes = append(outcomes, probeOutcome{
					probe:   p,
					verdict: verdictInconclusive,
					tokenHP: jwtHeaderPayload(tok),
				})
				continue
			}
			if !endpointAbsent(resp) {
				anyResponse = true
			}
			outcomes = append(outcomes, probeOutcome{
				probe:    p,
				verdict:  classifyResponse(resp),
				status:   resp.StatusCode,
				bodySnip: snippetMCP(resp.Body),
				tokenHP:  jwtHeaderPayload(tok),
			})
		}
		if anyResponse {
			return ep, outcomes, nil
		}
	}
	return "", nil, nil
}

// classifyResponse maps an HTTP response into the verdict taxonomy.
//
// HTTP 200 + a JSON-RPC `result` envelope is the cleanest acceptance signal.
// HTTP 200 + a JSON-RPC `error` envelope is treated as rejection because the
// server is explicitly refusing the call. HTTP 200 with neither shape (empty
// body, raw HTML, "{}", etc.) is inconclusive: it is not evidence that the call
// was accepted, so it produces no finding. (Previously this was treated as a
// downgraded "ambiguous" acceptance, which false-positived non-MCP targets whose
// /mcp request fell through to a 200 HTML page.)
func classifyResponse(resp *attack.Response) audVerdict {
	switch {
	case resp.StatusCode == 200:
		body := resp.BodyString()
		// Strict precedence: an `error` envelope means the JSON-RPC layer
		// rejected the call regardless of HTTP status.
		if isJSONRPCError(body) {
			return verdictRejected
		}
		if isJSONRPCResult(body) {
			return verdictAcceptedVulnerable
		}
		return verdictInconclusive
	case resp.StatusCode == 401, resp.StatusCode == 403:
		return verdictRejected
	case endpointAbsent(resp):
		// There is no MCP endpoint at this path, so nothing examined the token.
		// Calling it a rejection read a 404 as evidence that audience matching
		// worked, which is how this rule reported a whole target secure on the
		// strength of paths that did not exist.
		return verdictInconclusive
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return verdictRejected
	default:
		return verdictInconclusive
	}
}

// endpointAbsent reports whether a response says "there is nothing here to talk
// to" rather than anything about the request that was made.
//
// 404 means the path is unrouted. 405 means it is routed but does not take the
// POST an MCP call requires, so it is not an MCP endpoint either. Neither is a
// verdict on the forged token, and neither should end the candidate walk.
func endpointAbsent(resp *attack.Response) bool {
	return resp.StatusCode == 404 || resp.StatusCode == 405
}

// isJSONRPCResult reports whether body parses as a JSON-RPC response with a
// non-empty `result` field. We accept both the streamable-HTTP wrapped form
// and a raw JSON envelope.
func isJSONRPCResult(body string) bool {
	if body == "" {
		return false
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	if _, ok := m["result"]; ok {
		return true
	}
	return false
}

func isJSONRPCError(body string) bool {
	if body == "" {
		return false
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	if _, ok := m["error"]; ok {
		return true
	}
	return false
}

// coalesceOutcomes turns the per-probe results into a single rule-level
// finding (or no finding). Multiple accepted trap probes do not inflate impact:
// they enrich the evidence of one finding.
//
// The negative control is evaluated first. If the control (an unrelated forged
// audience) was clearly accepted, the server accepts any forged token and no
// specific aud-matching bug can be isolated - we report that blanket-acceptance
// fact instead of a misattributed matching bug. A specific matching-bug finding
// is reported as ConfirmedExploit only when the control was clearly REJECTED
// (so the audience value is the decisive factor); if the control response was
// inconclusive (not clearly rejected), accepted traps are downgraded to
// RiskIndicator because the bug cannot be cleanly isolated.
func coalesceOutcomes(rc attack.RuleContext, endpoint, expected string, outcomes []probeOutcome) *attack.Finding {
	var (
		control    *probeOutcome
		vulnerable []probeOutcome
	)
	for i := range outcomes {
		o := outcomes[i]
		if o.probe.isControl {
			control = &outcomes[i]
			continue
		}
		if o.verdict == verdictAcceptedVulnerable {
			vulnerable = append(vulnerable, o)
		}
	}

	// Control accepted with a clear result envelope: blanket forged-token
	// acceptance, not an isolable matching bug.
	if control != nil && control.verdict == verdictAcceptedVulnerable {
		return &attack.Finding{
			RuleID:      rc.ID,
			RuleName:    rc.Name,
			Severity:    rc.Severity,
			Confidence:  attack.ConfirmedExploit,
			Title:       fmt.Sprintf("MCP server %s", control.probe.titleSuffix),
			Description: control.probe.descSuffix,
			Evidence:    formatEvidence(endpoint, expected, []probeOutcome{*control}),
			Remediation: rc.Remediation,
			TargetURL:   endpoint,
		}
	}

	if len(vulnerable) == 0 {
		return nil
	}

	controlRejected := control != nil && control.verdict == verdictRejected

	// A trap that returned a clear result envelope is a real acceptance. If the
	// negative control was clearly rejected, the audience value is the decisive
	// factor and the matching bug is cleanly isolated (confirmed). Otherwise the
	// control was inconclusive and the bug cannot be fully isolated (indicator).
	primary := vulnerable[0]
	confidence := attack.RiskIndicator
	if controlRejected {
		confidence = attack.ConfirmedExploit
	}

	return &attack.Finding{
		RuleID:      rc.ID,
		RuleName:    rc.Name,
		Severity:    rc.Severity,
		Confidence:  confidence,
		Title:       fmt.Sprintf("MCP server %s", primary.probe.titleSuffix),
		Description: primary.probe.descSuffix,
		Evidence:    formatEvidence(endpoint, expected, vulnerable),
		Remediation: rc.Remediation,
		TargetURL:   endpoint,
	}
}

// formatEvidence renders the per-probe evidence block. The operator-supplied
// audience is summarized rather than echoed verbatim to avoid leaking
// production identifiers into shared scan reports.
func formatEvidence(endpoint, expected string, vulnerable []probeOutcome) string {
	var sb strings.Builder
	sb.WriteString("endpoint: ")
	sb.WriteString(endpoint)
	sb.WriteString("\nexpected aud (summary): ")
	sb.WriteString(summarizeAudience(expected))
	sb.WriteString("\n")

	if len(vulnerable) > 0 {
		sb.WriteString("\nAccepted probes (clear vulnerability signal):\n")
		for _, o := range vulnerable {
			writeOutcomeLine(&sb, o)
		}
	}
	return sb.String()
}

func writeOutcomeLine(sb *strings.Builder, o probeOutcome) {
	fmt.Fprintf(sb, "  - %s: HTTP %d\n", o.probe.name, o.status)
	fmt.Fprintf(sb, "      token header.payload: %s...[signature omitted]\n", o.tokenHP)
	fmt.Fprintf(sb, "      response snippet: %s\n", oneLine(o.bodySnip))
}

// summarizeAudience returns a short, low-leakage description of the operator's
// audience value: the scheme + first 12 characters of the host, plus the host
// length. This is enough for an operator to recognize their own value while
// keeping the full string out of report bodies.
func summarizeAudience(expected string) string {
	parsed, err := url.Parse(expected)
	if err != nil || parsed.Host == "" {
		// Fallback: redact most of the value, keep length.
		return fmt.Sprintf("[len=%d, opaque]", len(expected))
	}
	host := parsed.Host
	const headLen = 12
	if len(host) <= headLen {
		return fmt.Sprintf("%s://%s (host len=%d)", parsed.Scheme, host, len(host))
	}
	return fmt.Sprintf("%s://%s... (host len=%d)", parsed.Scheme, host[:headLen], len(host))
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
