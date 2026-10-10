package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

// OAuthAudienceExecutor tests audience-matching traps on both MCP wires.
// A forged-token acceptance also implies broken signature validation; this rule
// does not test validly signed tokens issued for another resource.
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
	// judgedAt names the surface the verdict came from: "initialize", or the
	// gated method an ungated-initialize server was re-probed against.
	judgedAt string
}

// Execute runs the audience-matching probes against the target.
func (e *OAuthAudienceExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	expected := strings.TrimSpace(opts.AudienceClaim)
	operatorSupplied := expected != ""
	if !operatorSupplied {
		discovered, mcpReached, observed, err := discoverExpectedAudience(ctx, client,
			attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
		if err != nil {
			return nil, err
		}
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
				if observed.rank > rankNothing {
					return nil, inconclusive(handshakeRefusal{observed.reason})
				}
				return nil, attack.ErrInconclusive
			}
			return nil, nil
		}
		expected = discovered
	}

	probes := buildProbes(expected)

	anon := attack.NewUnauthHTTPClient(opts, vars)
	endpoint, outcomes, legacyErr := runProbesAgainstEndpoint(ctx, client,
		anon, vars.BaseURL, probes)
	modernEndpoint, modernOutcomes, err := runModernAudienceProbes(ctx, anon, vars.BaseURL, probes)
	if err != nil {
		return nil, err
	}
	var findings []attack.Finding
	if endpoint != "" {
		if finding := coalesceOutcomes(e.rule, endpoint, expected, outcomes); finding != nil {
			findings = append(findings, *finding)
		}
	}
	if modernEndpoint != "" {
		if finding := coalesceOutcomes(e.rule, modernEndpoint, expected, modernOutcomes); finding != nil {
			findings = append(findings, labelEra(mcpSession{Era: EraModern}, []attack.Finding{*finding})...)
		}
	}
	if len(findings) > 0 {
		return findings, nil
	}
	if legacyErr != nil {
		return nil, legacyErr
	}
	if endpoint == "" && modernEndpoint == "" {
		return nil, attack.ErrInconclusive
	}

	// A clean result needs every probe judged on each established wire. An
	// entirely unjudged legacy attempt does not establish a legacy wire when a
	// modern wire answered.
	legacyIncomplete := endpoint != "" && anyProbeInconclusive(outcomes) &&
		(modernEndpoint == "" || !allProbeInconclusive(outcomes))
	if legacyIncomplete || (modernEndpoint != "" && anyProbeInconclusive(modernOutcomes)) {
		return nil, fmt.Errorf("%w: one or more credential-gated MCP requests did not judge an audience probe (legacy HTTP %s; modern HTTP %s)",
			attack.ErrInconclusive, outcomeStatuses(outcomes), outcomeStatuses(modernOutcomes))
	}

	// Nothing was accepted. That is only a clean result if the probes were built
	// from the audience this server actually uses, so verify the premise before
	// reporting one. The check runs here rather than up front for two reasons: a
	// scan that found something needs no premise check, and a disagreement is not
	// a reason to withhold a finding the server demonstrated.
	if operatorSupplied {
		judgedEndpoint := endpoint
		if judgedEndpoint == "" {
			judgedEndpoint = modernEndpoint
		}
		advertised, _, _, err := discoverExpectedAudience(ctx, client,
			attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
		if err != nil {
			return nil, err
		}
		if advertised != "" && advertised != expected {
			return nil, fmt.Errorf("%w: the probes were built from the --audience-claim value %q, "+
				"but %s advertises %q as its resource audience; RFC 7519 section 4.1.3 compares the "+
				"aud claim exactly, so every probe was a plain mismatch this server refuses whether "+
				"or not its audience matching is sound; rerun with the advertised value, or with no "+
				"--audience-claim to use it automatically",
				attack.ErrInconclusive, expected, judgedEndpoint, advertised)
		}
	}
	return nil, nil
}

func runModernAudienceProbes(ctx context.Context, anon *attack.HTTPClient, baseURL string, probes []audienceProbe) (string, []probeOutcome, error) {
	for _, ep := range endpointCandidates(baseURL) {
		gate := probeModernAuthGate(ctx, anon, ep)
		if !gate.ready {
			continue
		}
		outcomes := make([]probeOutcome, 0, len(probes))
		for _, p := range probes {
			tok, err := forgeHS256JWT(map[string]interface{}{
				"iss": "https://attacker.example.com", "sub": "batesian-probe",
				"aud": p.audClaim, "iat": 1700000000, "exp": 9999999999,
			})
			if err != nil {
				return "", nil, fmt.Errorf("forging token for probe %s: %w", p.name, err)
			}
			resp, access := probeModernBearer(ctx, anon, ep, gate.method, tok)
			outcome := probeOutcome{probe: p, verdict: verdictInconclusive, tokenHP: jwtHeaderPayload(tok), judgedAt: gate.method}
			if resp != nil {
				outcome.status = resp.StatusCode
				outcome.bodySnip = snippetMCP(resp.Body)
			}
			switch access {
			case accessGranted:
				outcome.verdict = verdictAcceptedVulnerable
			case accessRefused:
				outcome.verdict = verdictRejected
			}
			outcomes = append(outcomes, outcome)
		}
		return ep, outcomes, nil
	}
	return "", nil, nil
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
func discoverExpectedAudience(ctx context.Context, client, metaClient *attack.HTTPClient,
	baseURL string) (audience string, mcpReached bool, observed initObservation, err error) {
	metaURL, mcpReached, observed := probeWWWAuthenticateResourceMetadata(ctx, client, baseURL)
	if metaURL != "" {
		resource, err := fetchResourceFromMetadata(ctx, metaClient, metaURL)
		if err != nil {
			return "", mcpReached, observed, err
		}
		if resource != "" {
			return resource, mcpReached, observed, nil
		}
	}
	wellKnown := endpoint.AppendPath(baseURL, "/.well-known/oauth-protected-resource")
	resource, err := fetchResourceFromMetadata(ctx, metaClient, wellKnown)
	return resource, mcpReached, observed, err
}

// probeWWWAuthenticateResourceMetadata sends an unauth initialize request to
// the first responsive endpoint candidate and returns the resource_metadata
// URL advertised in the WWW-Authenticate response header, if any.
// mcpReached reports whether any candidate answered the handshake, which is what
// separates "this MCP server exposes no OAuth" from "nothing here answered at
// all". The first is a clean result for an OAuth-gated rule; the second is a
// target that was never tested.
func probeWWWAuthenticateResourceMetadata(ctx context.Context, client *attack.HTTPClient,
	baseURL string) (metadataURL string, mcpReached bool, observed initObservation) {
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
			return u, true, observed
		}
		modern := mcpSession{Endpoint: ep, Era: EraModern}
		modernResp, modernErr := modern.postShaping(ctx, client, 1, "server/discover", nil, func(headers map[string]string) {
			headers["Authorization"] = ""
		})
		if modernErr == nil && modernResp != nil {
			if u := parseResourceMetadataURL(modernResp.Headers.Get("WWW-Authenticate")); u != "" {
				return u, true, observed
			}
			if modernResp.IsAccepted() && modernWireAdvertised(modernResp.Body) {
				for _, method := range modernAuthMethods {
					methodResp, methodErr := modern.postShaping(ctx, client, 2, method, nil, func(headers map[string]string) {
						headers["Authorization"] = ""
					})
					if methodErr == nil && methodResp != nil {
						if u := parseResourceMetadataURL(methodResp.Headers.Get("WWW-Authenticate")); u != "" {
							return u, true, observed
						}
					}
				}
				return "", true, observed
			}
		}
		// An endpoint that answered the handshake is the server, and it issued no
		// challenge. The remaining candidates are the same server at paths it does
		// not serve, so walking them only adds 404s.
		if isMCPInitialize(resp) {
			return "", true, observed
		}
		// It answered and it was neither a challenge nor a handshake. Record why, so
		// a rule that ends up reporting nothing can say what it met. This probe is
		// deliberately unauthenticated, so a refusal here is about the anonymous
		// request rather than about any credential the operator supplied.
		observed.observe(classifyInitFailure(ep, false, resp))
	}
	return "", false, observed
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
func fetchResourceFromMetadata(ctx context.Context, client *attack.HTTPClient, metaURL string) (string, error) {
	resp, err := client.GETOAuth(ctx, metaURL, nil)
	if err != nil {
		if errors.Is(err, attack.ErrInconclusive) {
			return "", err
		}
		return "", nil
	}
	if !resp.IsSuccess() {
		return "", nil
	}
	resource := resp.JSONField("resource")
	if resource == "" {
		return "", nil
	}
	parsed, err := url.Parse(resource)
	if err != nil || !parsed.IsAbs() {
		return "", nil
	}
	return parsed.String(), nil
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
//
// anon is a credential-free client. It backs one control: a probe accepted at
// initialize only says something about tokens if the server examines them
// there, and plenty of servers leave initialize ungated and authorize the calls
// that follow. On those, every forged token was accepted by a method that never
// looked at it, and this rule reported blanket forged-token acceptance on the
// strength of it. When any probe is accepted, probeInitGate establishes where
// the gate sits; if it is after initialize, every probe is re-judged at the
// gated method (see init_gate.go).
func runProbesAgainstEndpoint(ctx context.Context, client *attack.HTTPClient, anon *attack.HTTPClient, baseURL string, probes []audienceProbe) (string, []probeOutcome, error) {
	forge := func(p audienceProbe) (string, error) {
		return forgeHS256JWT(map[string]interface{}{
			"iss": "https://attacker.example.com",
			"sub": "batesian-probe",
			"aud": p.audClaim,
			"iat": 1700000000,
			"exp": 9999999999,
		})
	}
	for _, ep := range endpointCandidates(baseURL) {
		outcomes := make([]probeOutcome, 0, len(probes))
		anyResponse := false
		anyAccepted := false
		for _, p := range probes {
			tok, err := forge(p)
			if err != nil {
				return "", nil, fmt.Errorf("forging token for probe %s: %w", p.name, err)
			}
			resp, err := client.POST(ctx, ep, map[string]string{
				"Authorization": "Bearer " + tok,
				"Content-Type":  "application/json",
			}, json.RawMessage(mcpInitBody))
			if err != nil {
				outcomes = append(outcomes, probeOutcome{
					probe:    p,
					verdict:  verdictInconclusive,
					tokenHP:  jwtHeaderPayload(tok),
					judgedAt: "initialize",
				})
				continue
			}
			if !endpointAbsent(resp) {
				anyResponse = true
			}
			verdict := classifyResponse(resp)
			if verdict == verdictAcceptedVulnerable {
				anyAccepted = true
			}
			outcomes = append(outcomes, probeOutcome{
				probe:    p,
				verdict:  verdict,
				status:   resp.StatusCode,
				bodySnip: snippetMCP(resp.Body),
				tokenHP:  jwtHeaderPayload(tok),
				judgedAt: "initialize",
			})
		}
		if !anyResponse {
			continue
		}

		if anyAccepted {
			gp := probeInitGate(ctx, anon, ep)
			switch gp.gate {
			case gateOnInit:
				// Initialize itself demands a credential; its verdicts stand.
			case gateAfterInit:
				// Initialize does not authenticate; the advertised listing
				// does. Re-judge every probe there.
				var incomplete []string
				for i := range outcomes {
					tok, err := forge(outcomes[i].probe)
					if err != nil {
						return "", nil, fmt.Errorf("forging token for probe %s: %w", outcomes[i].probe.name, err)
					}
					mresp, verdict, reason := probeForgedAtMethod(ctx, anon, ep, gp.method, tok)
					if reason != "" {
						incomplete = append(incomplete, outcomes[i].probe.name+": "+reason)
					}
					outcomes[i].tokenHP = jwtHeaderPayload(tok)
					outcomes[i].judgedAt = judgedAtLabel(gp.method)
					outcomes[i].verdict = verdictInconclusive
					outcomes[i].status = 0
					outcomes[i].bodySnip = ""
					if mresp != nil {
						outcomes[i].status = mresp.StatusCode
						outcomes[i].bodySnip = snippetMCP(mresp.Body)
					}
					switch verdict {
					case accessGranted:
						outcomes[i].verdict = verdictAcceptedVulnerable
					case accessRefused:
						outcomes[i].verdict = verdictRejected
					}
				}
				if len(incomplete) > 0 {
					return ep, outcomes, fmt.Errorf("%w: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
				}
			default:
				// gateNowhere / gateUnknown: nothing here can be attributed to
				// the token rather than to an open surface or a control that
				// did not answer.
				return "", nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, gp.reason)
			}
		}
		return ep, outcomes, nil
	}
	return "", nil, nil
}

// classifyResponse distinguishes token refusals from protocol errors and
// transport failures. Only a JSON-RPC result proves acceptance.
func classifyResponse(resp *attack.Response) audVerdict {
	switch {
	case resp.StatusCode == 200:
		body := resp.BodyString()
		if isJSONRPCError(body) {
			if authRefusal(resp) {
				return verdictRejected
			}
			return verdictInconclusive
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
	case authRefusal(resp):
		return verdictRejected
	default:
		// A 429 from a rate limiter, a bare 400, an HTML 500: the server did not
		// judge the token. classifyAccess leaves these undetermined, and so does
		// this rule now.
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

func anyProbeInconclusive(outcomes []probeOutcome) bool {
	for _, o := range outcomes {
		if o.verdict == verdictInconclusive {
			return true
		}
	}
	return false
}

func allProbeInconclusive(outcomes []probeOutcome) bool {
	if len(outcomes) == 0 {
		return false
	}
	for _, o := range outcomes {
		if o.verdict != verdictInconclusive {
			return false
		}
	}
	return true
}

// outcomeStatuses renders the distinct HTTP statuses the probes received, for
// the not-tested reason. Zero is a transport failure, which said nothing about
// the endpoint and is left out.
func outcomeStatuses(outcomes []probeOutcome) string {
	seen := map[int]bool{}
	statuses := []string{}
	for _, o := range outcomes {
		if o.status == 0 || seen[o.status] {
			continue
		}
		seen[o.status] = true
		statuses = append(statuses, strconv.Itoa(o.status))
	}
	return strings.Join(statuses, ", ")
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
	if o.judgedAt != "" && o.judgedAt != "initialize" {
		fmt.Fprintf(sb, "      judged at: %s\n", o.judgedAt)
	}
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
	if len(s) <= 200 {
		return s
	}
	// Back the cut to a rune boundary so a multi-byte character is never split.
	// The result ends up in Finding.Evidence, which is marshalled to JSON/SARIF,
	// where a trailing partial rune is silently rewritten to U+FFFD.
	cut := 200
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
