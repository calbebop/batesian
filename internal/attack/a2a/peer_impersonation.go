package a2a

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
	protoa2a "github.com/calbebop/batesian/internal/protocol/a2a"
)

// PeerImpersonationExecutor compares a forged bearer JWT with an anonymous
// request. A refusal is only meaningful when the issuer is known and the
// response identifies an authentication failure.
type PeerImpersonationExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-peer-impersonation", func(rc attack.RuleContext) attack.Executor { return NewPeerImpersonationExecutor(rc) })
}

// NewPeerImpersonationExecutor creates an executor for the peer impersonation rule.
func NewPeerImpersonationExecutor(r attack.RuleContext) *PeerImpersonationExecutor {
	return &PeerImpersonationExecutor{rule: r}
}

func (e *PeerImpersonationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
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
	body, cardOK, cardReadReason := fetchAgentCardBodyWithOutcome(ctx, client, vars.BaseURL)
	if cardOK {
		var parsed protoa2a.AgentCard
		if err := json.Unmarshal(body, &parsed); err == nil {
			card = &parsed
			if parsed.Name != "" {
				agentName = parsed.Name
			}
		} else {
			if cardReadReason != "" {
				cardReadReason += "; "
			}
			cardReadReason += "Agent Card fields could not be parsed"
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
	forgedResp, baselineResp, wire, incomplete, ok := e.probeWires(ctx, client, unauthClient, endpoint, forgedToken, vars.RandID)
	if cardReadReason != "" {
		incomplete = append(incomplete, "Agent Card prerequisite: "+cardReadReason)
	}
	if !ok {
		if len(incomplete) > 0 {
			return nil, fmt.Errorf("%w: peer assessment incomplete: %s", attack.ErrInconclusive,
				strings.Join(incomplete, "; "))
		}
		return nil, fmt.Errorf("%w: no revision's send method is implemented at %s "+
			"(tried v1.0 SendMessage and v0.3 message/send), so credential handling was never exercised",
			attack.ErrInconclusive, endpoint)
	}

	forgedOK := forgedResp.IsAccepted()
	baselineOK := baselineResp.IsAccepted()
	forgedDenied := peerAuthDenied(forgedResp)
	baselineDenied := peerAuthDenied(baselineResp)

	if forgedOK && !baselineOK && !baselineDenied {
		incomplete = append(incomplete, wire+" anonymous baseline did not establish an authentication rejection")
	}
	if !forgedOK && !forgedDenied {
		incomplete = append(incomplete, wire+" forged token response did not establish an authentication rejection")
	}
	if !forgedOK && baselineOK {
		incomplete = append(incomplete, wire+" anonymous request succeeded while the forged token was refused")
	}
	if !forgedOK && !claims.discovered() {
		incomplete = append(incomplete, "no trusted issuer was published for the forged token")
	}
	findingObserved := forgedOK && (baselineOK || baselineDenied)
	if len(incomplete) > 0 && !findingObserved {
		return nil, fmt.Errorf("%w: peer assessment incomplete: %s", attack.ErrInconclusive,
			strings.Join(incomplete, "; "))
	}

	var findings []attack.Finding

	switch {
	case forgedOK && baselineDenied:
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "A2A SendMessage accepted a randomly signed JWT but rejected anonymous access",
			Description: fmt.Sprintf(
				"A randomly signed HS256 JWT (sub=%q, iss=%q) was accepted (HTTP %d), while "+
					"the same request without a token was rejected (HTTP %d). This demonstrates "+
					"that this token passed the endpoint's authentication gate. It does not establish "+
					"which claim was honored or that peer-specific privileges were granted.",
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
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "A2A SendMessage accepted an anonymous request",
			Description: fmt.Sprintf(
				"Both a randomly signed JWT request (HTTP %d) and an anonymous request "+
					"(HTTP %d) were accepted. This endpoint permits anonymous SendMessage "+
					"requests; whether that violates policy depends on the deployment. No "+
					"peer identity or elevated privilege was verified.",
				forgedResp.StatusCode, baselineResp.StatusCode),
			Evidence: fmt.Sprintf(
				"wire: %s\nForged response: HTTP %d\nBaseline response: HTTP %d\n%s",
				wire, forgedResp.StatusCode, baselineResp.StatusCode,
				snippet(forgedResp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})

	}

	if cardReadReason != "" {
		for i := range findings {
			findings[i].Evidence += "\nunobserved Agent Card prerequisite: " + cardReadReason
		}
	}
	if len(incomplete) > 0 {
		return findings, fmt.Errorf("%w: peer assessment incomplete: %s", attack.ErrInconclusive,
			strings.Join(incomplete, "; "))
	}
	return findings, nil
}

func peerAuthDenied(resp *attack.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return true
	}
	if !resp.IsSuccess() {
		return false
	}
	_, hasError := jsonRPCErrorCode(resp.Body)
	return hasError && errMessageIsAuth(resp.Body)
}

// impersonationWire is one revision's send request, in the shape that revision
// defines.
type impersonationWire struct {
	name    string
	headers map[string]string
	body    map[string]interface{}
}

// impersonationWires lists the v1.0 and v0.3 send methods, newest first.
func impersonationWires(randID string) []impersonationWire {
	return []impersonationWire{
		{
			name:    "v1.0 SendMessage",
			headers: map[string]string{"A2A-Version": "1.0"},
			body: jsonRPCCall("batesian-peer-"+randID+"-v1", "SendMessage", map[string]interface{}{
				"configuration": map[string]interface{}{"returnImmediately": true},
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
			body: jsonRPCCall("batesian-peer-"+randID+"-v03", "message/send", map[string]interface{}{
				"message": map[string]interface{}{
					"messageId": "batesian-pi-" + randID,
					"role":      "user",
					"parts":     []interface{}{map[string]interface{}{"kind": "text", "text": "ping"}},
				},
			}),
		},
	}
}

// probeWires skips unsupported methods and records unobserved comparisons.
func (e *PeerImpersonationExecutor) probeWires(ctx context.Context, client, unauthClient *attack.HTTPClient,
	endpoint, forgedToken, randID string) (forged, baseline *attack.Response, wire string, incomplete []string, ok bool) {
	for i, w := range impersonationWires(randID) {
		requestID := fmt.Sprintf("batesian-peer-%s-%d", randID, i)
		forgedHeaders := map[string]string{"Authorization": "Bearer " + forgedToken}
		for k, v := range w.headers {
			forgedHeaders[k] = v
		}
		forgedBody := maps.Clone(w.body)
		forgedBody["id"] = requestID + "-forged"
		fResp, err := client.POST(ctx, endpoint, forgedHeaders, forgedBody)
		if err != nil {
			incomplete = append(incomplete, w.name+" forged request failed")
			continue
		}
		baselineBody := maps.Clone(w.body)
		baselineBody["id"] = requestID + "-anonymous"
		bResp, err := unauthClient.POST(ctx, endpoint, w.headers, baselineBody)
		if err != nil {
			incomplete = append(incomplete, w.name+" anonymous request failed")
			continue
		}
		if !peerReplyCorrelated(fResp, requestID+"-forged") ||
			!peerReplyCorrelated(bResp, requestID+"-anonymous") {
			incomplete = append(incomplete, w.name+" reply did not match its request ID")
			continue
		}
		if methodAbsent(fResp) && methodAbsent(bResp) {
			continue
		}
		if methodAbsent(fResp) || methodAbsent(bResp) {
			incomplete = append(incomplete, w.name+" method availability differed between probes")
			continue
		}
		return fResp, bResp, w.name, incomplete, true
	}
	return nil, nil, "", incomplete, false
}

func peerReplyCorrelated(resp *attack.Response, requestID string) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return true
	}
	if !resp.IsSuccess() && !json.Valid(resp.Body) {
		return true
	}
	_, _, _, valid := discoveryResponse(resp.Body, requestID)
	return valid
}

// methodAbsent accepts method-not-found only with an observed RPC response.
func methodAbsent(resp *attack.Response) bool {
	if resp == nil {
		return false
	}
	if !resp.IsSuccess() && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		return false
	}
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
	if resp, err := client.GET(ctx, endpoint.AppendPath(baseURL, "/.well-known/oauth-protected-resource"), nil); err == nil && resp.IsSuccess() {
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
