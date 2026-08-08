package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ConfusedDeputyExecutor tests whether an MCP server's OAuth authorization
// endpoint enforces exact redirect_uri validation (rule mcp-confused-deputy-001).
//
// The MCP "confused deputy" problem: a server that proxies OAuth to a third-party
// authorization server with a static client_id, while forwarding a client-supplied
// redirect_uri, lets an attacker harvest authorization codes once the upstream
// consent screen is skipped (a consent cookie set for the static client_id). The
// MCP Security Best Practices require the proxy to validate that redirect_uri
// "exactly matches the registered URI" using exact string matching, and RFC 6749
// section 4.1.2.1 requires the authorization server to NOT redirect to a missing,
// invalid, or mismatching redirect_uri.
//
// Black-box detection (no browser, user, or consent cookie):
//   - Register a client via DCR with an off-origin redirect R1.
//   - Request /authorize with a DIFFERENT, unregistered off-origin redirect R2.
//   - CONFIRMED: the server answers with a 3xx whose Location host is R2's host;
//     it is redirecting to a redirect_uri that was never registered for the
//     client (a direct RFC 6749 4.1.2.1 violation, the open-redirect primitive
//     that enables the confused deputy).
//   - INDICATOR: DCR accepted the arbitrary off-origin redirect R1 (the confused
//     deputy precondition) but the authorize-time check could not be confirmed
//     (e.g. the endpoint deferred validation behind a login page).
//
// Redirect targets use the reserved .invalid TLD (RFC 6761) with a per-run
// marker, so they never resolve and the flow is never completed: the probe only
// reads the server's redirect decision, it does not harvest any code.
type ConfusedDeputyExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-confused-deputy", func(rc attack.RuleContext) attack.Executor {
		return NewConfusedDeputyExecutor(rc)
	})
}

func NewConfusedDeputyExecutor(r attack.RuleContext) *ConfusedDeputyExecutor {
	return &ConfusedDeputyExecutor{rule: r}
}

func (e *ConfusedDeputyExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	regEP, authEP := discoverOAuthEndpoints(ctx, client, vars.BaseURL)
	if authEP == "" || regEP == "" {
		// No authorization endpoint, or no DCR endpoint to obtain a client_id.
		// CIMD-only (2025-11-25) and non-OAuth servers land here: not applicable,
		// but only when something actually answered.
		return nil, oauthNotApplicable(ctx, client, vars.BaseURL)
	}

	// Register a client with an off-origin redirect. We use a domain unrelated to
	// the target's own origin so a server with a redirect allowlist rejects it.
	registeredRedirect := fmt.Sprintf("https://batesian-%s-registered.invalid/cb", vars.RandID)
	clientName := "batesian-cd-" + vars.RandID
	clientID, dcrEchoedRedirect, dcrResult, regResp := registerDCRClient(ctx, unauthClient, regEP, registeredRedirect, vars.RandID)

	// Remove the client this probe created, whatever the outcome below. The deferred
	// call is the guarantee; cleanup runs before the findings are built so its result
	// can be reported in their evidence, and the flag keeps the two from duplicating.
	var cleanup dcrCleanup
	cleanedUp := false
	removeClient := func() {
		if cleanedUp || clientID == "" {
			return
		}
		cleanup = deregisterDCRClient(ctx, unauthClient, regEP, clientName, regResp)
		cleanedUp = true
	}
	defer removeClient()

	if clientID == "" {
		if dcrResult.redirectRefused {
			// The allowlist refused our off-origin redirect. That is the mitigation
			// this rule exists to look for, so a clean result is honest.
			return nil, nil
		}
		// Registration could not be completed for an unrelated reason, so
		// /authorize was never probed and its redirect validation is unknown.
		return nil, fmt.Errorf("%w: dynamic client registration at %s issued no client_id (%s), "+
			"so the authorize endpoint's redirect_uri validation was never probed",
			attack.ErrInconclusive, regEP, dcrResult.detail)
	}

	// Authorize with a DIFFERENT, unregistered off-origin redirect.
	attackerHost := fmt.Sprintf("batesian-%s-attacker.invalid", vars.RandID)
	attackerRedirect := "https://" + attackerHost + "/cb"
	loc, status := authorizeRedirectProbe(ctx, opts, authEP, clientID, attackerRedirect, vars.RandID)

	// The client_id has served its purpose, so remove the registration before
	// reporting, which is what lets the report say whether anything was left behind.
	removeClient()

	if redirectsToHost(status, loc, attackerHost) {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   e.rule.Severity,
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP OAuth authorization endpoint redirects to an unregistered redirect_uri (confused deputy)",
			Description: "The authorization endpoint issued a redirect to a redirect_uri that was never " +
				"registered for the client. RFC 6749 section 4.1.2.1 requires the server to reject a missing, " +
				"invalid, or mismatching redirect_uri and to NOT redirect to it, and the MCP Security Best " +
				"Practices require exact-match validation. Because the endpoint forwards the user agent to an " +
				"attacker-supplied URI, an attacker can harvest authorization codes; combined with a static " +
				"proxy client_id and a skipped upstream consent screen this is the confused deputy account-" +
				"takeover primitive.",
			Evidence: fmt.Sprintf(
				"authorization_endpoint: %s\nregistered redirect_uri: %s\nunregistered redirect_uri sent: %s\n"+
					"server response: HTTP %d, Location: %s\n%s",
				authEP, registeredRedirect, attackerRedirect, status, loc, cleanup.evidenceLine()),
			Remediation: e.rule.Remediation,
			TargetURL:   authEP,
		}}, nil
	}

	if dcrEchoedRedirect {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "MCP OAuth DCR accepts an arbitrary off-origin redirect_uri (confused deputy precondition)",
			Description: "Dynamic client registration accepted a client whose redirect_uri is an arbitrary " +
				"off-origin host unrelated to the server. This is the precondition for the confused deputy " +
				"attack: an attacker can register their own redirect target. The authorization endpoint did " +
				"not redirect to an unregistered URI in this probe, so exact-match enforcement was not " +
				"disproven. Manually verify that the proxy stores per-client consent and does not skip the " +
				"upstream consent screen for the static client_id.",
			Evidence: fmt.Sprintf(
				"registration_endpoint: %s\naccepted off-origin redirect_uri: %s\nauthorize probe: HTTP %d, "+
					"Location: %s\n%s",
				regEP, registeredRedirect, status, loc, cleanup.evidenceLine()),
			Remediation: e.rule.Remediation,
			TargetURL:   regEP,
		}}, nil
	}

	return nil, nil
}

// discoverOAuthEndpoints reads the authorization-server metadata and returns the
// registration_endpoint and authorization_endpoint. It tries the RFC 8414
// authorization-server document first, then the OIDC openid-configuration.
func discoverOAuthEndpoints(ctx context.Context, client *attack.HTTPClient, baseURL string) (registrationEndpoint, authorizationEndpoint string) {
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		resp, err := client.GET(ctx, baseURL+p, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		reg := resp.JSONField("registration_endpoint")
		authz := resp.JSONField("authorization_endpoint")
		if authz != "" {
			return reg, authz
		}
	}
	return "", ""
}

// registerDCRClient registers a client via DCR with the given redirect_uri and
// returns the issued client_id, whether the response echoed the off-origin
// redirect back (i.e. DCR accepted an arbitrary external redirect target), and
// how the registration itself went.
//
// The outcome matters because a refused registration has two very different
// meanings. A server that refuses to register an off-origin redirect_uri has
// applied the very mitigation this rule is about: the confused-deputy chain needs
// an attacker-controlled redirect registered, and the allowlist stopped it at step
// one, so a clean result is honest. A server whose DCR requires an initial access
// token (RFC 7591 section 3) and answers 401, or which fails for any unrelated
// reason, has told us nothing about redirect validation, and reporting that clean
// grades an endpoint the rule never reached.
//
// The registration response is returned as well, so the caller can deregister the
// client it just created once the client_id has served its purpose. See
// deregisterDCRClient: a scan that registers a client with an attacker-shaped
// redirect_uri and leaves it there has changed the target and not changed it back.
func registerDCRClient(ctx context.Context, client *attack.HTTPClient, registrationEndpoint, redirectURI,
	randID string) (clientID string, echoedRedirect bool, outcome dcrOutcome, reg *attack.Response) {
	resp, err := client.POST(ctx, registrationEndpoint, nil, map[string]interface{}{
		"client_name":    "batesian-cd-" + randID,
		"redirect_uris":  []string{redirectURI},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
	})
	if err != nil {
		return "", false, dcrOutcome{unavailable: true, detail: "the registration request failed: " + err.Error()}, nil
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		clientID = resp.JSONField("client_id")
		if clientID == "" {
			return "", false, dcrOutcome{unavailable: true,
				detail: fmt.Sprintf("registration returned HTTP %d with no client_id", resp.StatusCode)}, resp
		}
		echoedRedirect = strings.Contains(resp.BodyString(), redirectURI)
		return clientID, echoedRedirect, dcrOutcome{}, resp
	case http.StatusUnauthorized, http.StatusForbidden:
		// DCR itself is credential-gated. Nothing about redirect policy follows.
		return "", false, dcrOutcome{unavailable: true,
			detail: fmt.Sprintf("registration requires credentials (HTTP %d)", resp.StatusCode)}, resp
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		// A client-error rejection of the registration we sent. This is the
		// allowlist doing its job, which is the mitigation, not an untested surface.
		return "", false, dcrOutcome{redirectRefused: true}, resp
	default:
		return "", false, dcrOutcome{unavailable: true,
			detail: fmt.Sprintf("registration answered HTTP %d", resp.StatusCode)}, resp
	}
}

// dcrOutcome records why a registration produced no client_id.
type dcrOutcome struct {
	// redirectRefused: the server rejected the registration we sent, which for an
	// off-origin redirect_uri is the mitigation this rule looks for.
	redirectRefused bool
	// unavailable: registration could not be completed for reasons unrelated to
	// redirect policy, so the authorize endpoint was never probed.
	unavailable bool
	detail      string
}

// authorizeRedirectProbe issues a single authorization request with the given
// (unregistered) redirect_uri and returns the response's Location header and
// status code WITHOUT following the redirect, so the server's redirect decision
// can be inspected directly.
func authorizeRedirectProbe(ctx context.Context, opts attack.Options, authorizationEndpoint, clientID, redirectURI, randID string) (location string, status int) {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", "batesian-"+randID)
	q.Set("scope", "openid")
	// OAuth 2.1 requires PKCE; include a well-formed S256 challenge (43-char
	// base64url, RFC 7636) so the request is not rejected for malformed PKCE
	// before redirect_uri is evaluated.
	q.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(authorizationEndpoint, "?") {
		sep = "&"
	}
	reqURL := authorizationEndpoint + sep + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", "batesian/"+attack.Version+" (https://github.com/calbebop/batesian)")

	hc := &http.Client{
		Transport: attack.Transport(opts),
		// Do not follow redirects: we need the first response's Location header.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	return resp.Header.Get("Location"), resp.StatusCode
}

// redirectsToHost reports whether a 3xx response carries a Location header whose
// host equals wantHost. Comparing the host (not the body) avoids the common false
// positive where a rejection page merely displays the rejected URI as text.
func redirectsToHost(status int, location, wantHost string) bool {
	if status < 300 || status >= 400 || location == "" {
		return false
	}
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), wantHost)
}
