package mcp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ShadowSurfaceExecutor looks for MCP surfaces the target host serves on
// ports adjacent to the one it was given (rule mcp-shadow-surface-001).
//
// The class: developer dashboards and inspector proxies bind to loopback or
// every interface with no authentication, on ports nobody associates with the
// production service. An MCP server answering there is reachable by anything
// on the machine and, when Origin validation is also absent, by any web page
// in a browser via DNS rebinding - which is exactly the chain behind
// CVE-2025-49596 (MCP Inspector), CVE-2026-49471 (Serena) and
// CVE-2026-23744 (MCPJam). Operators rarely know these listeners exist, so
// scanning only the URL they named misses them entirely.
//
// The port list is deliberately short and documented rather than a sweep:
// each entry is a default binding of a product with a published unauth-RCE
// advisory against it. Probing closed ports costs one refused connection.
//
//   - 6277  - MCP Inspector's proxy server default
//   - 24282 - Serena's dashboard/API default
//   - 3000  - the conventional dev-server port
//
// Oracles, all read-only:
//
//   - an initialize answered without credentials is an open shadow surface;
//     repeating that exact request with a foreign Origin distinguishes the
//     full browser-reachable chain (both accepted, high) from an open surface
//     behind Origin validation (medium)
//   - a dashboard fingerprint ("MCP Inspector", "Serena") without a drivable
//     protocol endpoint is a low indicator naming the exposed product page
type ShadowSurfaceExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-shadow-surface", func(rc attack.RuleContext) attack.Executor { return NewShadowSurfaceExecutor(rc) })
}

func NewShadowSurfaceExecutor(r attack.RuleContext) *ShadowSurfaceExecutor {
	return &ShadowSurfaceExecutor{rule: r}
}

// shadowPorts are the candidate ports probed on the target's host. Package
// level so the harness can point it at ephemeral listeners; callers must not
// mutate it outside tests.
var shadowPorts = []int{6277, 24282, 3000}

// shadowFingerprints are substrings treated as naming a known-vulnerable
// dashboard product when its protocol endpoint cannot be driven directly.
var shadowFingerprints = []string{"MCP Inspector", "Serena"}

// shadowPaths are the candidate paths per port. Two, not four: the walk here
// asks whether this listener speaks MCP at all, and a listener that answers
// neither spelling is reported as closed to the protocol.
var shadowPaths = []string{"/mcp", "/"}

func (e *ShadowSurfaceExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	u, err := url.Parse(vars.BaseURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: could not parse a host out of %s",
			attack.ErrInconclusive, vars.BaseURL)
	}
	scheme := "http"
	if u.Scheme == "https" {
		scheme = "https"
	}
	targetPort := u.Port()

	var findings []attack.Finding
	for _, port := range shadowPorts {
		if strconv.Itoa(port) == targetPort {
			continue // the surface the operator already aimed at; other rules own it
		}
		if f := e.probePort(ctx, client, scheme, u.Hostname(), port); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

// probePort characterises one listener. A nil return covers everything from
// "connection refused" to "an unrelated service answered": none of those is a
// shadow MCP surface, and a refused connection is itself an answer - silence
// here means checked-and-absent, never could-not-tell.
func (e *ShadowSurfaceExecutor) probePort(ctx context.Context, client *attack.HTTPClient, scheme, host string, port int) *attack.Finding {
	base := scheme + "://" + host + ":" + strconv.Itoa(port)

	marker := e.fingerprint(ctx, client, base)

	mcpPath := ""
	for _, path := range shadowPaths {
		resp, err := client.POST(ctx, base+path, nil, legacyHandshakeBody())
		if err != nil || !resp.IsSuccess() || !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			continue
		}
		mcpPath = path
		break
	}

	if mcpPath == "" {
		if marker == "" {
			return nil
		}
		// A known dashboard is served but its protocol endpoint did not answer
		// the probes. Exposed product page, undriven protocol: low indicator.
		return &attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "low",
			Confidence: attack.RiskIndicator,
			Title:      fmt.Sprintf("Known MCP dashboard served without credentials on %s:%d (%s)", host, port, marker),
			Description: fmt.Sprintf(
				"GET %s/ returned a page identifying as %q, but no MCP endpoint answered on the "+
					"probed paths. The dashboard for this product is exposed to your scan position; "+
					"whether its control endpoints are reachable depends on paths and methods this "+
					"rule does not drive. Inspector-class dashboards have shipped with unauthenticated "+
					"RCE when exposed like this (CVE-2025-49596), so confirm what else the process serves.",
				base, marker),
			Evidence:    fmt.Sprintf("GET %s/ -> HTTP 200, body names %q\nno MCP handshake on %s", base, marker, strings.Join(shadowPaths, ", ")),
			Remediation: e.rule.Remediation,
			TargetURL:   base + "/",
		}
	}

	endpoint := base + mcpPath

	// Foreign-Origin twin of the request that just succeeded: identical bytes,
	// one header different. Accepting it is the browser-reachability half of
	// the rebinding chain.
	rebindResp, rebindErr := client.POST(ctx, endpoint, map[string]string{"Origin": foreignOrigin}, legacyHandshakeBody())
	originOpen := rebindErr == nil && rebindResp.IsSuccess() &&
		rebindResp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`)

	sev, title := "medium", fmt.Sprintf("MCP surface answers without authentication on %s:%d%s", host, port, mcpPath)
	if originOpen {
		sev = "high"
		title = fmt.Sprintf("Unauthenticated MCP surface accepts foreign Origins on %s:%d%s (DNS-rebinding chain)", host, port, mcpPath)
	}
	return &attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   sev,
		Confidence: attack.ConfirmedExploit,
		Title:      title,
		Description: fmt.Sprintf(
			"The host behind %s also answers an MCP initialize at %s with no credentials. This "+
				"listener sits on a non-standard port, away from the service the operator named, which "+
				"is where inspector and dashboard processes end up after setup.", scheme+"://"+host, endpoint) +
			func() string {
				if originOpen {
					return " The same handshake was accepted carrying a foreign Origin, so a page on " +
						"another origin can reach this surface from a victim's browser - the full " +
						"precondition pair behind CVE-2025-49596. Anything the process can do, the " +
						"page can drive."
				}
				return " A foreign-Origin twin of the same handshake was refused, so direct cross-origin " +
					"reaching is mitigated here; the surface is still unauthenticated for anything on " +
					"the machine or network path."
			}(),
		Evidence: func() string {
			lines := fmt.Sprintf("endpoint: %s\ninitialize without credentials: accepted\nforeign Origin twin (%s): ",
				endpoint, foreignOrigin)
			if originOpen {
				lines += "accepted"
			} else {
				lines += "refused"
			}
			if marker != "" {
				lines += "\npage fingerprint: " + marker
			}
			return lines
		}(),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

// fingerprint GETs the listener root and returns the first known product name
// its body admits, or empty. It is a hint used for evidence and the low
// finding, never load-bearing on its own.
func (e *ShadowSurfaceExecutor) fingerprint(ctx context.Context, client *attack.HTTPClient, base string) string {
	resp, err := client.GET(ctx, base+"/", nil)
	if err != nil || !resp.IsSuccess() {
		return ""
	}
	body := strings.ToLower(string(resp.Body))
	for _, fp := range shadowFingerprints {
		if strings.Contains(body, strings.ToLower(fp)) {
			return fp
		}
	}
	return ""
}
