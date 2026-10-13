package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"

	"github.com/calbebop/batesian/internal/attack"
)

// ShadowSurfaceExecutor checks adjacent ports for unauthenticated MCP listeners
// and known dashboard fingerprints (rule mcp-shadow-surface-001).
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
	var incomplete []string
	for _, port := range shadowPorts {
		if strconv.Itoa(port) == targetPort {
			continue // the surface the operator already aimed at; other rules own it
		}
		f, uncertain := e.probePort(ctx, client, scheme, u.Hostname(), port)
		if f != nil {
			findings = append(findings, *f)
		}
		if uncertain {
			incomplete = append(incomplete, strconv.Itoa(port))
		}
	}
	if len(incomplete) > 0 {
		ports := strings.Join(incomplete, ", ")
		return findings, fmt.Errorf("%w: shadow-surface probes did not complete on port(s) %s",
			attack.ErrInconclusive, ports)
	}
	return findings, nil
}

// probePort distinguishes a closed or unrelated listener from an incomplete probe.
func (e *ShadowSurfaceExecutor) probePort(ctx context.Context, client *attack.HTTPClient, scheme, host string, port int) (*attack.Finding, bool) {
	base := scheme + "://" + host + ":" + strconv.Itoa(port)

	marker, incomplete := e.fingerprint(ctx, client, base)

	mcpPath := ""
	for _, path := range shadowPaths {
		resp, err := client.POST(ctx, base+path, nil, legacyHandshakeBody())
		if shadowProbeIncomplete(resp, err) {
			incomplete = true
			continue
		}
		if err != nil || !resp.IsSuccess() || !initializeSucceeded(resp.Body) {
			continue
		}
		mcpPath = path
		break
	}

	if mcpPath == "" {
		if marker == "" {
			return nil, incomplete
		}
		probeEvidence := "no MCP handshake on " + strings.Join(shadowPaths, ", ")
		if incomplete {
			probeEvidence = "MCP handshake probes incomplete on " + strings.Join(shadowPaths, ", ")
		}
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
			Evidence:    fmt.Sprintf("GET %s/ -> HTTP 200, body names %q\n%s", base, marker, probeEvidence),
			Remediation: e.rule.Remediation,
			TargetURL:   base + "/",
		}, false
	}

	endpoint := base + mcpPath

	// Foreign-Origin twin of the request that just succeeded: identical bytes,
	// one header different. Accepting it is the browser-reachability half of
	// the rebinding chain.
	rebindResp, rebindErr := client.POST(ctx, endpoint, map[string]string{"Origin": foreignOrigin}, legacyHandshakeBody())
	originOpen := rebindErr == nil && rebindResp != nil && rebindResp.IsSuccess() && initializeSucceeded(rebindResp.Body)
	originRefused := rebindErr == nil && rebindResp != nil && rebindResp.StatusCode == http.StatusForbidden
	originEvidence := "inconclusive (transport failure)"
	originDescription := "The foreign-Origin comparison did not yield a verdict, so browser reachability was not assessed."
	if rebindResp != nil {
		originEvidence = fmt.Sprintf("inconclusive (HTTP %d)", rebindResp.StatusCode)
	}
	if originOpen {
		originEvidence = "accepted"
		originDescription = "A matching handshake with a foreign Origin also succeeded."
	} else if originRefused {
		originEvidence = "refused (HTTP 403)"
		originDescription = "A matching handshake with a foreign Origin was refused with HTTP 403."
	}

	sev, title := "medium", fmt.Sprintf("MCP surface answers without authentication on %s:%d%s", host, port, mcpPath)
	if originOpen {
		sev = "high"
		title = fmt.Sprintf("Unauthenticated MCP surface accepts foreign Origins on %s:%d%s (DNS-rebinding chain)", host, port, mcpPath)
	}
	evidence := fmt.Sprintf("endpoint: %s\ninitialize without credentials: accepted\nforeign Origin twin (%s): %s",
		endpoint, foreignOrigin, originEvidence)
	if marker != "" {
		evidence += "\npage fingerprint: " + marker
	}
	return &attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   sev,
		Confidence: attack.ConfirmedExploit,
		Title:      title,
		Description: fmt.Sprintf("An MCP initialize succeeded without credentials at %s on an adjacent port. %s",
			endpoint, originDescription),
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}, false
}

func shadowProbeIncomplete(resp *attack.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, syscall.ECONNREFUSED)
	}
	if resp == nil {
		return true
	}
	return resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= http.StatusInternalServerError
}

// fingerprint checks the page for a known dashboard name.
func (e *ShadowSurfaceExecutor) fingerprint(ctx context.Context, client *attack.HTTPClient, base string) (string, bool) {
	resp, err := client.GET(ctx, base+"/", nil)
	if err != nil || resp == nil || !resp.IsSuccess() {
		return "", shadowProbeIncomplete(resp, err)
	}
	body := strings.ToLower(string(resp.Body))
	for _, fp := range shadowFingerprints {
		if strings.Contains(body, strings.ToLower(fp)) {
			return fp, false
		}
	}
	return "", false
}
