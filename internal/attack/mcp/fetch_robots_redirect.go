package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

type FetchRobotsRedirectExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-fetch-robots-redirect", func(rc attack.RuleContext) attack.Executor {
		return &FetchRobotsRedirectExecutor{rule: rc}
	})
}

func NewFetchRobotsRedirectExecutor(rc attack.RuleContext) *FetchRobotsRedirectExecutor {
	return &FetchRobotsRedirectExecutor{rule: rc}
}

func (e *FetchRobotsRedirectExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	probe := opts.MCPFetchRobotsRedirectProbe
	if !attack.ValidMCPFetchRobotsRedirectProbe(probe) {
		return nil, fmt.Errorf("%w: configure mcp_fetch_robots_redirect_probe with an owned canary origin", attack.ErrInconclusive)
	}
	if !approvedToolName(fetchRobotsTool, opts.MCPInvokeTools) {
		return nil, fmt.Errorf("%w: approve fetch with --mcp-invoke-tool", attack.ErrInconclusive)
	}
	if reason := checkFetchRobotsRedirectCanary(ctx, opts, probe); reason != "" {
		return nil, fmt.Errorf("%w: fetch robots redirect canary: %s", attack.ErrInconclusive, reason)
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	var incomplete []string
	findings, err := runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		f, determined, reason := e.probeSession(ctx, client, session, probe)
		if reason != "" {
			incomplete = append(incomplete, session.Era.String()+": "+reason)
		}
		return f, determined
	})
	if len(incomplete) != 0 {
		return findings, fmt.Errorf("%w: fetch robots redirect probe incomplete: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return findings, err
}

func checkFetchRobotsRedirectCanary(ctx context.Context, opts attack.Options, probe *attack.MCPFetchRobotsRedirectProbe) string {
	client, reason := checkFetchRobotsPolicy(ctx, opts, probe.Origin, probe.PrivatePath)
	if reason != "" {
		return reason
	}
	private, err := client.GET(ctx, probe.Origin+probe.PrivatePath, nil)
	if err != nil || private == nil || private.StatusCode != 200 || len(private.Body) > 4096 ||
		strings.TrimSpace(string(private.Body)) != probe.PrivateMarker {
		return "private canary path must serve the exact marker"
	}
	redirect, err := client.GET(ctx, probe.Origin+probe.RedirectPath, nil)
	if err != nil || redirect == nil || redirect.StatusCode != 302 ||
		redirect.Headers.Get("Location") != probe.PrivatePath || len(redirect.Body) > 4096 ||
		strings.Contains(string(redirect.Body), probe.PrivateMarker) {
		return "allowed canary path must redirect to the private path without serving the marker"
	}
	return ""
}

func (e *FetchRobotsRedirectExecutor) probeSession(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, probe *attack.MCPFetchRobotsRedirectProbe) ([]attack.Finding, bool, string) {
	candidate, reason := fetchRobotsCandidate(ctx, client, session)
	if reason != "" {
		return nil, false, reason
	}
	canonical := probe.Origin + probe.PrivatePath
	control, reason, _, toolError := callPathTool(ctx, client, session, 20, candidate, canonical)
	if reason != "" || !toolError || !robotsDenied(control) || strings.Contains(control, probe.PrivateMarker) {
		return nil, false, "private path was not explicitly denied by robots policy"
	}
	result, reason, _, redirectError := callPathTool(ctx, client, session, 21, candidate, probe.Origin+probe.RedirectPath)
	if reason != "" {
		return nil, false, "redirect response was unavailable"
	}
	if !redirectError && strings.Contains(result, probe.PrivateMarker) {
		return []attack.Finding{e.finding(session.Endpoint)}, true, ""
	}
	if redirectError && robotsDenied(result) && strings.Contains(result, canonical) &&
		!strings.Contains(result, probe.PrivateMarker) {
		return nil, true, ""
	}
	return nil, false, "redirect response did not establish access or target-path robots denial"
}

func (e *FetchRobotsRedirectExecutor) finding(endpoint string) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "low", Confidence: attack.RiskIndicator,
		Title:       "MCP Fetch followed a redirect into a robots-disallowed path",
		Description: "The approved Fetch tool denied the canary path under robots.txt but returned its controlled content after a same-origin redirect. This indicates missing robots enforcement on the redirect hop, not an authentication or private-network bypass.",
		Evidence:    "endpoint: " + endpoint + "\nowned canary origin: verified\nprivate path: robots denial\nredirect target: exact marker returned\norigin, paths, marker, and response text omitted",
		Remediation: e.rule.Remediation, TargetURL: endpoint,
	}
}
