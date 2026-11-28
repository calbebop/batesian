package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

const fetchRobotsTool = "fetch"

type FetchRobotsExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-fetch-robots", func(rc attack.RuleContext) attack.Executor {
		return &FetchRobotsExecutor{rule: rc}
	})
}

func NewFetchRobotsExecutor(rc attack.RuleContext) *FetchRobotsExecutor {
	return &FetchRobotsExecutor{rule: rc}
}

func (e *FetchRobotsExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	probe := opts.MCPFetchRobotsProbe
	if !attack.ValidMCPFetchRobotsProbe(probe) {
		return nil, fmt.Errorf("%w: configure mcp_fetch_robots_probe with an owned canary origin", attack.ErrInconclusive)
	}
	if !approvedToolName(fetchRobotsTool, opts.MCPInvokeTools) {
		return nil, fmt.Errorf("%w: approve fetch with --mcp-invoke-tool", attack.ErrInconclusive)
	}
	if reason := checkFetchRobotsCanary(ctx, opts, probe); reason != "" {
		return nil, fmt.Errorf("%w: fetch robots canary: %s", attack.ErrInconclusive, reason)
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
		return findings, fmt.Errorf("%w: fetch robots probe incomplete: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return findings, err
}

func checkFetchRobotsCanary(ctx context.Context, opts attack.Options, probe *attack.MCPFetchRobotsProbe) string {
	client, reason := checkFetchRobotsPolicy(ctx, opts, probe.Origin, probe.PrivatePath)
	if reason != "" {
		return reason
	}
	paths := []string{probe.PrivatePath}
	for _, alternate := range attack.FetchRobotsAlternates(probe) {
		paths = append(paths, alternate.Path)
	}
	for _, path := range paths {
		resp, err := client.GET(ctx, probe.Origin+path, nil)
		if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) > 4096 ||
			strings.TrimSpace(string(resp.Body)) != probe.PrivateMarker {
			return "canonical and selected alternate canary paths must serve the exact marker"
		}
	}
	return ""
}

func checkFetchRobotsPolicy(ctx context.Context, opts attack.Options, origin, privatePath string) (*attack.HTTPClient, string) {
	client := attack.NewUnauthHTTPClient(opts, attack.NewVars(origin, ""))
	robots, err := client.GET(ctx, origin+"/robots.txt", nil)
	if err != nil || robots == nil || robots.StatusCode != 200 || len(robots.Body) > 4096 {
		return nil, "robots.txt could not be verified"
	}
	policy := strings.ReplaceAll(string(robots.Body), "\r\n", "\n")
	if strings.TrimSpace(policy) != "User-agent: *\nDisallow: "+privatePath {
		return nil, "robots.txt must contain only the wildcard user-agent and exact canary disallow"
	}
	return client, ""
}

func (e *FetchRobotsExecutor) probeSession(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, probe *attack.MCPFetchRobotsProbe) ([]attack.Finding, bool, string) {
	candidate, reason := fetchRobotsCandidate(ctx, client, session)
	if reason != "" {
		return nil, false, reason
	}
	canonical := probe.Origin + probe.PrivatePath
	control, reason, _, toolError := callPathTool(ctx, client, session, 20, candidate, canonical)
	if reason != "" || !toolError || !robotsDenied(control) || strings.Contains(control, probe.PrivateMarker) {
		return nil, false, "canonical path was not explicitly denied by robots policy"
	}
	var matched, incomplete []string
	for i, alternate := range attack.FetchRobotsAlternates(probe) {
		result, reason, _, alternateError := callPathTool(ctx, client, session, 21+i, candidate, probe.Origin+alternate.Path)
		switch {
		case reason != "":
			incomplete = append(incomplete, alternate.Variant)
		case !alternateError && strings.Contains(result, probe.PrivateMarker):
			matched = append(matched, alternate.Variant)
		case alternateError && robotsDenied(result) && !strings.Contains(result, probe.PrivateMarker):
		default:
			incomplete = append(incomplete, alternate.Variant)
		}
	}
	var findings []attack.Finding
	if len(matched) != 0 {
		findings = []attack.Finding{e.finding(session.Endpoint, matched)}
	}
	if len(incomplete) != 0 {
		return findings, false, "alternate path responses were inconclusive: " + strings.Join(incomplete, ", ")
	}
	return findings, true, ""
}

func fetchRobotsCandidate(ctx context.Context, client *attack.HTTPClient, session mcpSession) (traversalCandidate, string) {
	if !session.ServerSupports("tools") {
		return traversalCandidate{}, "tools are not advertised"
	}
	listed, ok := listToolPages(ctx, client, session, 3)
	if !ok {
		return traversalCandidate{}, "tool listing was unavailable or incomplete"
	}
	var selected *traversalTool
	for _, raw := range listed {
		var tool traversalTool
		if json.Unmarshal(raw, &tool) != nil || tool.Name == "" {
			return traversalCandidate{}, "tool listing was malformed"
		}
		if tool.Name == fetchRobotsTool {
			if selected != nil {
				return traversalCandidate{}, "fetch appeared more than once"
			}
			selected = &tool
		}
	}
	if selected == nil || selected.Annotations == nil ||
		!declaresReadOnlyTool(selected.Annotations.ReadOnlyHint, selected.Annotations.DestructiveHint) {
		return traversalCandidate{}, "fetch was absent or not declared read-only"
	}
	required := requiredParams(selected.InputSchema)
	props, _ := selected.InputSchema["properties"].(map[string]interface{})
	urlSpec, _ := props["url"].(map[string]interface{})
	if len(required) != 1 || !required["url"] || urlSpec["type"] != "string" {
		return traversalCandidate{}, "fetch did not have a URL-only required input"
	}
	if session.Era == EraModern {
		if _, err := toolParamHeaders(selected.InputSchema, nil); err != nil {
			return traversalCandidate{}, "fetch parameter headers were invalid"
		}
	}
	return traversalCandidate{tool: fetchRobotsTool, param: "url", schema: selected.InputSchema}, ""
}

func robotsDenied(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "robots.txt") &&
		(strings.Contains(lower, "not allowed") || strings.Contains(lower, "disallow") || strings.Contains(lower, "blocked"))
}

func (e *FetchRobotsExecutor) finding(endpoint string, variants []string) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "low", Confidence: attack.RiskIndicator,
		Title:       "MCP Fetch served a path its robots policy denied",
		Description: "The approved Fetch tool denied the canonical canary path under robots.txt but returned the same controlled content through an alternate spelling. This indicates a robots path comparison gap, not an authentication or private-network bypass.",
		Evidence:    "endpoint: " + endpoint + "\nowned canary origin: verified\ncanonical path: robots denial\nalternate variants: " + strings.Join(variants, ", ") + "\nalternate path: exact marker returned\norigin, paths, marker, and response text omitted",
		Remediation: e.rule.Remediation, TargetURL: endpoint,
	}
}
