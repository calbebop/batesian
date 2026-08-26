package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// VulnerableVersionExecutor reads the server identity a target publishes and
// matches it against documented advisories for MCP components with known
// vulnerabilities (rule mcp-vulnerable-version-001).
//
// Every Tier-1 SDK and most product servers state who they are in the
// handshake: result.serverInfo{name,version} on the legacy wire, the same
// block under result._meta on 2026-07-28's server/discover. That is exactly
// what an attacker needs to pick the right exploit, so it is also what a
// scanner should check: a self-declared version inside a known-vulnerable
// range is a lead no operator should have to find by hand.
//
// Everything here is an indicator. The version string is self-reported -
// trivially spoofed, sometimes wrong in real deployments - and matching a
// range is not proof that the vulnerable code path is reachable. Each finding
// names the advisory so an operator can verify against the actual patch.
//
// The advisory table is deliberately short: only products whose patched
// version is published and unambiguous get an entry. A table nobody maintains
// rots into false confidence; additions follow the same review bar as rules.
type VulnerableVersionExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-vulnerable-version", func(rc attack.RuleContext) attack.Executor { return NewVulnerableVersionExecutor(rc) })
}

func NewVulnerableVersionExecutor(r attack.RuleContext) *VulnerableVersionExecutor {
	return &VulnerableVersionExecutor{rule: r}
}

// vvAdvisory maps a component identity to a published vulnerability.
type vvAdvisory struct {
	// key matches case-insensitively as a substring of serverInfo.name.
	key string
	// affected is "<X.Y.Z", "<=X.Y.Z" or "=X.Y.Z".
	affected string
	// severity for this finding (never above the rule YAML declares).
	severity string
	title    string
	refs     string
}

// vvTable entries carry their own citations; keep them in step with upstream
// advisories when bumping.
var vvTable = []vvAdvisory{
	{
		key: "mcp-server-git", affected: "<2025.12.18", severity: "high",
		title: "mcp-server-git argument injection and path escape chain",
		refs:  "CVE-2025-68143, CVE-2025-68144, CVE-2025-68145",
	},
	{
		key: "mcp-remote", affected: "<0.1.16", severity: "high",
		title: "mcp-remote OAuth flow command injection",
		refs:  "CVE-2025-6514",
	},
	{
		key: "mcp-atlassian", affected: "<0.17.0", severity: "high",
		title: "mcp-atlassian attachment path traversal to RCE",
		refs:  "CVE-2026-27825, CVE-2026-27826",
	},
	{
		key: "mcp-atlassian", affected: "<0.22.0", severity: "medium",
		title: "mcp-atlassian SSRF DNS-rebinding TOCTOU bypass of the 27826 fix",
		refs:  "GHSA-489g-7rxv-6c8q",
	},
	{
		key: "inspector", affected: "<0.14.1", severity: "high",
		title: "MCP Inspector unauthenticated RCE via DNS rebinding",
		refs:  "CVE-2025-49596",
	},
	{
		key: "serena", affected: "<1.5.2", severity: "high",
		title: "Serena dashboard memory poisoning to RCE via DNS rebinding",
		refs:  "CVE-2026-49471",
	},
	{
		key: "mcpjam", affected: "<=1.4.2", severity: "high",
		title: "MCPJam inspector exposed control endpoint RCE",
		refs:  "CVE-2026-23744",
	},
}

func (e *VulnerableVersionExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		name, version, ok := vvExtractServerInfo(session.RawInit)
		if !ok {
			return nil, false // identity unreadable: nothing assessed on this wire
		}
		return e.matchAdvisories(session.Endpoint, name, version), true
	})
}

// vvExtractServerInfo pulls {name, version} from wherever the wire puts it:
// legacy initialize results carry result.serverInfo; the modern discover
// result carries the same block under result._meta. Both paths are tried on
// any body, since the shapes are unambiguous.
func vvExtractServerInfo(raw []byte) (name, version string, ok bool) {
	var legacy struct {
		Result struct {
			ServerInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &legacy) == nil && legacy.Result.ServerInfo.Name != "" {
		return legacy.Result.ServerInfo.Name, legacy.Result.ServerInfo.Version, true
	}
	var modern struct {
		Result struct {
			Meta map[string]struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"_meta"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &modern) == nil {
		if si, present := modern.Result.Meta[metaServerInfoKey]; present && si.Name != "" {
			return si.Name, si.Version, true
		}
	}
	return "", "", false
}

// metaServerInfoKey is the _meta key carrying server identity on the modern
// wire.
const metaServerInfoKey = "io.modelcontextprotocol/serverInfo"

// matchAdvisories compares one identity against the table. Findings are per
// advisory; a product matching several entries yields several findings, which
// is the honest shape when the ranges differ.
func (e *VulnerableVersionExecutor) matchAdvisories(endpoint, name, version string) []attack.Finding {
	lower := strings.ToLower(name)
	parsed := vvParseVersion(version)

	var findings []attack.Finding
	for _, adv := range vvTable {
		if !strings.Contains(lower, adv.key) {
			continue
		}
		op, bound, ok := vvParseRange(adv.affected)
		if !ok || parsed == nil {
			findings = append(findings, e.unverifiableFinding(endpoint, name, version, adv))
			continue
		}
		cmp := vvCompare(parsed, bound)
		inRange := false
		switch op {
		case "<":
			inRange = cmp < 0
		case "<=":
			inRange = cmp <= 0
		case "=":
			inRange = cmp == 0
		}
		if !inRange {
			continue
		}
		findings = append(findings, e.finding(endpoint, name, version, adv))
	}
	return findings
}

func (e *VulnerableVersionExecutor) finding(endpoint, name, version string, adv vvAdvisory) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   adv.severity,
		Confidence: attack.RiskIndicator,
		Title:      fmt.Sprintf("MCP server identifies as %q %s (%s)", name, version, adv.title),
		Description: fmt.Sprintf(
			"The handshake at %s identifies this server as %q running version %s, which falls inside "+
				"the affected range %s for %s (%s). The version is self-reported and spoofable, and the "+
				"match does not prove the vulnerable code path is reachable from this surface - verify "+
				"against the advisory before acting.",
			endpoint, name, version, adv.affected, adv.key, adv.refs),
		Evidence: fmt.Sprintf("endpoint: %s\nserverInfo.name: %s\nserverInfo.version: %s\nmatched: %s %s\nadvisories: %s",
			endpoint, name, version, adv.key, adv.affected, adv.refs),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

// unverifiableFinding covers the awkward middle: the name says this is a
// product with a published advisory but the version string cannot be parsed,
// so neither clean nor vulnerable can be claimed.
func (e *VulnerableVersionExecutor) unverifiableFinding(endpoint, name, version string, adv vvAdvisory) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "low",
		Confidence: attack.RiskIndicator,
		Title:      fmt.Sprintf("MCP server identifies as %q but its version is unverifiable", name),
		Description: fmt.Sprintf(
			"The handshake at %s identifies this server as %q reporting version %q, which is not a "+
				"parseable version for range comparison against %s (%s). Whether this deployment is "+
				"affected could not be determined from what the server publishes.",
			endpoint, name, version, adv.key, adv.refs),
		Evidence: fmt.Sprintf("endpoint: %s\nserverInfo.name: %s\nserverInfo.version: %s\nrelated advisories: %s",
			endpoint, name, version, adv.refs),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

// vvParseVersion extracts the leading dotted-numeric core of a version
// string: "v0.14.1-beta2" -> [0,14,1], "2025.12.18" -> [2025,12,18]. nil when
// no numeric core exists.
func vvParseVersion(s string) []int {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "v")
	end := 0
	for end < len(s) {
		c := s[end]
		if (c >= '0' && c <= '9') || c == '.' {
			end++
			continue
		}
		break
	}
	core := s[:end]
	if core == "" || strings.HasPrefix(core, ".") || strings.HasSuffix(core, ".") || strings.Contains(core, "..") {
		return nil
	}
	parts := strings.Split(core, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// vvParseRange splits an operator like "<" into op and bound segments.
func vvParseRange(r string) (op string, bound []int, ok bool) {
	switch {
	case strings.HasPrefix(r, "<="):
		op = "<="
	case strings.HasPrefix(r, "<"):
		op = "<"
	case strings.HasPrefix(r, ">="):
		op = ">="
	case strings.HasPrefix(r, ">"):
		op = ">"
	case strings.HasPrefix(r, "="):
		op = "="
	default:
		return "", nil, false
	}
	bound = vvParseVersion(r[len(op):])
	return op, bound, bound != nil
}

// vvCompare compares two dotted-numeric versions segment by segment; missing
// segments read as zero, so 1.0 == 1.0.0.
func vvCompare(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
