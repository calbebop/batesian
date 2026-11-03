package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// VulnerableVersionExecutor compares self-reported server versions with a
// closed advisory table. Matches are indicators, not proof of exploitability.
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
	// key matches serverInfo.name as a substring unless exact is set.
	key   string
	exact bool
	// affected joins version bounds with spaces.
	affected string
	// severity for this finding (never above the rule YAML declares).
	severity string
	title    string
	refs     string
	fixed    string
	pkg      string
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
		key: "mcp-git", exact: true, affected: ">=2026.10.10 <2026.10.28", severity: "medium",
		title: "reference git server repository confinement bypass",
		refs:  "GHSA-w766-5x43-whvw", fixed: "2026.10.28", pkg: "mcp-server-git",
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
	{
		key: "secure-filesystem-server", exact: true,
		affected: ">=1.0.0 <2.0.1", severity: "medium",
		title: "reference filesystem server path validation mismatch",
		refs:  "GHSA-7rgq-gccq-qphx", fixed: "2.0.1", pkg: "@modelcontextprotocol/server-filesystem",
	},
	{
		key: "secure-filesystem-server", exact: true,
		affected: ">=1.0.0 <2.0.1", severity: "low",
		title: "reference filesystem server symlink metadata disclosure",
		refs:  "GHSA-hhwq-wxfx-cj7g", fixed: "2.0.1", pkg: "@modelcontextprotocol/server-filesystem",
	},
	{
		key: "secure-filesystem-server", exact: true,
		affected: ">=1.0.0 <2.0.1", severity: "medium",
		title: "reference filesystem server case-variant symlink write escape",
		refs:  "GHSA-4gxg-m5jx-9j57", fixed: "2.0.1", pkg: "@modelcontextprotocol/server-filesystem",
	},
	{
		key: "secure-filesystem-server", exact: true,
		affected: ">=1.0.0 <2.0.1", severity: "low",
		title: "reference filesystem server parent-directory write race",
		refs:  "GHSA-53mr-w429-c597", fixed: "2.0.1", pkg: "@modelcontextprotocol/server-filesystem",
	},
	{
		key: "mcp-fetch", exact: true,
		affected: ">=2026.10.10 <=2026.10.19", severity: "medium",
		title: "reference fetch server IDNA private-address guard bypass",
		refs:  "GHSA-v38p-wf49-hx2j", fixed: "2026.10.24", pkg: "mcp-server-fetch",
	},
	{
		key: "mcp-fetch", exact: true,
		affected: ">=2026.10.10 <=2026.10.19", severity: "low",
		title: "reference fetch server robots.txt redirect bypass",
		refs:  "GHSA-3jqg-r5pp-rmp2", fixed: "2026.10.24", pkg: "mcp-server-fetch",
	},
	{
		key: "mcp-fetch", exact: true,
		affected: ">=2026.10.10 <=2026.10.19", severity: "low",
		title: "reference fetch server NAT64 private-address guard bypass",
		refs:  "GHSA-66qx-2266-pmj6", fixed: "2026.10.24", pkg: "mcp-server-fetch",
	},
}

func (e *VulnerableVersionExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Inventory is read-only; use the supplied token when the server requires it.
	client := attack.NewHTTPClient(opts, vars)

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
		if adv.exact && lower != adv.key || !adv.exact && !strings.Contains(lower, adv.key) {
			continue
		}
		if parsed == nil {
			findings = append(findings, e.unverifiableFinding(endpoint, name, version, adv))
			continue
		}
		inRange, valid := vvMatchesAffected(parsed, adv.affected)
		if !valid {
			findings = append(findings, e.unverifiableFinding(endpoint, name, version, adv))
			continue
		}
		if !inRange {
			continue
		}
		findings = append(findings, e.finding(endpoint, name, version, adv))
	}
	return findings
}

func (e *VulnerableVersionExecutor) finding(endpoint, name, version string, adv vvAdvisory) attack.Finding {
	remediation := e.rule.Remediation
	if adv.fixed != "" {
		remediation = fmt.Sprintf("Upgrade %s to %s or later. Verify the installed package and review %s; serverInfo is self-reported.",
			adv.pkg, adv.fixed, adv.refs)
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   adv.severity,
		Confidence: attack.RiskIndicator,
		Title:      fmt.Sprintf("MCP server identifies as %q %s (%s)", name, version, adv.title),
		Description: fmt.Sprintf(
			"MCP server metadata at %s identifies this server as %q running version %s, which falls inside "+
				"the affected range %s for %s (%s). The version is self-reported and spoofable, and the "+
				"match does not prove the vulnerable code path is reachable from this surface - verify "+
				"against the advisory before acting.",
			endpoint, name, version, adv.affected, adv.key, adv.refs),
		Evidence: fmt.Sprintf("endpoint: %s\nserverInfo.name: %s\nserverInfo.version: %s\nmatched: %s %s\nadvisories: %s",
			endpoint, name, version, adv.key, adv.affected, adv.refs),
		Remediation: remediation,
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
			"MCP server metadata at %s identifies this server as %q reporting version %q, which is not a "+
				"parseable version for range comparison against %s (%s). Whether this deployment is "+
				"affected could not be determined from what the server publishes.",
			endpoint, name, version, adv.key, adv.refs),
		Evidence: fmt.Sprintf("endpoint: %s\nserverInfo.name: %s\nserverInfo.version: %s\nrelated advisories: %s",
			endpoint, name, version, adv.refs),
		Remediation: fmt.Sprintf("Verify the installed component version against %s; upgrade if affected.", adv.refs),
		TargetURL:   endpoint,
	}
}

type vvVersion struct {
	parts      []int
	prerelease bool
}

// vvParseVersion accepts dotted versions with optional semver suffixes.
func vvParseVersion(s string) *vvVersion {
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
	suffix := s[end:]
	pre, build, hasBuild := strings.Cut(suffix, "+")
	if hasBuild && !vvValidIdentifiers(build) {
		return nil
	}
	if pre != "" && (!strings.HasPrefix(pre, "-") || !vvValidIdentifiers(pre[1:])) {
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
	return &vvVersion{parts: out, prerelease: pre != ""}
}

func vvValidIdentifiers(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func vvMatchesAffected(version *vvVersion, affected string) (bool, bool) {
	bounds := strings.Fields(affected)
	if len(bounds) == 0 {
		return false, false
	}
	within := true
	for _, spec := range bounds {
		op, bound, ok := vvParseRange(spec)
		if !ok {
			return false, false
		}
		cmp := vvCompare(version, bound)
		switch op {
		case "<":
			within = within && cmp < 0
		case "<=":
			within = within && cmp <= 0
		case ">":
			within = within && cmp > 0
		case ">=":
			within = within && cmp >= 0
		case "=":
			within = within && cmp == 0
		}
	}
	return within, true
}

// vvParseRange splits an operator from its stable version bound.
func vvParseRange(r string) (op string, bound *vvVersion, ok bool) {
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
	return op, bound, bound != nil && !bound.prerelease
}

// vvCompare compares two dotted-numeric versions segment by segment; missing
// segments read as zero, so 1.0 == 1.0.0.
func vvCompare(a, b *vvVersion) int {
	n := len(a.parts)
	if len(b.parts) > n {
		n = len(b.parts)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a.parts) {
			av = a.parts[i]
		}
		if i < len(b.parts) {
			bv = b.parts[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	if a.prerelease && !b.prerelease {
		return -1
	}
	if !a.prerelease && b.prerelease {
		return 1
	}
	return 0
}
