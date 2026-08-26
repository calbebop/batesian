package mcp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// OriginPrefixBypassExecutor tests whether an MCP server's Origin validation
// compares strings instead of parsed hosts (rule mcp-origin-prefix-bypass-001).
//
// mcp-dns-rebind-origin-001 asks whether any validation exists at all, using a
// completely unrelated origin. But the recurring real-world defect sits one
// step inside: validators implemented as string prefix or containment checks -
//
//	strings.HasPrefix(origin, "https://trusted.example")
//	strings.Contains(origin, "trusted.example")
//
// - reject that same unrelated origin and read clean under the existing rule,
// while accepting anything that merely STARTS WITH the trusted string:
//
//	https://trusted.example.attacker.tld   (attacker subdomain)
//	https://trusted.example@attacker.tld    (userinfo smuggle)
//
// Both published repeatedly as CVEs in MCP platform transports this quarter
// (CVE-2026-55532 prefix match, CVE-2026-55637 local rebind), because every
// naive implementation reaches for HasPrefix before reaching for url.Parse.
//
// The probe is a control pair on each served wire:
//
//	baseline        handshake without Origin                  -> must succeed
//	control twin    same request + fully foreign origin       -> must FAIL
//	                (a failure proves a validator exists)
//	prefix twins    same request + <host>-sharing origins     -> any ACCEPT is
//	                the bypass, confirmed against the rejecting control
//
// If the control twin is also accepted there is no validator to bypass; that
// surface belongs to mcp-dns-rebind-origin-001 and is suppressed here rather
// than double-counted.
type OriginPrefixBypassExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-origin-prefix-bypass", func(rc attack.RuleContext) attack.Executor {
		return NewOriginPrefixBypassExecutor(rc)
	})
}

func NewOriginPrefixBypassExecutor(r attack.RuleContext) *OriginPrefixBypassExecutor {
	return &OriginPrefixBypassExecutor{rule: r}
}

// prefixCanaryZone is the non-resolving RFC 6761 zone used to craft attacker
// domains that share the target's hostname as a string prefix.
const prefixCanaryZone = "prefix-rebind.batesian-invalid.invalid"

// originProbe is one crafted Origin value plus what its acceptance would mean.
type originProbe struct {
	label  string
	origin string
}

// prefixProbes composes the crafted origins for a target exactly as a
// prefix-matching validator sees them: raw strings starting with the trusted
// value. The target's own scheme and host[:port] travel verbatim inside the
// craft, because deployments allowlist whatever they themselves serve - an
// http server never accepts https-prefixed strings, so the mirror is what
// makes a prefix bug observable rather than merely another rejection.
func prefixProbes(trustedOrigin string) []originProbe {
	return []originProbe{
		{"attacker subdomain sharing the trusted hostname",
			trustedOrigin + "." + prefixCanaryZone},
		{"userinfo-smuggled attacker domain",
			trustedOrigin + "@" + prefixCanaryZone},
	}
}

func (e *OriginPrefixBypassExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	u, err := url.Parse(vars.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: could not parse a host out of %s",
			attack.ErrInconclusive, vars.BaseURL)
	}

	targetHostPort := u.Host // kept raw incl. port: prefix matches are literal
	trustedOrigin := u.Scheme + "://" + targetHostPort

	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {

		// Control: an unrelated origin. Accepted means no validator runs here at
		// all, which suppresses the rule; rejected proves one does.
		ctrlOK, ctrlResp := e.originWith(ctx, client, session, foreignOrigin)
		if ctrlResp == nil {
			return nil, false // no verdict from this wire
		}
		if ctrlOK {
			return nil, true // no gate: dns-rebind's surface, not ours
		}

		for _, probe := range prefixProbes(trustedOrigin) {
			ok, _ := e.originWith(ctx, client, session, probe.origin)
			if !ok {
				continue // this craft was rejected too: validator held on it
			}
			return []attack.Finding{e.finding(session, probe)}, true
		}
		// Every craft rejected against a live validator: the boundary held.
		return nil, true
	})
}

// originWith repeats this wire's baseline request carrying the given Origin.
// The request shape mirrors dns-rebind's twin selection so both rules pair
// their probes against the identical baseline per era.
func (e *OriginPrefixBypassExecutor) originWith(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, origin string) (bool, *attack.Response) {
	if session.Era == EraModern {
		resp, err := session.postShaping(ctx, client, "batesian-originpfx", "server/discover", nil,
			func(h map[string]string) { h["Origin"] = origin })
		if err != nil {
			return false, nil
		}
		return resp.IsAccepted(), resp
	}
	headers := map[string]string{"Content-Type": "application/json", "Origin": origin}
	resp, err := client.POST(ctx, session.Endpoint, headers, legacyHandshakeBody())
	if err != nil {
		return false, nil
	}
	return resp.IsAccepted(), resp
}

func (e *OriginPrefixBypassExecutor) finding(session mcpSession, probe originProbe) attack.Finding {
	method := probeMethod(session)
	host := sessionHost(session.Endpoint)
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP Origin validation accepts " + method + " with a prefix-forged origin (" + method + " reached)",
		Description: fmt.Sprintf(
			"The %s endpoint rejected a fully foreign Origin but accepted one whose string merely "+
				"starts with the trusted value (%q). That is a string prefix or containment check, not "+
				"host validation: parsed out, the accepted origin resolves to attacker infrastructure "+
				"(%s), so the DNS rebinding protection the check pretends to provide does not exist. "+
				"A page on such a domain can drive this server from a victim's browser exactly as if "+
				"no check were present. Parse the Origin header into a URL and compare scheme and host "+
				"components individually.", session.Endpoint, probe.origin, host),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nbaseline %s (no Origin): accepted\n"+
				"control, unrelated origin %s: rejected\n"+
				"probe (%s) %s: ACCEPTED\naccepted origin resolves to attacker infrastructure; "+
				"shared substring only", session.Endpoint, method, foreignOrigin, probe.label, probe.origin),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}

// sessionHost extracts the host component of an endpoint for finding text.
func sessionHost(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
}
