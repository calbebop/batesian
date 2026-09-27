package mcp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// OriginPrefixBypassExecutor checks whether a foreign, browser-shaped Origin
// bypasses a validator that rejects an unrelated Origin.
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

// prefixCanaryZone is a non-resolving stand-in for an attacker domain.
const prefixCanaryZone = "prefix-rebind.batesian-invalid.invalid"

type originProbe struct {
	label        string
	origin       string
	attackerHost string
}

// prefixProbes keeps the target port after the foreign hostname, as browsers do.
func prefixProbes(target *url.URL) []originProbe {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	scheme := strings.ToLower(target.Scheme)
	if host == "" || strings.Contains(host, ":") || (scheme != "http" && scheme != "https") {
		return nil
	}
	for _, r := range host {
		if r > 127 {
			return nil
		}
	}
	attackerHost := host + "." + prefixCanaryZone
	origin := scheme + "://" + attackerHost
	port := target.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil
		}
		port = strconv.Itoa(n)
	}
	isDefaultPort := (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
	if port != "" && !isDefaultPort {
		origin += ":" + port
	}
	return []originProbe{{"attacker hostname with trusted-host prefix", origin, attackerHost}}
}

func (e *OriginPrefixBypassExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	u, err := url.Parse(vars.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: could not parse a host out of %s",
			attack.ErrInconclusive, vars.BaseURL)
	}

	probes := prefixProbes(u)
	if len(probes) == 0 {
		return nil, fmt.Errorf("%w: no browser-shaped prefix probe for %s", attack.ErrInconclusive, vars.BaseURL)
	}

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

		for _, probe := range probes {
			ok, _ := e.originWith(ctx, client, session, probe.origin)
			if !ok {
				continue // this craft was rejected too: validator held on it
			}
			return []attack.Finding{e.finding(session, probe)}, true
		}
		// The browser-shaped prefix was rejected.
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
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP Origin validation accepts " + method + " with a prefix-forged origin (" + method + " reached)",
		Description: fmt.Sprintf(
			"The %s endpoint rejected an unrelated Origin but accepted %q, whose foreign "+
				"hostname (%s) shares a string prefix with the target hostname. This "+
				"browser-shaped Origin bypasses the validator; exploitability also depends "+
				"on network and TLS conditions. Compare parsed origins exactly, including "+
				"scheme, hostname, and port.", session.Endpoint, probe.origin, probe.attackerHost),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nbaseline %s (no Origin): accepted\n"+
				"control, unrelated origin %s: rejected\n"+
				"probe (%s) %s: ACCEPTED\nforeign hostname: %s",
			session.Endpoint, method, foreignOrigin, probe.label, probe.origin, probe.attackerHost),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}
