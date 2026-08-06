package mcp

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// EraDowngradeExecutor probes whether a server that serves both protocol wires
// gates them differently (rule mcp-era-downgrade-001).
//
// The 2026-07-28 revision is a second, independent entry point. A server built on
// the current SDKs serves it alongside the handshake revisions on the same URL, so
// an authorization check bolted onto one request path leaves the other open, and a
// caller simply asks on the wire that answers. This is
// mcp-init-downgrade-001's bug with wires in place of versions.
type EraDowngradeExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-era-downgrade", func(rc attack.RuleContext) attack.Executor {
		return NewEraDowngradeExecutor(rc)
	})
}

func NewEraDowngradeExecutor(r attack.RuleContext) *EraDowngradeExecutor {
	return &EraDowngradeExecutor{rule: r}
}

func (e *EraDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Probe UNAUTHENTICATED, for the reason mcp-init-downgrade-001 does: attaching
	// opts.Token would have a gated wire grant the call too, and the discriminator
	// below could never fire. Reaching protected functionality without credentials
	// is the whole claim.
	client := attack.NewUnauthHTTPClient(opts, vars)

	sessions, err := openSessions(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, err
	}

	var legacy, modern *mcpSession
	for i := range sessions {
		switch sessions[i].Era {
		case EraLegacy:
			legacy = &sessions[i]
		case EraModern:
			modern = &sessions[i]
		case EraUnknown:
			// openSessions never returns one; nothing to compare against.
		}
	}
	if legacy == nil || modern == nil {
		// One wire cannot disagree with itself. A server serving a single era is
		// covered by the unauth rules, not here.
		return nil, nil
	}

	legacyOutcome := e.probeList(ctx, client, *legacy)
	modernOutcome := e.probeList(ctx, client, *modern)
	if legacyOutcome.method == "" || modernOutcome.method == "" {
		// Neither wire advertised a listable capability, so there is nothing whose
		// gating could be compared.
		return nil, nil
	}

	// Both granted means the server gates nothing, which is
	// mcp-resources-unauth-001 and mcp-tools-unauth-001 territory rather than a
	// difference between wires. Both refused is the secure outcome. Either way
	// there is no asymmetry to report.
	if legacyOutcome.granted == modernOutcome.granted {
		return nil, nil
	}

	open, closed := legacyOutcome, modernOutcome
	if modernOutcome.granted {
		open, closed = modernOutcome, legacyOutcome
	}
	return []attack.Finding{e.finding(*legacy, open, closed)}, nil
}

// listOutcome is one wire's answer to a read-only list call.
type listOutcome struct {
	era    Era
	method string // "" when the wire advertised nothing listable
	status int
	body   string
	// granted is true when the call was answered with a JSON-RPC result rather
	// than refused, which for an unauthenticated probe means no gate stopped it.
	granted bool
}

// probeList asks one wire for a listing, choosing a method that wire advertises.
//
// The capability is read from that wire's own advertisement, because the two need
// not agree: on a server built on the Python SDK the handshake reports
// experimental, prompts, resources and tools while server/discover reports
// prompts, resources and tools. Comparing a method one wire does not implement
// against one it does would measure the capability difference, not the gate.
func (e *EraDowngradeExecutor) probeList(ctx context.Context, client *attack.HTTPClient, session mcpSession) listOutcome {
	out := listOutcome{era: session.Era}

	for _, c := range []struct{ capability, method string }{
		{"tools", "tools/list"},
		{"resources", "resources/list"},
		{"prompts", "prompts/list"},
	} {
		if !session.ServerSupports(c.capability) {
			continue
		}
		out.method = c.method
		break
	}
	if out.method == "" {
		return out
	}

	resp, err := session.post(ctx, client, 2, out.method, nil)
	if err != nil {
		// A transport failure is not a refusal, and treating it as one would invent
		// an asymmetry out of a dropped connection. Leaving method set with granted
		// false would do exactly that, so the outcome is blanked.
		out.method = ""
		return out
	}
	out.status = resp.StatusCode
	out.body = resp.BodyString()
	out.granted = resp.IsAccepted()
	return out
}

func (e *EraDowngradeExecutor) finding(session mcpSession, open, closed listOutcome) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "critical",
		Confidence: attack.ConfirmedExploit,
		Title: fmt.Sprintf("MCP authorization enforced on the %s wire but not the %s wire (era downgrade bypass)",
			closed.era, open.era),
		Description: fmt.Sprintf(
			"At %s, an unauthenticated %s was REFUSED on the %s wire but ANSWERED on the %s wire. "+
				"The server serves both protocol eras on one endpoint and applies its authorization "+
				"check to only one of them, so a caller reaches protected functionality by asking on "+
				"the other. Nothing about the two eras changes who is allowed to read what.",
			session.Endpoint, open.method, closed.era, open.era),
		Evidence: fmt.Sprintf(
			"endpoint: %s\n%s wire: %s -> HTTP %d, refused\n%s wire: %s -> HTTP %d, answered\nanswered body: %.300s",
			session.Endpoint,
			closed.era, closed.method, closed.status,
			open.era, open.method, open.status, open.body),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}
