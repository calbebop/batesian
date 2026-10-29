package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// CacheScopeExecutor compares public cache hints across two authorization contexts.
type CacheScopeExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-cache-scope", func(rc attack.RuleContext) attack.Executor {
		return &CacheScopeExecutor{rule: rc}
	})
}

func NewCacheScopeExecutor(rc attack.RuleContext) *CacheScopeExecutor {
	return &CacheScopeExecutor{rule: rc}
}

type cacheSnapshot struct {
	payload  []byte
	raw      []byte
	scope    string
	ttlMs    int64
	count    int
	received time.Time
}

type cacheSurface struct {
	method     string
	field      string
	capability string
}

var cacheListSurfaces = []cacheSurface{
	{"tools/list", "tools", "tools"},
	{"prompts/list", "prompts", "prompts"},
	{"resources/list", "resources", "resources"},
	{"resources/templates/list", "resourceTemplates", "resources"},
}

func (e *CacheScopeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	a, b, err := cacheScopePrincipals(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	var session mcpSession
	var firstA, firstB cacheSnapshot
	for _, endpoint := range modernDiscoveryEndpoints(vars.BaseURL, "") {
		candidate := mcpSession{Endpoint: endpoint, Era: EraModern}
		aResult, aErr := cacheScopeFetch(ctx, client, candidate, a, 1, cacheSurface{method: "server/discover"})
		bResult, bErr := cacheScopeFetch(ctx, client, candidate, b, 2, cacheSurface{method: "server/discover"})
		if aErr != nil || bErr != nil || !modernWireAdvertised(aResult.raw) || !modernWireAdvertised(bResult.raw) {
			continue
		}
		session, firstA, firstB = candidate, aResult, bResult
		break
	}
	if session.Endpoint == "" {
		return nil, fmt.Errorf("%w: two principals could not discover the same modern MCP endpoint at %s",
			attack.ErrInconclusive, vars.BaseURL)
	}

	var findings []attack.Finding
	var incomplete []error
	checks := append([]cacheSurface{{method: "server/discover"}}, cacheListSurfaces...)
	for _, surface := range checks {
		if surface.capability != "" && (!cacheSupports(firstA.raw, surface.capability) ||
			!cacheSupports(firstB.raw, surface.capability)) {
			continue
		}
		a1, b1 := firstA, firstB
		if surface.method != "server/discover" {
			var aErr, bErr error
			a1, aErr = cacheScopeFetch(ctx, client, session, a, 10, surface)
			b1, bErr = cacheScopeFetch(ctx, client, session, b, 11, surface)
			if aErr != nil || bErr != nil {
				incomplete = append(incomplete, fmt.Errorf("%w: %s did not return comparable results for both principals",
					attack.ErrInconclusive, surface.method))
				continue
			}
		}
		a2, aErr := cacheScopeFetch(ctx, client, session, a, 12, surface)
		b2, bErr := cacheScopeFetch(ctx, client, session, b, 13, surface)
		if aErr != nil || bErr != nil {
			incomplete = append(incomplete, fmt.Errorf("%w: %s could not be repeated for both principals",
				attack.ErrInconclusive, surface.method))
			continue
		}
		if !bytes.Equal(a1.payload, a2.payload) || !bytes.Equal(b1.payload, b2.payload) {
			incomplete = append(incomplete, fmt.Errorf("%w: %s changed within one principal's repeated reads",
				attack.ErrInconclusive, surface.method))
			continue
		}
		if bytes.Equal(a1.payload, b1.payload) || !cachePublic(a1, a2) || !cachePublic(b1, b2) ||
			a1.ttlMs <= b1.received.Sub(a1.received).Milliseconds() ||
			b1.ttlMs <= a2.received.Sub(b1.received).Milliseconds() {
			continue
		}
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      fmt.Sprintf("MCP %s advertises different principal results as publicly cacheable", surface.method),
			Description: fmt.Sprintf("%s returned different stable results to %s and %s for the same request, while both responses declared a positive public cache lifetime. A shared client or gateway may serve one principal's result to the other. This proves a cache-scope mismatch, but does not prove a client actually shared the result.",
				surface.method, a.name, b.name),
			Evidence: fmt.Sprintf("method: %s\nprincipal %s: %d item(s), public TTL %d ms\nprincipal %s: %d item(s), public TTL %d ms\nA-B-A-B results were stable within each principal and different across principals; response content omitted",
				surface.method, a.name, a1.count, a1.ttlMs, b.name, b1.count, b1.ttlMs),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
	}
	return findings, errors.Join(incomplete...)
}

func cacheScopePrincipals(opts attack.Options) (taskPrincipal, taskPrincipal, error) {
	if len(opts.Principals) < 2 {
		return taskPrincipal{}, taskPrincipal{}, fmt.Errorf("%w: cache-scope comparison requires two configured principals",
			attack.ErrInconclusive)
	}
	a, err := configuredTaskPrincipal(opts.Principals[0])
	if err != nil {
		return a, taskPrincipal{}, err
	}
	b, err := configuredTaskPrincipal(opts.Principals[1])
	if err != nil {
		return a, b, err
	}
	if len(principalIdentityHeaders(a)) == 0 || len(principalIdentityHeaders(b)) == 0 || samePrincipalIdentity(a, b) {
		return a, b, fmt.Errorf("%w: cache-scope comparison requires two distinct principal identities",
			attack.ErrInconclusive)
	}
	return a, b, nil
}

func cacheScopeFetch(ctx context.Context, client *attack.HTTPClient, session mcpSession, principal taskPrincipal,
	id int, surface cacheSurface) (cacheSnapshot, error) {
	headers, body := session.request(id, surface.method, nil)
	identity := map[string]string{}
	attachPrincipal(identity, principal)
	for key, value := range headers {
		identity[key] = value
	}
	resp, err := client.POST(ctx, session.Endpoint, identity, body)
	verdict, envelope := classifyProbe(resp, err, id)
	if verdict != probeAnswered || !validRPCResult(envelope) {
		return cacheSnapshot{}, fmt.Errorf("%w: %s did not return a successful result", attack.ErrInconclusive, surface.method)
	}
	result, ok := envelope["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return cacheSnapshot{}, fmt.Errorf("%w: %s returned no complete result", attack.ErrInconclusive, surface.method)
	}
	snapshot := cacheSnapshot{raw: resp.Body, received: time.Now()}
	snapshot.scope, _ = result["cacheScope"].(string)
	if ttl, ok := result["ttlMs"].(json.Number); ok {
		if value, parseErr := strconv.ParseInt(ttl.String(), 10, 64); parseErr == nil && value > 0 {
			snapshot.ttlMs = value
		}
	}
	var payload interface{}
	if surface.field == "" {
		copyResult := make(map[string]interface{}, len(result))
		for key, value := range result {
			if key != "ttlMs" && key != "cacheScope" && key != "_meta" {
				copyResult[key] = value
			}
		}
		payload = copyResult
	} else {
		items, ok := result[surface.field].([]interface{})
		if !ok {
			return cacheSnapshot{}, fmt.Errorf("%w: %s returned no %s array",
				attack.ErrInconclusive, surface.method, surface.field)
		}
		snapshot.count = len(items)
		canonical := make([]string, 0, len(items))
		for _, item := range items {
			encoded, marshalErr := json.Marshal(item)
			if marshalErr != nil {
				return cacheSnapshot{}, marshalErr
			}
			canonical = append(canonical, string(encoded))
		}
		sort.Strings(canonical)
		payload = map[string]interface{}{"items": canonical, "nextCursor": result["nextCursor"]}
	}
	var marshalErr error
	snapshot.payload, marshalErr = json.Marshal(payload)
	return snapshot, marshalErr
}

func cacheSupports(raw []byte, capability string) bool {
	return (mcpSession{RawInit: raw}).ServerSupports(capability)
}

func cachePublic(first, repeat cacheSnapshot) bool {
	return first.scope == "public" && repeat.scope == "public" && first.ttlMs > 0 && repeat.ttlMs > 0
}
