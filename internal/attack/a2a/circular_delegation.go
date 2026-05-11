package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// CircularDelegationExecutor tests whether an A2A agent enforces delegation
// loop detection or depth limits (rule a2a-circular-delegation-001).
//
// Detection uses two complementary methods:
//
//  1. OOB callback: craft a tasks/send containing delegation configuration
//     fields pointing to a local listener. If the agent makes an outbound
//     request to that URL, it delegated without loop detection.
//
//  2. Depth probe: embed a 10-hop delegation chain in configuration metadata.
//     A compliant agent should reject the task with a depth-limit error.
type CircularDelegationExecutor struct {
	rule attack.RuleContext
}

// NewCircularDelegationExecutor creates an executor for a2a-circular-delegation.
func NewCircularDelegationExecutor(r attack.RuleContext) *CircularDelegationExecutor {
	return &CircularDelegationExecutor{rule: r}
}

func (e *CircularDelegationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	rpcPaths := []string{"", "/a2a", "/rpc", "/api"}
	var findings []attack.Finding

	for _, path := range rpcPaths {
		ep := vars.BaseURL + path

		// Method 1: OOB callback delegation probe.
		if f := e.oobProbe(ctx, client, ep, opts.OOBListenerURL); f != nil {
			findings = append(findings, *f)
			break
		}

		// Method 2: depth-limit probe.
		if f := e.depthProbe(ctx, client, ep); f != nil {
			findings = append(findings, *f)
			break
		}
	}

	return findings, nil
}

// oobProbe starts a local listener and sends a task with delegation fields
// pointing to that listener. Returns a finding if an outbound request arrives.
func (e *CircularDelegationExecutor) oobProbe(
	ctx context.Context,
	client *attack.HTTPClient,
	ep string,
	existingOOB string,
) *attack.Finding {
	// Prefer a pre-configured OOB URL; fall back to a local listener.
	callbackURL := existingOOB
	var callbackReceived atomic.Bool

	if callbackURL == "" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil
		}
		callbackURL = fmt.Sprintf("http://127.0.0.1:%d/batesian-circdeleg", addrPort(ln.Addr().String()))
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callbackReceived.Store(true)
				w.WriteHeader(http.StatusOK)
			}),
		}
		go func() { _ = srv.Serve(ln) }()
		defer func() { _ = srv.Close() }()
	}

	resp, err := client.POST(ctx, ep, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tasks/send",
		"params": map[string]interface{}{
			"id": "batesian-circdeleg-oob",
			"message": map[string]interface{}{
				"role":  1,
				"parts": []interface{}{map[string]interface{}{"text": "ping"}},
			},
			"configuration": map[string]interface{}{
				"forwardTask": callbackURL,
				"delegateTo":  callbackURL,
				"delegateURL": callbackURL,
				"upstreamURL": callbackURL,
			},
		},
	})
	if err != nil || resp.StatusCode == 0 || !looksLikeA2A(resp.Body) {
		return nil
	}

	// Give the agent 1s to make the outbound request.
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(1 * time.Second):
	}

	if callbackReceived.Load() {
		return &attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"A2A agent at %s delegated task to attacker-controlled URL (no loop detection)",
				ep),
			Description: fmt.Sprintf(
				"A tasks/send request with forwardTask/delegateTo configuration pointing to %s "+
					"caused the agent to make an outbound HTTP request. The agent accepted the "+
					"caller-supplied delegation target without allowlist validation or loop detection.",
				callbackURL),
			Evidence: fmt.Sprintf(
				"POST %s\ncallback URL: %s\noutbound callback received: yes\nHTTP %d",
				ep, callbackURL, resp.StatusCode),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}
	}
	return nil
}

// depthProbe sends a task with a 10-hop delegation chain and checks whether
// the server applies a depth limit.
func (e *CircularDelegationExecutor) depthProbe(
	ctx context.Context,
	client *attack.HTTPClient,
	ep string,
) *attack.Finding {
	chain := make([]interface{}, 10)
	for i := range chain {
		chain[i] = map[string]interface{}{
			"agent": fmt.Sprintf("https://agent-%d.batesian.invalid/a2a", i),
			"hop":   i + 1,
		}
	}

	resp, err := client.POST(ctx, ep, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tasks/send",
		"params": map[string]interface{}{
			"id": "batesian-circdeleg-depth",
			"message": map[string]interface{}{
				"role":  1,
				"parts": []interface{}{map[string]interface{}{"text": "ping"}},
			},
			"configuration": map[string]interface{}{
				"delegationChain": chain,
				"hopCount":        10,
				"maxHops":         10,
			},
		},
	})
	if err != nil || resp.StatusCode == 0 || !looksLikeA2A(resp.Body) {
		return nil
	}

	var body map[string]interface{}
	_ = json.Unmarshal(resp.Body, &body)
	_, hasError := body["error"]

	// 2xx with no JSON-RPC error means the server accepted the deep chain.
	if resp.IsSuccess() && !hasError {
		return &attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title: fmt.Sprintf(
				"A2A agent at %s accepted tasks/send with 10-hop delegation chain (no depth limit)",
				ep),
			Description: fmt.Sprintf(
				"A tasks/send with configuration.hopCount=10 and a 10-entry delegationChain was "+
					"accepted by %s with HTTP %d and no JSON-RPC error. A compliant implementation "+
					"should reject tasks that exceed a maximum delegation depth to prevent "+
					"resource exhaustion from circular or unbounded delegation chains.",
				ep, resp.StatusCode),
			Evidence: fmt.Sprintf(
				"POST %s\nhopCount: 10, delegationChain: [10 entries]\nHTTP %d, no JSON-RPC error\nsnippet: %.300s",
				ep, resp.StatusCode, string(resp.Body)),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}
	}
	return nil
}

// addrPort extracts the port number from an address string.
// Handles both IPv4 ("1.2.3.4:port") and IPv6 ("[::1]:port") forms.
func addrPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return port
}
