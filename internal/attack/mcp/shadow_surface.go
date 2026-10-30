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
	var initBody []byte
	var sessionID string
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
		initBody = resp.Body
		sessionID = resp.Headers.Get("Mcp-Session-Id")
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
		return e.dashboardFinding(base, host, port, marker, probeEvidence), incomplete
	}

	endpoint := base + mcpPath
	session := mcpSession{Endpoint: endpoint, SessionID: sessionID,
		ProtocolVersion: negotiatedVersion(initBody), RawInit: initBody}
	_, _ = client.POST(ctx, endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	})

	method, count := "", 0
	for i, candidate := range advertisedListMethods(session) {
		id := i + 2
		resp, err := session.post(ctx, client, id, candidate, nil)
		items, valid := shadowListItems(resp, err, id, candidate)
		if valid && items > 0 {
			method, count = candidate, items
			break
		}
		if !valid && (err != nil || resp == nil || (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden)) {
			incomplete = true
		}
	}
	if method == "" {
		if marker == "" {
			return nil, incomplete
		}
		return e.dashboardFinding(base, host, port, marker,
			"MCP initialize answered; no unauthenticated read-only listing was observed"), incomplete
	}

	// Check both the foreign-Origin handshake and the same read-only listing.
	rebindResp, rebindErr := client.POST(ctx, endpoint, map[string]string{"Origin": foreignOrigin}, legacyHandshakeBody())
	originRefused := rebindErr == nil && rebindResp != nil && rebindResp.StatusCode == http.StatusForbidden
	originOpen := false
	if rebindErr == nil && rebindResp != nil && rebindResp.IsSuccess() && initializeSucceeded(rebindResp.Body) {
		foreignSession := mcpSession{Endpoint: endpoint, SessionID: rebindResp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(rebindResp.Body), RawInit: rebindResp.Body}
		headers := foreignSession.header()
		headers["Origin"] = foreignOrigin
		_, _ = client.POST(ctx, endpoint, headers, map[string]interface{}{
			"jsonrpc": "2.0", "method": "notifications/initialized",
		})
		foreignList, listErr := foreignSession.postShaping(ctx, client, 2, method, nil,
			func(headers map[string]string) { headers["Origin"] = foreignOrigin })
		foreignCount, valid := shadowListItems(foreignList, listErr, 2, method)
		originOpen = valid && foreignCount > 0
		originRefused = listErr == nil && foreignList != nil && foreignList.StatusCode == http.StatusForbidden
	}
	originEvidence := "inconclusive (transport failure)"
	originDescription := "The foreign-Origin comparison did not yield a verdict, so browser reachability was not assessed."
	if rebindResp != nil {
		originEvidence = fmt.Sprintf("inconclusive (HTTP %d)", rebindResp.StatusCode)
	}
	if originOpen {
		originEvidence = "initialize and listing accepted"
		originDescription = "The same read-only listing also succeeded with a foreign Origin."
	} else if originRefused {
		originEvidence = "refused (HTTP 403)"
		originDescription = "The foreign-Origin handshake or listing was refused with HTTP 403."
	}

	sev, title := "medium", fmt.Sprintf("MCP %s exposes %d item(s) without authentication on %s:%d%s", method, count, host, port, mcpPath)
	if originOpen {
		sev = "high"
		title = fmt.Sprintf("Unauthenticated MCP %s accepts foreign Origins on %s:%d%s", method, host, port, mcpPath)
	}
	evidence := fmt.Sprintf("endpoint: %s\ninitialize without credentials: accepted\n%s without credentials: %d items\nforeign Origin twin (%s): %s",
		endpoint, method, count, foreignOrigin, originEvidence)
	if marker != "" {
		evidence += "\npage fingerprint: " + marker
	}
	return &attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   sev,
		Confidence: attack.ConfirmedExploit,
		Title:      title,
		Description: fmt.Sprintf("An MCP %s returned %d item(s) without credentials at %s on an adjacent port. %s",
			method, count, endpoint, originDescription),
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}, incomplete || (!originOpen && !originRefused)
}

func (e *ShadowSurfaceExecutor) dashboardFinding(base, host string, port int, marker, probeEvidence string) *attack.Finding {
	return &attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "low", Confidence: attack.RiskIndicator,
		Title:       fmt.Sprintf("Known MCP dashboard served without credentials on %s:%d (%s)", host, port, marker),
		Description: fmt.Sprintf("GET %s/ returned a page identifying as %q. The dashboard is visible to this scan position, but operational access was not established.", base, marker),
		Evidence:    fmt.Sprintf("GET %s/ -> HTTP 200, body names %q\n%s", base, marker, probeEvidence),
		Remediation: e.rule.Remediation, TargetURL: base + "/",
	}
}

func shadowListItems(resp *attack.Response, err error, id int, method string) (int, bool) {
	if err != nil || resp == nil || !resp.IsSuccess() {
		return 0, false
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok || !matchesRPCID(body, id) || !validRPCResult(body) {
		return 0, false
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok {
		return 0, false
	}
	items, ok := result[strings.TrimSuffix(method, "/list")].([]interface{})
	if !ok {
		return 0, false
	}
	return len(items), true
}

func shadowProbeIncomplete(resp *attack.Response, err error) bool {
	if err != nil {
		// 10061 is Winsock's WSAECONNREFUSED.
		return !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.Errno(10061))
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
