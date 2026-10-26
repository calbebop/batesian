package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// PromptUnauthExecutor probes whether MCP prompt templates are accessible
// without authentication (rule mcp-prompt-unauth-001).
type PromptUnauthExecutor struct {
	rule attack.RuleContext
}

// NewPromptUnauthExecutor creates an executor for mcp-prompt-unauth.
func init() {
	attack.Register("mcp-prompt-unauth", func(rc attack.RuleContext) attack.Executor { return NewPromptUnauthExecutor(rc) })
}

func NewPromptUnauthExecutor(r attack.RuleContext) *PromptUnauthExecutor {
	return &PromptUnauthExecutor{rule: r}
}

func (e *PromptUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token - the rule tests whether prompts are
	// accessible WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// A server may expose prompts on both protocol wires, and need not gate them
	// the same way on each, so every wire it serves is probed.
	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session)
	})
}

// probeSession runs the rule against one already-opened wire. determined reports
// whether the wire established anything; see classifyProbe.
func (e *PromptUnauthExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, determined bool) {
	// Skip servers that do not advertise the prompts capability - probing them
	// would produce meaningless noise. This reads the server capabilities from
	// the handshake captured by initializeMCP (no redundant second initialize),
	// and parses the structured capabilities object rather than substring-matching
	// the whole body (which could false-match "prompts" in serverInfo/instructions).
	if !session.ServerSupports("prompts") {
		// Determined: the server says it has none, so none can be open.
		return nil, true
	}

	// Call prompts/list without any auth token.
	listResp, err := session.post(ctx, client, 3, "prompts/list", nil)
	result, denied, ok := promptListResult(listResp, err, 3)
	if !ok {
		return nil, denied
	}
	promptsRaw, ok := result["prompts"].([]interface{})
	if !ok {
		return nil, false
	}
	cursor, more, valid := resourcesListCursor(result)
	complete := valid && !more
	seen := map[string]bool{}
	nextID := 4
	for page := 1; page < 10 && valid && more; page++ {
		if seen[cursor] {
			break
		}
		seen[cursor] = true
		pageID := nextID
		nextID++
		pageResp, pageErr := session.post(ctx, client, pageID, "prompts/list",
			map[string]interface{}{"cursor": cursor})
		pageResult, _, ok := promptListResult(pageResp, pageErr, pageID)
		if !ok {
			break
		}
		pagePrompts, ok := pageResult["prompts"].([]interface{})
		if !ok {
			break
		}
		promptsRaw = append(promptsRaw, pagePrompts...)
		cursor, more, valid = resourcesListCursor(pageResult)
		complete = valid && !more
	}
	if len(promptsRaw) == 0 {
		return nil, complete
	}

	// Collect prompt names for evidence.
	var names []string
	for _, p := range promptsRaw {
		if pm, ok := p.(map[string]interface{}); ok {
			if name, ok := pm["name"].(string); ok {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, false
	}
	evidence := fmt.Sprintf("HTTP %d from %s\nprompts (%d): %v", listResp.StatusCode, session.Endpoint, len(names), names)
	if !complete {
		evidence += "\nlisting incomplete: pagination stopped before the final page"
	}

	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "info",
		Confidence: attack.RiskIndicator,
		Title: fmt.Sprintf(
			"MCP prompts/list returned %d template(s) without authentication", len(names)),
		Description: fmt.Sprintf(
			"prompts/list at %s returned %d prompt names without authentication. "+
				"This shows name visibility, not access to prompt contents. Whether it violates policy depends on the deployment.",
			session.Endpoint, len(names)),
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	const maxPromptReads = 10
	var outcomes []string
	getsComplete := true
	for i, name := range names {
		if i >= maxPromptReads {
			break
		}
		id := nextID
		nextID++
		getResp, err := session.post(ctx, client, id, "prompts/get", map[string]interface{}{"name": name})
		content, outcome := promptGetOutcome(getResp, err, id)
		outcomes = append(outcomes, outcome)
		if strings.HasPrefix(outcome, "incomplete") {
			getsComplete = false
		}
		if content == "" {
			continue
		}
		for _, pattern := range credentialPatterns {
			if pattern.MatchString(content) {
				content = "[redacted: credential pattern detected]"
				break
			}
		}
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title: fmt.Sprintf(
				"MCP prompt %q full content readable without authentication", name),
			Description: fmt.Sprintf(
				"prompts/get for %q at %s returned full template content without authentication. "+
					"The content is readable by unauthenticated callers; whether that violates policy depends on the deployment.",
				name, session.Endpoint),
			Evidence:    fmt.Sprintf("HTTP %d from %s\nprompt: %q\ncontent snippet: %.400s", getResp.StatusCode, session.Endpoint, name, content),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
		break
	}
	findings[0].Evidence += "\nprompts/get attempts:"
	for i, outcome := range outcomes {
		findings[0].Evidence += fmt.Sprintf("\n  %d: %s", i+1, outcome)
	}
	if len(findings) == 1 {
		findings[0].Evidence += "\nprompt content access not confirmed"
	}

	return findings, complete && getsComplete
}

// promptListResult distinguishes an auth gate from an unrelated RPC failure.
func promptListResult(resp *attack.Response, err error, id int) (map[string]interface{}, bool, bool) {
	verdict, body := classifyProbe(resp, err, id)
	if verdict == probeInconclusive {
		return nil, false, false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, true, false
	}
	if _, ok := body["error"]; ok {
		return nil, promptAuthError(body), false
	}
	if verdict != probeAnswered {
		return nil, false, false
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || (result["resultType"] != nil && result["resultType"] != "complete") {
		return nil, false, false
	}
	return result, false, true
}

func promptGetOutcome(resp *attack.Response, err error, id int) (string, string) {
	verdict, body := classifyProbe(resp, err, id)
	switch verdict {
	case probeInconclusive:
		if err != nil || resp == nil {
			return "", "incomplete (transport error)"
		}
		if !resp.IsSuccess() {
			return "", fmt.Sprintf("incomplete (HTTP %d)", resp.StatusCode)
		}
		return "", "incomplete (invalid JSON-RPC response)"
	case probeRejected:
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", fmt.Sprintf("denied (HTTP %d)", resp.StatusCode)
		}
		if promptAuthError(body) {
			return "", "denied (JSON-RPC error)"
		}
		return "", "incomplete (JSON-RPC error)"
	case probeAnswered:
		if _, hasErr := body["error"]; hasErr {
			if promptAuthError(body) {
				return "", "denied (JSON-RPC error)"
			}
			return "", "incomplete (JSON-RPC error)"
		}
		return promptGetContent(resp.Body, id)
	default:
		return "", "incomplete (unknown response)"
	}
}

func promptAuthError(body map[string]interface{}) bool {
	rpcErr, ok := body["error"].(map[string]interface{})
	if !ok {
		return false
	}
	msg, _ := rpcErr["message"].(string)
	return authFlavoredError(rpcErrorCode(rpcErr["code"]), msg)
}

func promptGetContent(response []byte, id int) (string, string) {
	var body struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  *struct {
			ResultType string `json:"resultType"`
			Messages   *[]struct {
				Content struct {
					Type     string `json:"type"`
					Text     string `json:"text"`
					Data     string `json:"data"`
					Resource struct {
						URI  string `json:"uri"`
						Text string `json:"text"`
						Blob string `json:"blob"`
					} `json:"resource"`
				} `json:"content"`
			} `json:"messages"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(response, &body) != nil {
		return "", "incomplete (invalid prompt response)"
	}
	if body.JSONRPC != "2.0" || string(body.ID) != strconv.Itoa(id) || len(body.Error) != 0 {
		return "", "incomplete (invalid JSON-RPC response)"
	}
	if body.Result == nil {
		return "", "incomplete (missing result)"
	}
	if body.Result.ResultType == "input_required" {
		return "", "incomplete (input required)"
	}
	if body.Result.ResultType != "" && body.Result.ResultType != "complete" {
		return "", "incomplete (unexpected result type)"
	}
	if body.Result.Messages == nil {
		return "", "incomplete (missing prompt messages)"
	}

	var content string
	invalidContent := false
	for _, message := range *body.Result.Messages {
		item := message.Content
		switch item.Type {
		case "text":
			content = item.Text
		case "image", "audio":
			decoded, err := base64.StdEncoding.DecodeString(item.Data)
			if err != nil {
				invalidContent = true
			} else if len(decoded) != 0 {
				content = fmt.Sprintf("[%s content: %d bytes]", item.Type, len(decoded))
			}
		case "resource":
			if item.Resource.URI == "" {
				invalidContent = true
				continue
			}
			content = item.Resource.Text
			if content == "" {
				decoded, err := base64.StdEncoding.DecodeString(item.Resource.Blob)
				if err != nil {
					invalidContent = true
				} else if len(decoded) != 0 {
					content = fmt.Sprintf("[embedded resource: %d bytes]", len(decoded))
				}
			}
		default:
			invalidContent = true
		}
		if content != "" {
			break
		}
	}
	if content != "" {
		return content, "content returned"
	}
	if invalidContent {
		return "", "incomplete (invalid prompt content)"
	}
	return "", "no non-empty content returned"
}
