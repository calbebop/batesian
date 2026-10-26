package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskIDEntropyExecutor checks modern Tasks extension handles for weak IDs.
// Only approved, annotated read-only tools receive probe inputs.
type TaskIDEntropyExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-task-id-entropy", func(rc attack.RuleContext) attack.Executor {
		return NewTaskIDEntropyExecutor(rc)
	})
}

func NewTaskIDEntropyExecutor(r attack.RuleContext) *TaskIDEntropyExecutor {
	return &TaskIDEntropyExecutor{rule: r}
}

const (
	entropySampleTarget = 5
	entropyCallBase     = 30
)

func (e *TaskIDEntropyExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	sessions, sessErr := openSessions(ctx, client, vars.BaseURL)
	if sessErr != nil {
		return nil, sessErr
	}

	var findings []attack.Finding
	modernSeen := false
	taskSurface := false
	lastReason := ""
	pending := map[string]bool{}

	for _, session := range sessions {
		if session.Era != EraModern {
			continue
		}
		modernSeen = true
		if !session.ServerSupports("tools") || !teSupportsTasks(session) {
			continue
		}
		taskSurface = true

		fs, reason, determined, unapproved := e.probeSession(ctx, client, session, opts.MCPInvokeTools)
		findings = append(findings, labelEra(session, fs)...)
		for _, name := range unapproved {
			pending[name] = true
		}
		if determined {
			lastReason = ""
		} else if reason != "" && lastReason == "" {
			lastReason = reason
		}
	}

	if !modernSeen {
		return nil, fmt.Errorf("%w: no MCP %s wire was found at %s",
			attack.ErrInconclusive, modernEraVersion, vars.BaseURL)
	}
	if !taskSurface {
		return nil, fmt.Errorf("%w: no modern wire advertises both tools and the Tasks extension at %s",
			attack.ErrInconclusive, vars.BaseURL)
	}
	if len(findings) == 0 && len(pending) > 0 {
		names := make([]string, 0, len(pending))
		for name := range pending {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w: approve an exact task-capable tool name with --mcp-invoke-tool before task probes: %s",
			attack.ErrInconclusive, strings.Join(names, ", "))
	}
	if len(findings) == 0 && lastReason != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, lastReason)
	}
	return findings, nil
}

func teSupportsTasks(s mcpSession) bool {
	var body struct {
		Result struct {
			Capabilities struct {
				Extensions map[string]json.RawMessage `json:"extensions"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if json.Unmarshal(s.RawInit, &body) != nil {
		return false
	}
	var settings map[string]interface{}
	return json.Unmarshal(body.Result.Capabilities.Extensions["io.modelcontextprotocol/tasks"], &settings) == nil && settings != nil
}

func (e *TaskIDEntropyExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession, approved []string) (findings []attack.Finding, stopReason string, determined bool, unapproved []string) {
	safeTool, ok, pending, listed := teFindSafeTool(ctx, client, session, approved)
	if !listed {
		return nil, "tools/list returned no usable answer on this wire", false, nil
	}
	if !ok {
		if len(pending) > 0 {
			return nil, "", false, pending
		}
		return nil, "no annotated read-only tool was available for Tasks extension probes", false, nil
	}

	var ids []string
	for i := 0; i < entropySampleTarget; i++ {
		requestID := entropyCallBase + i
		resp, err := teCallTaskTool(ctx, client, session, requestID, map[string]interface{}{
			"name":      safeTool.name,
			"arguments": synthesizeArgs(safeTool.schema, "batesian-"+fmt.Sprint(i)),
		}, safeTool.schema)
		if isMCPHeaderMismatch(resp) {
			return nil, fmt.Sprintf("tools/call for %q returned HeaderMismatch; task handles were not fully sampled",
				safeTool.name), false, nil
		}
		if verdict, _ := classifyProbe(resp, err, requestID); verdict != probeAnswered {
			if len(ids) == 0 {
				return nil, fmt.Sprintf("task-augmented tools/call against %q was %s on this wire, so "+
					"no handle could be minted", safeTool.name, scopeVerdictName(verdict)), false, nil
			}
			stopReason = "the next tools/call was " + scopeVerdictName(verdict)
			break
		}
		id := teTaskID(resp.Body, requestID)
		if id == "" {
			if len(ids) == 0 {
				return nil, fmt.Sprintf("tools/call against %q answered but carried no task handle, so "+
					"the handles-per-call premise was never established", safeTool.name), false, nil
			}
			stopReason = "the next tools/call returned no task handle"
			break
		}
		ids = append(ids, id)
	}
	if len(ids) < entropySampleTarget {
		return nil, fmt.Sprintf("only %d of %d task handles were sampled from %q; %s",
			len(ids), entropySampleTarget, safeTool.name, stopReason), false, nil
	}
	return e.teGradeHandles(session.Endpoint, safeTool.name, ids), "", true, nil
}

func teCallTaskTool(ctx context.Context, client *attack.HTTPClient, session mcpSession, id int,
	params, schema map[string]interface{}) (*attack.Response, error) {
	headers, body, err := session.toolRequest(id, params, schema)
	if err != nil {
		return nil, err
	}
	meta := body["params"].(map[string]interface{})["_meta"].(map[string]interface{})
	caps := meta[metaClientCapabilities].(map[string]interface{})
	caps["extensions"] = map[string]interface{}{"io.modelcontextprotocol/tasks": map[string]interface{}{}}
	return client.POST(ctx, session.Endpoint, headers, body)
}

func teTaskID(raw []byte, requestID int) string {
	var body struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  *struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Status     string `json:"status"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil || body.JSONRPC != "2.0" || body.ID != requestID ||
		body.Result == nil || len(body.Error) > 0 || body.Result.ResultType != "task" ||
		body.Result.TaskID == "" || body.Result.Status == "" {
		return ""
	}
	return body.Result.TaskID
}

// teSafeTool is the invoke-capable candidate the rule settles on.
type teSafeTool struct {
	name   string
	schema map[string]interface{}
}

// teFindSafeTool picks an approved, annotated task-capable tool.
func teFindSafeTool(ctx context.Context, client *attack.HTTPClient, s mcpSession, approved []string) (teSafeTool, bool, []string, bool) {
	return teFindSafeToolFiltered(ctx, client, s, approved, false)
}

func teFindSafeToolFiltered(ctx context.Context, client *attack.HTTPClient, s mcpSession, approved []string, requireParamHeader bool) (teSafeTool, bool, []string, bool) {
	resp, err := s.post(ctx, client, 20, "tools/list", nil)
	if verdict, _ := classifyProbe(resp, err, 20); verdict != probeAnswered {
		return teSafeTool{}, false, nil, false
	}
	var body struct {
		Result struct {
			Tools []struct {
				Name        string                 `json:"name"`
				InputSchema map[string]interface{} `json:"inputSchema"`
				Annotations *struct {
					ReadOnlyHint    *bool `json:"readOnlyHint"`
					DestructiveHint *bool `json:"destructiveHint"`
				} `json:"annotations"`
			} `json:"tools"`
			ResultType string `json:"resultType"`
		} `json:"result"`
		JSONRPC string                 `json:"jsonrpc"`
		ID      int                    `json:"id"`
		Error   map[string]interface{} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &body) != nil || body.JSONRPC != "2.0" || body.ID != 20 ||
		body.Result.ResultType != "complete" || body.Error != nil {
		return teSafeTool{}, false, nil, false
	}
	var pending []string
	for _, t := range body.Result.Tools {
		if s.Era == EraModern {
			var bindings []toolHeaderBinding
			if err := collectToolHeaderBindings(t.InputSchema, nil, true, map[string]bool{}, &bindings); err != nil {
				continue
			}
			if requireParamHeader && len(bindings) == 0 {
				continue
			}
			if requireParamHeader {
				headers, err := toolParamHeaders(t.InputSchema, synthesizeArgs(t.InputSchema, "header-control"))
				if err != nil || len(headers) == 0 {
					continue
				}
			}
		}
		if t.Annotations == nil {
			continue
		}
		if !declaresReadOnlyTool(t.Annotations.ReadOnlyHint, t.Annotations.DestructiveHint) {
			continue
		}
		if approvedToolName(t.Name, approved) {
			return teSafeTool{name: t.Name, schema: t.InputSchema}, true, nil, true
		}
		pending = append(pending, t.Name)
	}
	return teSafeTool{}, false, pending, true
}

var teNumericOnly = regexp.MustCompile(`^[0-9]+$`)
var teUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// entropyThresholdBits is the minimum accepted bearer-handle search space.
const entropyThresholdBits = 64

// teGradeHandles reports sequence and entropy failures independently.
func (e *TaskIDEntropyExecutor) teGradeHandles(endpoint, tool string, ids []string) []attack.Finding {
	var findings []attack.Finding

	if step, kind, ok := teConstantStep(ids); ok {
		findings = append(findings, e.sequenceFinding(endpoint, tool, ids, step, kind))
	}

	bits, alphabet, maxLen, variablePositions := teVariableBits(ids)
	if bits < entropyThresholdBits {
		findings = append(findings, e.entropyFinding(endpoint, tool, ids, bits, alphabet, maxLen, variablePositions))
	}
	return findings
}

// teConstantStep recognizes decimal and UUID-shaped counters.
func teConstantStep(ids []string) (string, string, bool) {
	if len(ids) < 3 {
		return "", "", false
	}
	kind, base := "integers", 10
	if teUUID.MatchString(ids[0]) {
		kind, base = "UUID-shaped values", 16
	}
	values := make([]*big.Int, 0, len(ids))
	for _, id := range ids {
		if (base == 10 && !teNumericOnly.MatchString(id)) || (base == 16 && !teUUID.MatchString(id)) {
			return "", "", false
		}
		v, ok := new(big.Int).SetString(strings.ReplaceAll(id, "-", ""), base)
		if !ok {
			return "", "", false
		}
		values = append(values, v)
	}
	step := new(big.Int).Sub(values[1], values[0])
	if step.Sign() == 0 {
		return "", "", false
	}
	for i := 2; i < len(values); i++ {
		if new(big.Int).Sub(values[i], values[i-1]).Cmp(step) != 0 {
			return "", "", false
		}
	}
	return step.String(), kind, true
}

// teVariableBits excludes formatting and other positions fixed in every sample.
func teVariableBits(ids []string) (bits float64, alphabet string, maxLen, variablePositions int) {
	set := map[rune]bool{}
	rows := make([][]rune, len(ids))
	for _, id := range ids {
		if n := len([]rune(id)); n > maxLen {
			maxLen = n
		}
	}
	for i, id := range ids {
		rows[i] = []rune(id)
	}
	for pos := 0; pos < maxLen; pos++ {
		observed := map[rune]bool{}
		for _, row := range rows {
			if pos < len(row) {
				observed[row[pos]] = true
			}
		}
		if len(observed) == 1 {
			allPresent := true
			for _, row := range rows {
				if pos >= len(row) {
					allPresent = false
					break
				}
			}
			if allPresent {
				continue
			}
		}
		variablePositions++
		for r := range observed {
			set[r] = true
		}
	}
	runes := make([]rune, 0, len(set))
	for r := range set {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })
	alphabet = string(runes)
	n := float64(len(set))
	if n <= 1 || maxLen == 0 {
		return 0, alphabet, maxLen, variablePositions
	}
	return float64(variablePositions) * math.Log2(n), alphabet, maxLen, variablePositions
}

func (e *TaskIDEntropyExecutor) sequenceFinding(endpoint, tool string, ids []string, step, kind string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.RiskIndicator,
		Title:      fmt.Sprintf("MCP task handles minted by %q are sequential %s", tool, kind),
		Description: fmt.Sprintf(
			"%d handles requested back to back from %q at %s were %s with a constant "+
				"stride (%s). This suggests a predictable generator; other callers' requests may "+
				"interleave, and task access still requires authorization.",
			len(ids), tool, endpoint, kind, step),
		Evidence: fmt.Sprintf("endpoint: %s\ntool: %s\nhandles sampled: %d\nconstant stride: %s\nhandle values: [redacted]",
			endpoint, tool, len(ids), step),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskIDEntropyExecutor) entropyFinding(endpoint, tool string, ids []string, bits float64, alphabet string, maxLen, variablePositions int) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title: fmt.Sprintf("MCP task handles have a ~%.0f-bit variable-position estimate (below %d bits)",
			bits, entropyThresholdBits),
		Description: fmt.Sprintf(
			"%d handles minted by %q at %s vary in %d of at most %d positions, with %d observed "+
				"characters in those positions. This yields a ~%.0f-bit estimate from the sample. Unseen characters and the "+
				"generator's actual entropy cannot be determined from these samples. Review the "+
				"generator before treating task IDs as unguessable.",
			len(ids), tool, endpoint, variablePositions, maxLen, len(alphabet), bits),
		Evidence: fmt.Sprintf("endpoint: %s\ntool: %s\nhandles sampled: %d\nhandle values: [redacted]\nvariable-position characters: %q\n"+
			"variable positions: %d of %d\nvariable-position estimate: %.1f bits (threshold %d)",
			endpoint, tool, len(ids), alphabet, variablePositions, maxLen, bits, entropyThresholdBits),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
