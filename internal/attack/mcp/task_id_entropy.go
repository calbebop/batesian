package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
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
			break // mid-collection refusal: judge what was collected
		}
		id := teTaskID(resp.Body, requestID)
		if id == "" {
			if len(ids) == 0 {
				return nil, fmt.Sprintf("tools/call against %q answered but carried no task handle, so "+
					"the handles-per-call premise was never established", safeTool.name), false, nil
			}
			break
		}
		ids = append(ids, id)
	}
	if len(ids) < 2 {
		return nil, fmt.Sprintf("only %d task handle(s) were minted by %q on this wire, so no pattern "+
			"could be distinguished from coincidence", len(ids), safeTool.name), false, nil
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
			if _, err := toolParamHeaders(t.InputSchema, nil); err != nil {
				continue
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

// entropyThresholdBits is the minimum accepted bearer-handle search space.
const entropyThresholdBits = 64

// teGradeHandles reports sequence and entropy failures independently.
func (e *TaskIDEntropyExecutor) teGradeHandles(endpoint, tool string, ids []string) []attack.Finding {
	var findings []attack.Finding

	allNumeric := true
	for _, id := range ids {
		if !teNumericOnly.MatchString(id) {
			allNumeric = false
			break
		}
	}
	if allNumeric {
		if step, ok := teConstantStep(ids); ok {
			findings = append(findings, e.sequenceFinding(endpoint, tool, ids, step))
		}
	}

	bits, alphabet, maxLen := teAlphabetBits(ids)
	if bits < entropyThresholdBits {
		findings = append(findings, e.entropyFinding(endpoint, tool, ids, bits, alphabet, maxLen))
	}
	return findings
}

// teConstantStep reports whether every consecutive delta between mints is
// identical and non-zero - the signature of a counter, whatever its stride.
func teConstantStep(ids []string) (int64, bool) {
	values := make([]int64, 0, len(ids))
	for _, id := range ids {
		v, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return 0, false
		}
		values = append(values, v)
	}
	step := values[1] - values[0]
	if step == 0 {
		return 0, false // repeated ids are a different defect
	}
	for i := 2; i < len(values); i++ {
		if values[i]-values[i-1] != step {
			return 0, false
		}
	}
	return step, true
}

// teAlphabetBits estimates search space from the sampled characters.
func teAlphabetBits(ids []string) (bits float64, alphabet string, maxLen int) {
	set := map[rune]bool{}
	maxLen = 0
	for _, id := range ids {
		if len(id) > maxLen {
			maxLen = len(id)
		}
		for _, r := range id {
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
		return 0, alphabet, maxLen
	}
	return float64(maxLen) * math.Log2(n), alphabet, maxLen
}

func (e *TaskIDEntropyExecutor) sequenceFinding(endpoint, tool string, ids []string, step int64) attack.Finding {
	predicted := teNext(ids[len(ids)-1], step)
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.RiskIndicator,
		Title:      fmt.Sprintf("MCP task handles minted by %q are sequential integers", tool),
		Description: fmt.Sprintf(
			"%d handles requested back to back from %q at %s were integers with a constant "+
				"stride (%s). This suggests a predictable generator; other callers' requests may "+
				"interleave, and task access still requires authorization.",
			len(ids), tool, endpoint, teJoinSteps(ids)),
		Evidence: fmt.Sprintf("endpoint: %s\ntool: %s\nhandles: %s\nconstant stride: %d\npredicted next handle if uninterrupted: %s",
			endpoint, tool, strings.Join(ids, ", "), step, predicted),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskIDEntropyExecutor) entropyFinding(endpoint, tool string, ids []string, bits float64, alphabet string, maxLen int) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title: fmt.Sprintf("MCP task handles have a ~%.0f-bit observed-alphabet estimate (below %d bits)",
			bits, entropyThresholdBits),
		Description: fmt.Sprintf(
			"%d handles minted by %q at %s contain %d distinct observed characters over at most %d "+
				"positions, yielding a ~%.0f-bit search-space estimate. Unseen characters and the "+
				"generator's actual entropy cannot be determined from these samples. Review the "+
				"generator before treating task IDs as unguessable.",
			len(ids), tool, endpoint, len(alphabet), maxLen, bits),
		Evidence: fmt.Sprintf("endpoint: %s\ntool: %s\nhandles: %s\ndistinct characters: %q\n"+
			"longest handle: %d positions\nobserved-alphabet estimate: %.1f bits (threshold %d)",
			endpoint, tool, strings.Join(ids, ", "), alphabet, maxLen, bits, entropyThresholdBits),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func teNext(last string, step int64) string {
	v, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return "?"
	}
	return strconv.FormatInt(v+step, 10)
}

func teJoinSteps(ids []string) string {
	var sb strings.Builder
	for i, id := range ids {
		if i > 0 {
			a, _ := strconv.ParseInt(ids[i-1], 10, 64)
			b, _ := strconv.ParseInt(id, 10, 64)
			fmt.Fprintf(&sb, " (%+d) ", b-a)
		}
		sb.WriteString(id)
	}
	return sb.String()
}
