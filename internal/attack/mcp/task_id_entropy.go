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

// TaskIDEntropyExecutor collects task handles the server mints for task-
// augmented calls and judges whether they meet the tasks extension's own
// unguessability requirement (rule mcp-task-id-entropy-001).
//
// The 2026-07-28 revision moved tasks out of core into
// io.modelcontextprotocol/tasks and deliberately DROPPED context binding:
// its Security Considerations permit a server to treat task ids as bearer
// tokens for stored state, provided they carry enough entropy:
//
//	"Servers MUST generate them with sufficient entropy that a third party
//	 cannot enumerate or guess them."
//
// That MUST is what this rule measures, and it is why the cross-context
// reads mcp-task-idor-001 performs on the core wire would be wrong here: a
// conformant extension-era server answering a guessed handle is doing what
// the spec allows. What is never permitted is an id a third party can guess.
//
// Two measurable failures, both from N samples (spec has no "minimum
// samples"; five distinguish the classes below while keeping cost bounded):
//
//   - Sequential or uniformly stepped numeric handles -> CONFIRMED high.
//     The next id is demonstrated, not estimated.
//   - Sub-threshold alphabet entropy -> CONFIRMED medium. Bits are counted
//     as length * log2(distinct characters) over the observed set, which is
//     an upper bound on real entropy per id; falling under 64 bits violates
//     a bearer-token MUST even before prediction. Exotic-but-fine formats
//     (UUID hex at ~122 bits, nanoid at ~120) clear it comfortably.
//
// SAFETY mirrors mcp-task-idor-001 exactly: only tools whose annotations
// declare readOnlyHint true or destructiveHint false and that declare
// taskSupport optional/required are invoked; their arguments are inert.
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
	client := attack.NewUnauthHTTPClient(opts, vars)

	sessions, sessErr := openSessions(ctx, client, vars.BaseURL)
	if sessErr != nil {
		return nil, sessErr
	}

	var findings []attack.Finding
	capabilityKnown := false
	lastReason := ""

	for _, session := range sessions {
		if !session.ServerSupports("tools") {
			continue // no tool surface on this wire: nothing mints handles here
		}
		capabilityKnown = true

		fs, reason, determined := e.probeSession(ctx, client, session)
		findings = append(findings, labelEra(session, fs)...)
		if determined {
			lastReason = ""
		} else if reason != "" && lastReason == "" {
			lastReason = reason
		}
	}

	if !capabilityKnown {
		return nil, fmt.Errorf("%w: no served wire advertises the tools capability at %s",
			attack.ErrInconclusive, vars.BaseURL)
	}
	if len(findings) == 0 && lastReason != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, lastReason)
	}
	return findings, nil
}

func (e *TaskIDEntropyExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, stopReason string, determined bool) {
	safeTool, ok := teFindSafeTool(ctx, client, session)
	if !ok {
		// Consistent with mcp-task-idor-001: nothing declared safe to invoke,
		// so no handle could exist without breaking that gate first.
		return nil, "", true
	}

	var ids []string
	for i := 0; i < entropySampleTarget; i++ {
		resp, err := session.post(ctx, client, entropyCallBase+i, "tools/call", map[string]interface{}{
			"name":      safeTool.name,
			"arguments": synthesizeArgs(safeTool.schema, "batesian-"+fmt.Sprint(i)),
			"task":      map[string]interface{}{"ttl": 60000},
		})
		if verdict, _ := classifyProbe(resp, err); verdict != probeAnswered {
			if len(ids) == 0 {
				return nil, fmt.Sprintf("task-augmented tools/call against %q was %s on this wire, so "+
					"no handle could be minted", safeTool.name, scopeVerdictName(verdict)), false
			}
			break // mid-collection refusal: judge what was collected
		}
		var body struct {
			Result struct {
				Task struct {
					TaskID string `json:"taskId"`
				} `json:"task"`
			} `json:"result"`
			Error map[string]interface{} `json:"error"`
		}
		if json.Unmarshal(resp.Body, &body) != nil || body.Error != nil || body.Result.Task.TaskID == "" {
			if len(ids) == 0 {
				return nil, fmt.Sprintf("tools/call against %q answered but carried no task handle, so "+
					"the handles-per-call premise was never established", safeTool.name), false
			}
			break
		}
		ids = append(ids, body.Result.Task.TaskID)
	}
	if len(ids) < 2 {
		return nil, fmt.Sprintf("only %d task handle(s) were minted by %q on this wire, so no pattern "+
			"could be distinguished from coincidence", len(ids), safeTool.name), false
	}
	return e.teGradeHandles(session.Endpoint, safeTool.name, ids), "", true
}

// teSafeTool is the invoke-capable candidate the rule settles on.
type teSafeTool struct {
	name   string
	schema map[string]interface{}
}

// teFindSafeTool picks the first annotated read-only/non-destructive tool
// whose execution.taskSupport marks it task-augmentable.
func teFindSafeTool(ctx context.Context, client *attack.HTTPClient, s mcpSession) (teSafeTool, bool) {
	resp, err := s.post(ctx, client, 20, "tools/list", nil)
	if verdict, _ := classifyProbe(resp, err); verdict != probeAnswered {
		return teSafeTool{}, false
	}
	var body struct {
		Result struct {
			Tools []struct {
				Name        string                 `json:"name"`
				InputSchema map[string]interface{} `json:"inputSchema"`
				Execution   struct {
					TaskSupport string `json:"taskSupport"`
				} `json:"execution"`
				Annotations *struct {
					ReadOnlyHint    *bool `json:"readOnlyHint"`
					DestructiveHint *bool `json:"destructiveHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(resp.Body, &body) != nil {
		return teSafeTool{}, false
	}
	for _, t := range body.Result.Tools {
		if t.Execution.TaskSupport != "optional" && t.Execution.TaskSupport != "required" {
			continue
		}
		if t.Annotations == nil {
			continue
		}
		readOnly := t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
		nonDestructive := t.Annotations.DestructiveHint != nil && !*t.Annotations.DestructiveHint
		if !readOnly && !nonDestructive {
			continue
		}
		return teSafeTool{name: t.Name, schema: t.InputSchema}, true
	}
	return teSafeTool{}, false
}

var teNumericOnly = regexp.MustCompile(`^[0-9]+$`)

// entropyThresholdBits is where "a third party cannot guess" becomes
// measurable: at or above 64 bits, brute enumeration is out of reach of any
// realistic window; below it, offline guessing is a spreadsheet exercise.
const entropyThresholdBits = 64

// teGradeHandles runs the two analyses and returns every failure found. The
// checks are independent: a timestamp-stamped id with a short random tail
// clears the sequence check but fails the alphabet bar, and both readings
// belong in one report rather than short-circuiting each other.
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

// teAlphabetBits upper-bounds per-id entropy as length * log2(alphabet),
// using the longest observed id and every distinct character seen anywhere.
// This is deliberately generous to the server: a server that adds hidden
// randomness beyond what any sample shows only makes real entropy higher.
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
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP task handles minted by %q are sequential integers", tool),
		Description: fmt.Sprintf(
			"%d handles requested back to back from %q at %s came back as integers with a constant "+
				"stride (%s). Every subsequent handle is predictable before it is issued. The tasks "+
				"extension permits servers to treat these ids as bearer tokens for stored state, which "+
				"makes a predictable handle an authentication bypass of that scheme: anyone who sees one "+
				"id can read, poll or cancel another caller's work.",
			len(ids), tool, endpoint, teJoinSteps(ids)),
		Evidence: fmt.Sprintf("endpoint: %s\ntool: %s\nhandles: %s\nconstant stride: %d\npredicted next handle: %s",
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
		Confidence: attack.ConfirmedExploit,
		Title: fmt.Sprintf("MCP task handles carry ~%.0f bits of alphabet entropy (below the %d-bit bar)",
			bits, entropyThresholdBits),
		Description: fmt.Sprintf(
			"%d handles minted by %q at %s use only %d distinct characters over %d positions, giving "+
				"~%.0f bits of search space per handle. The tasks extension lets servers treat these ids "+
				"as bearer tokens for stored state and requires generation with sufficient entropy that a "+
				"third party cannot guess them; this estimate counts only characters the samples reveal, so "+
				"it is generous to the server - and it still falls under the bar. IDs readable once out of a "+
				"log or trace should not also be enumerable offline.",
			len(ids), tool, endpoint, len(alphabet), maxLen, bits),
		Evidence: fmt.Sprintf("endpoint: %s\ntool: %s\nhandles: %s\ndistinct characters: %q\n"+
			"longest handle: %d positions\nestimated entropy: %.1f bits (threshold %d)",
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
