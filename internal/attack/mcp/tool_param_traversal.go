package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ToolParamTraversalExecutor probes whether read-only MCP tools validate
// filesystem-style path arguments against escaping their intended root
// (rule mcp-tool-param-traversal-001).
//
// The failure: a tool joins its caller-supplied path onto an internal root and
// never checks where the result landed, so "../.." walks the caller out of the
// root and onto any file the server process can read. It is the defect class
// behind CVE-2025-53109 (Filesystem EscapeRoute) and CVE-2026-27825
// (mcp-atlassian), and it lives in ordinary tool arguments rather than in the
// transport or the authorization layer the other rules here cover.
//
// SAFETY. This rule invokes real tools by name, which only mcp-task-idor-001
// also does, so it inherits that rule's gate and adds one of its own:
//
//   - Only tools whose annotations declare readOnlyHint true (or explicitly
//     destructiveHint false) are dispatched at all. An unannotated tool is
//     never touched.
//   - Every probe reads a file that does not exist. The canary name is unique
//     per run, so there is nothing to find whatever the server resolves.
//
// The oracle is therefore the error text alone, which is enough. A server that
// resolves the join before opening leaks where it looked - a Node ENOENT names
// the resolved absolute path - and comparing that against a no-traversal
// baseline separates "looked inside the sandbox" from "walked out of it". No
// byte of file content is ever returned to prove the bug; the resolution is the
// proof.
type ToolParamTraversalExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-tool-param-traversal", func(rc attack.RuleContext) attack.Executor { return NewToolParamTraversalExecutor(rc) })
}

func NewToolParamTraversalExecutor(r attack.RuleContext) *ToolParamTraversalExecutor {
	return &ToolParamTraversalExecutor{rule: r}
}

// traversalCaps bounds how many tools one run will drive. Each candidate costs
// three calls (baseline plus two traversals), so the cap keeps a scan's cost a
// function of the rule rather than of the target's tool count. The number of
// candidates seen against the cap is reported when nothing fired.
const traversalCaps = 8

func (e *ToolParamTraversalExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Credentials are attached when supplied: the question is whether paths are
	// validated, not whether the surface authenticates, so a gated server should
	// be testable rather than skipped.
	client := attack.NewHTTPClient(opts, vars)

	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session, vars.RandID)
	})
}

// probeSession runs the rule on one wire. determined follows the package
// convention: a listing that produced no protocol-level verdict proves nothing,
// while a listing that was read settles the session either way.
func (e *ToolParamTraversalExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession, randID string) ([]attack.Finding, bool) {
	if !session.ServerSupports("tools") {
		return nil, true
	}

	listResp, err := session.post(ctx, client, 3, "tools/list", nil)
	if verdict, _ := classifyProbe(listResp, err); verdict != probeAnswered {
		return nil, verdict == probeRejected
	}
	var listBody struct {
		Result struct {
			Tools []traversalTool `json:"tools"`
		} `json:"result"`
		Error map[string]interface{} `json:"error"`
	}
	if json.Unmarshal(listResp.Body, &listBody) != nil || listBody.Error != nil {
		return nil, true
	}

	candidates := traversalCandidates(listBody.Result.Tools)
	if len(candidates) == 0 {
		// Nothing declared itself safe to invoke with a path argument. The same
		// convention as mcp-task-idor-001 applies: the rule does not dispatch
		// unannotated tools, and a server whose safe tools take no paths has no
		// surface this rule can reach.
		return nil, true
	}

	var findings []attack.Finding
	driven := 0
	for _, cand := range candidates {
		if driven >= traversalCaps {
			break
		}
		driven++
		if f := e.probeTool(ctx, client, session, randID, cand); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, true
}

// traversalTool is the slice of a tools/list entry this rule needs.
type traversalTool struct {
	Name        string `json:"name"`
	Annotations *struct {
		ReadOnlyHint    *bool `json:"readOnlyHint"`
		DestructiveHint *bool `json:"destructiveHint"`
	} `json:"annotations"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// traversalCandidate pairs a tool the rule may invoke with the path-like
// string parameter it will probe.
type traversalCandidate struct {
	tool   string
	param  string
	others map[string]interface{}
}

// pathParamNames are the parameter names treated as carrying a filesystem path:
// anything naming a path explicitly, plus the short file/directory words that
// appear on their own. A parameter merely mentioning "file" inside a longer
// name ("profile") does not match; "file_path" does via the suffix check.
var pathParamNames = map[string]bool{
	"file": true, "filename": true, "filepath": true,
	"dir": true, "directory": true, "folder": true,
	"location": true, "attachment": true, "note": true, "document": true,
}

// isPathParam reports whether a schema property name carries a filesystem path.
func isPathParam(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "path") {
		return true
	}
	return pathParamNames[lower]
}

// traversalCandidates selects tools this rule may drive: annotated read-only or
// explicitly non-destructive (the mcp-task-idor-001 predicate), with at least
// one path-like string parameter in their schema.
func traversalCandidates(tools []traversalTool) []traversalCandidate {
	var out []traversalCandidate
	for _, t := range tools {
		if t.Annotations == nil {
			continue // unannotated: assume it may be destructive
		}
		readOnly := t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
		nonDestructive := t.Annotations.DestructiveHint != nil && !*t.Annotations.DestructiveHint
		if !readOnly && !nonDestructive {
			continue
		}
		props, _ := t.InputSchema["properties"].(map[string]interface{})
		required := requiredParams(t.InputSchema)
		for name, raw := range props {
			spec, _ := raw.(map[string]interface{})
			if spec["type"] != "string" || !isPathParam(name) {
				continue
			}
			out = append(out, traversalCandidate{tool: t.Name, param: name, others: inertArgs(props, name, required)})
			break // one param per tool is enough to characterise its validation
		}
	}
	return out
}

// requiredParams lists a schema's required property names.
func requiredParams(schema map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	req, _ := schema["required"].([]interface{})
	for _, r := range req {
		if s, ok := r.(string); ok {
			out[s] = true
		}
	}
	return out
}

// inertArgs fills the tool's other properties with values of the declared
// type, leaving only the path parameter for the probe to set. Optional
// parameters are omitted entirely to keep the request minimal.
func inertArgs(props map[string]interface{}, skip string, required map[string]bool) map[string]interface{} {
	args := map[string]interface{}{}
	for name, raw := range props {
		if name == skip || !required[name] {
			continue
		}
		spec, _ := raw.(map[string]interface{})
		switch spec["type"] {
		case "string":
			args[name] = ""
		case "number", "integer":
			args[name] = 1
		case "boolean":
			args[name] = false
		case "array":
			args[name] = []interface{}{}
		case "object":
			args[name] = map[string]interface{}{}
		}
	}
	return args
}

// callTool issues one tools/call and returns the response text the oracle
// reads: the JSON-RPC error message when the envelope carries one, otherwise
// the textual content of the result. Both shapes occur in practice, since many
// servers report tool failures as isError results rather than protocol errors.
func (e *ToolParamTraversalExecutor) callTool(ctx context.Context, client *attack.HTTPClient, session mcpSession, id int, tool, param, value string, others map[string]interface{}) string {
	args := map[string]interface{}{param: value}
	for k, v := range others {
		args[k] = v
	}
	resp, err := session.post(ctx, client, id, "tools/call", map[string]interface{}{
		"name":      tool,
		"arguments": args,
	})
	if err != nil {
		return "" // transport failure: no text to judge
	}
	var body struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &body) != nil {
		return ""
	}
	if body.Error.Message != "" {
		return body.Error.Message
	}
	var sb strings.Builder
	for _, c := range body.Result.Content {
		sb.WriteString(c.Text)
		sb.WriteString("\n")
	}
	return sb.String()
}

// probeTool drives baseline plus two traversals against one tool's path
// parameter and grades what came back. A nil return means the tool validated
// its paths, refused them without disclosing resolutions, or could not be
// characterised; none of those is a finding.
func (e *ToolParamTraversalExecutor) probeTool(ctx context.Context, client *attack.HTTPClient, session mcpSession, randID string, cand traversalCandidate) *attack.Finding {
	canary := "batesian-" + randID

	baselineText := e.callTool(ctx, client, session, 10, cand.tool, cand.param, canary, cand.others)
	baselinePath := leakedPath(baselineText, canary)

	deepPrefix := strings.Repeat("../", 12)
	winPrefix := strings.Repeat("..\\", 12)
	traversalText := e.callTool(ctx, client, session, 11, cand.tool, cand.param, "/"+deepPrefix+canary, cand.others)
	backslashText := e.callTool(ctx, client, session, 12, cand.tool, cand.param, winPrefix+canary, cand.others)

	for _, probe := range []struct{ label, text string }{
		{"absolute + forward-slash traversal", traversalText},
		{"backslash traversal", backslashText},
	} {
		path := leakedPath(probe.text, canary)
		if !resolvedAbsolute(path) {
			// Either nothing was disclosed, or the server merely echoed the
			// caller's input back with its dot-dot segments intact. An echo is
			// not resolution evidence: a chatty read-only tool would otherwise
			// be accused of traversal for repeating what it was sent.
			continue
		}
		if escapedOutsideBaseline(path, baselinePath) {
			return e.finding(session.Endpoint, cand, probe.label, baselinePath, path)
		}
	}
	return nil
}

// resolvedAbsolute reports whether p is an absolute path with its traversal
// segments gone - the signature of a server-side resolution rather than an
// echo of the request.
func resolvedAbsolute(p string) bool {
	if p == "" || strings.Contains(p, "..") {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// leakedPath extracts the filesystem path the server looked for when it named
// the canary, returning empty when the canary was not mentioned. The canary is
// unique per run, so naming it means the server echoed its own resolution -
// exactly the disclosure this oracle reads.
func leakedPath(text, canary string) string {
	if text == "" || !strings.Contains(text, canary) {
		return ""
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, canary) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "- ")
		// Strip common error prefixes down toward the path itself.
		for _, marker := range []string{
			"ENOENT: no such file or directory, open '",
			"no such file or directory: ",
			"errno=2",
			"'",
		} {
			trimmed = strings.ReplaceAll(trimmed, marker, "")
		}
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" {
			continue
		}
		if looksLikePath(trimmed) {
			return trimmed
		}
	}
	return ""
}

// looksLikePath reports whether s resembles a filesystem path: absolute POSIX,
// absolute Windows, or a relative path still carrying traversal segments.
func looksLikePath(s string) bool {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\") {
		return true
	}
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	return strings.Contains(s, "../") || strings.Contains(s, "..\\")
}

// escapedOutsideBaseline decides whether the traversal probe resolved the
// canary somewhere the baseline did not: a different parent directory that is
// not beneath the baseline's own directory. A sandboxed server looks up both
// under the same root; an escaped one lands elsewhere entirely. The traversal
// path has already passed resolvedAbsolute, so the comparison runs on where
// the server actually looked.
func escapedOutsideBaseline(traversalPath, baselinePath string) bool {
	if baselinePath == "" {
		// No baseline resolution to compare against. Without it the rule cannot
		// name the root the tool was supposed to stay inside, so it declines to
		// report rather than guess containment from one lookup.
		return false
	}
	baseDir := parentDir(baselinePath)
	travDir := parentDir(traversalPath)
	if travDir == baseDir {
		return false // landed in the same directory: joined and contained
	}
	// Still contained when the traversal directory sits beneath the baseline's
	// directory tree (the sandbox swallowed some or all of the climb).
	if strings.HasPrefix(travDir, baseDir+"/") || strings.HasPrefix(travDir, baseDir+"\\") {
		return false
	}
	return true
}

// parentDir returns the directory portion of a path in either slash style.
func parentDir(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i > 0 {
		return p[:i]
	}
	return p
}

func (e *ToolParamTraversalExecutor) finding(endpoint string, cand traversalCandidate, how, baselinePath, traversalPath string) *attack.Finding {
	return &attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP tool %q resolves %q outside its sandbox (path traversal)", cand.tool, cand.param),
		Description: fmt.Sprintf(
			"tools/call for %q at %s resolved %q to %s, and the server's own error disclosed a lookup "+
				"outside the directory the no-traversal control resolved to (%s). Path validation is "+
				"absent, so any caller of this tool can walk out of its intended root and read files the "+
				"server process can access. No file content was returned during the probe: both lookups "+
				"named files that do not exist, and the escape is proven by where the server said it looked.",
			cand.tool, endpoint, cand.param, how, baselinePath),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntool: %s\nparameter: %s\nbaseline (no traversal) resolved to: %s\n%s resolved to: %s",
			endpoint, cand.tool, cand.param, baselinePath, how, traversalPath),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
