package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

const filesystemInfoTool = "get_file_info"

// FilesystemSuffixExecutor checks trailing-character path validation.
type FilesystemSuffixExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-filesystem-suffix", func(rc attack.RuleContext) attack.Executor {
		return &FilesystemSuffixExecutor{rule: rc}
	})
}

func NewFilesystemSuffixExecutor(rc attack.RuleContext) *FilesystemSuffixExecutor {
	return &FilesystemSuffixExecutor{rule: rc}
}

func (e *FilesystemSuffixExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	probe := opts.MCPFilesystemSuffixProbe
	if probe == nil || !validFilesystemSuffixRoot(probe.AllowedDirectory) {
		return nil, fmt.Errorf("%w: configure mcp_filesystem_suffix_probe with a disposable POSIX allowed_directory",
			attack.ErrInconclusive)
	}
	if !approvedToolName(filesystemInfoTool, opts.MCPInvokeTools) {
		return nil, fmt.Errorf("%w: approve get_file_info with --mcp-invoke-tool before filesystem suffix probes",
			attack.ErrInconclusive)
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	var incomplete []string
	findings, err := runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		f, determined, reason := e.probeSession(ctx, client, session, probe.AllowedDirectory, vars.RandID)
		if reason != "" {
			incomplete = append(incomplete, session.Era.String()+": "+reason)
		}
		return f, determined
	})
	if len(incomplete) > 0 {
		return findings, fmt.Errorf("%w: filesystem suffix probe incomplete: %s",
			attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return findings, err
}

func validFilesystemSuffixRoot(root string) bool {
	return strings.HasPrefix(root, "/") && root != "/" && path.Clean(root) == root &&
		strings.TrimSpace(root) == root && !strings.ContainsAny(root, "'\"\\\r\n\t")
}

func (e *FilesystemSuffixExecutor) probeSession(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, root, nonce string) ([]attack.Finding, bool, string) {
	if !session.ServerSupports("tools") {
		return nil, false, "tools are not advertised"
	}
	listed, ok := listToolPages(ctx, client, session, 3)
	if !ok {
		return nil, false, "tool listing was unavailable or incomplete"
	}
	var selected *traversalTool
	for _, raw := range listed {
		var tool traversalTool
		if json.Unmarshal(raw, &tool) != nil {
			return nil, false, "tool listing was malformed"
		}
		if tool.Name != filesystemInfoTool {
			continue
		}
		if selected != nil {
			return nil, false, "get_file_info appeared more than once"
		}
		selected = &tool
	}
	if selected == nil || selected.Annotations == nil ||
		!declaresReadOnlyTool(selected.Annotations.ReadOnlyHint, selected.Annotations.DestructiveHint) {
		return nil, false, "get_file_info was absent or not declared read-only"
	}
	required := requiredParams(selected.InputSchema)
	props, _ := selected.InputSchema["properties"].(map[string]interface{})
	pathSpec, _ := props["path"].(map[string]interface{})
	if len(required) != 1 || !required["path"] || pathSpec["type"] != "string" {
		return nil, false, "get_file_info did not have a path-only required input"
	}
	if session.Era == EraModern {
		if _, err := toolParamHeaders(selected.InputSchema, nil); err != nil {
			return nil, false, "get_file_info parameter headers were invalid"
		}
	}
	candidate := traversalCandidate{tool: filesystemInfoTool, param: "path", schema: selected.InputSchema}
	inside := root + "/batesian-" + nonce
	outside := root + "-batesian-" + nonce
	insideText, reason, _, toolError := callPathTool(ctx, client, session, 20, candidate, inside)
	if reason != "" || !toolError || !missingPathReply(insideText, inside) {
		return nil, false, "the inside missing-path control did not resolve"
	}
	outsideText, reason, _, outsideError := callPathTool(ctx, client, session, 21, candidate, outside)
	if !pathDenied(outsideText, reason, outsideError) {
		return nil, false, "the ordinary outside path was not explicitly denied"
	}
	var unresolved []string
	for i, suffix := range []struct{ label, value string }{
		{"single quote", "'"}, {"double quote", "\""}, {"trailing space", " "},
	} {
		candidatePath := root + suffix.value
		text, reason, _, toolError := callPathTool(ctx, client, session, 22+i, candidate, candidatePath)
		if reason == "" && toolError && missingPathReply(text, candidatePath) && !pathDenied(text, reason, toolError) {
			return []attack.Finding{e.finding(session.Endpoint, suffix.label)}, true, ""
		}
		if !pathDenied(text, reason, toolError) {
			unresolved = append(unresolved, suffix.label)
		}
	}
	if len(unresolved) > 0 {
		return nil, false, "suffix responses were ambiguous for " + strings.Join(unresolved, ", ")
	}
	return nil, true, ""
}

func missingPathReply(text, expected string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(text, expected) &&
		(strings.Contains(lower, "enoent") || strings.Contains(lower, "no such file or directory"))
}

func pathDenied(text, reason string, toolError bool) bool {
	lower := strings.ToLower(text)
	return reason == "HTTP 403" || toolError &&
		(strings.Contains(lower, "access denied") || strings.Contains(lower, "outside allowed directories"))
}

func (e *FilesystemSuffixExecutor) finding(endpoint, suffix string) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "medium", Confidence: attack.RiskIndicator,
		Title:       "MCP filesystem tool resolves a suffixed path outside its allowed directory",
		Description: fmt.Sprintf("The approved metadata tool resolved a %s suffixed sibling after denying an ordinary outside path. This suggests the validation and filesystem paths differ. Verify the installed filesystem server version and boundary policy.", suffix),
		Evidence:    fmt.Sprintf("endpoint: %s\ntool: get_file_info\ninside missing-path control: resolved\nordinary outside path: denied\n%s suffixed sibling: missing-path response\npaths and response text omitted", endpoint, suffix),
		Remediation: e.rule.Remediation, TargetURL: endpoint,
	}
}
