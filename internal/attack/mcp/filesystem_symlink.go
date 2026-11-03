package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

const (
	filesystemSizeTool = "list_directory_with_sizes"
	filesystemLinkTool = "get_file_info"
)

var filesystemListedSize = regexp.MustCompile(`^(?:0|[1-9][0-9]*) B$|^[0-9]+\.[0-9]{2} (?:KB|MB|GB|TB)$`)

type FilesystemSymlinkExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-filesystem-symlink", func(rc attack.RuleContext) attack.Executor {
		return &FilesystemSymlinkExecutor{rule: rc}
	})
}

func NewFilesystemSymlinkExecutor(rc attack.RuleContext) *FilesystemSymlinkExecutor {
	return &FilesystemSymlinkExecutor{rule: rc}
}

func validFilesystemSymlinkProbe(p *attack.MCPFilesystemSymlinkProbe) bool {
	if p == nil || !validFilesystemSuffixRoot(p.AllowedDirectory) || !validFilesystemSuffixRoot(p.OutsidePath) ||
		p.OutsidePath == p.AllowedDirectory || strings.HasPrefix(p.OutsidePath, p.AllowedDirectory+"/") ||
		p.OutsideSizeBytes < 1024 || p.OutsideSizeBytes > 65536 || p.OutsideSizeBytes%512 != 0 {
		return false
	}
	name := p.LinkName
	return name != "" && name != "." && name != ".." && len(name) <= 128 &&
		strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == ""
}

func (e *FilesystemSymlinkExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	probe := opts.MCPFilesystemSymlinkProbe
	if !validFilesystemSymlinkProbe(probe) {
		return nil, fmt.Errorf("%w: configure mcp_filesystem_symlink_probe with a disposable link and outside file",
			attack.ErrInconclusive)
	}
	if !approvedToolName(filesystemLinkTool, opts.MCPInvokeTools) ||
		!approvedToolName(filesystemSizeTool, opts.MCPInvokeTools) {
		return nil, fmt.Errorf("%w: approve get_file_info and list_directory_with_sizes with --mcp-invoke-tool",
			attack.ErrInconclusive)
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	var incomplete []string
	findings, err := runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		f, determined, reason := e.probeSession(ctx, client, session, probe)
		if reason != "" {
			incomplete = append(incomplete, session.Era.String()+": "+reason)
		}
		return f, determined
	})
	if len(incomplete) > 0 {
		return findings, fmt.Errorf("%w: filesystem symlink probe incomplete: %s",
			attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return findings, err
}

func (e *FilesystemSymlinkExecutor) probeSession(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, probe *attack.MCPFilesystemSymlinkProbe) ([]attack.Finding, bool, string) {
	if !session.ServerSupports("tools") {
		return nil, false, "tools are not advertised"
	}
	listed, ok := listToolPages(ctx, client, session, 3)
	if !ok {
		return nil, false, "tool listing was unavailable or incomplete"
	}
	selected := map[string]traversalCandidate{}
	for _, raw := range listed {
		var tool traversalTool
		if json.Unmarshal(raw, &tool) != nil || tool.Name == "" {
			return nil, false, "tool listing was malformed"
		}
		if tool.Name != filesystemLinkTool && tool.Name != filesystemSizeTool {
			continue
		}
		if _, duplicate := selected[tool.Name]; duplicate {
			return nil, false, "a required metadata tool appeared more than once"
		}
		candidate, valid := filesystemMetadataCandidate(tool, session.Era == EraModern)
		if !valid {
			return nil, false, "a required metadata tool was not declared read-only with a path-only required input"
		}
		selected[tool.Name] = candidate
	}
	linkTool, linkOK := selected[filesystemLinkTool]
	sizeTool, sizeOK := selected[filesystemSizeTool]
	if !linkOK || !sizeOK {
		return nil, false, "required metadata tools were absent"
	}
	insideText, insideReason, _, insideError := callPathTool(ctx, client, session, 20, linkTool, probe.AllowedDirectory)
	if insideReason != "" || insideError || strings.TrimSpace(insideText) == "" {
		return nil, false, "inside metadata control was unavailable"
	}
	outsideText, outsideReason, _, outsideError := callPathTool(ctx, client, session, 21, linkTool, probe.OutsidePath)
	if !pathDenied(outsideText, outsideReason, outsideError) {
		return nil, false, "outside metadata access was not explicitly denied"
	}
	linkPath := probe.AllowedDirectory + "/" + probe.LinkName
	linkText, linkReason, _, linkError := callPathTool(ctx, client, session, 22, linkTool, linkPath)
	if !pathDenied(linkText, linkReason, linkError) {
		return nil, false, "direct link metadata access was not explicitly denied"
	}
	listing, reason, _, toolError := callPathTool(ctx, client, session, 23, sizeTool, probe.AllowedDirectory)
	if reason != "" || toolError {
		return nil, false, "directory size listing was unavailable"
	}
	observed, ok := filesystemLinkSize(listing, probe.LinkName)
	if !ok {
		return nil, false, "the link had no unambiguous file-size entry"
	}
	expected := fmt.Sprintf("%.2f KB", float64(probe.OutsideSizeBytes)/1024)
	if observed != expected {
		return nil, true, ""
	}
	return []attack.Finding{e.finding(session.Endpoint)}, true, ""
}

func filesystemMetadataCandidate(tool traversalTool, modern bool) (traversalCandidate, bool) {
	if tool.Annotations == nil || !declaresReadOnlyTool(tool.Annotations.ReadOnlyHint, tool.Annotations.DestructiveHint) ||
		tool.InputSchema == nil {
		return traversalCandidate{}, false
	}
	required := requiredParams(tool.InputSchema)
	props, _ := tool.InputSchema["properties"].(map[string]interface{})
	pathSpec, _ := props["path"].(map[string]interface{})
	if len(required) != 1 || !required["path"] || pathSpec["type"] != "string" {
		return traversalCandidate{}, false
	}
	if modern {
		if _, err := toolParamHeaders(tool.InputSchema, nil); err != nil {
			return traversalCandidate{}, false
		}
	}
	return traversalCandidate{tool: tool.Name, param: "path", schema: tool.InputSchema}, true
}

func filesystemLinkSize(listing, name string) (string, bool) {
	prefix := "[FILE] " + name + " "
	var size string
	for _, line := range strings.Split(listing, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if size != "" {
			return "", false
		}
		size = strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if !filesystemListedSize.MatchString(size) {
			return "", false
		}
	}
	return size, size != ""
}

func (e *FilesystemSymlinkExecutor) finding(endpoint string) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "low", Confidence: attack.RiskIndicator,
		Title:       "MCP directory listing exposes an outside link target's size",
		Description: "The approved metadata tools denied direct access to the outside file and its link, but the directory listing reported the operator's known outside file size for that link. This indicates metadata exposure across the allowed-directory boundary. Verify the fixture and installed server version.",
		Evidence:    fmt.Sprintf("endpoint: %s\ninside metadata control: available\noutside metadata control: denied\nlink metadata control: denied\nlisting link size: matched outside fixture\npaths, size, and response text omitted", endpoint),
		Remediation: e.rule.Remediation, TargetURL: endpoint,
	}
}
