package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

const (
	skillsExtension   = "io.modelcontextprotocol/skills"
	appsExtension     = "io.modelcontextprotocol/ui"
	appsMIME          = "text/html;profile=mcp-app"
	maxExtensionPages = 2
	maxExtensionItems = 3
)

type ExtensionConsistencyExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-extension-consistency", func(rc attack.RuleContext) attack.Executor {
		return &ExtensionConsistencyExecutor{rule: rc}
	})
}

func NewExtensionConsistencyExecutor(rc attack.RuleContext) *ExtensionConsistencyExecutor {
	return &ExtensionConsistencyExecutor{rule: rc}
}

func (e *ExtensionConsistencyExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	var session mcpSession
	for _, endpoint := range modernDiscoveryEndpoints(vars.BaseURL, "") {
		candidate, ok, _ := discoverModernWithCaps(ctx, client, endpoint, appsClientCapabilities())
		if ok {
			session = candidate
			break
		}
	}
	if session.Endpoint == "" {
		return nil, fmt.Errorf("%w: modern MCP discovery did not complete", attack.ErrInconclusive)
	}
	capabilities := extensionObject(session.RawInit)
	var findings []attack.Finding
	var incomplete []error
	tested := false
	if _, ok := capabilities[skillsExtension]; ok {
		if !session.ServerSupports("resources") {
			fresh, ok, _ := discoverModernWithCaps(ctx, client, session.Endpoint, appsClientCapabilities())
			if ok {
				_, stillSkills := extensionObject(fresh.RawInit)[skillsExtension]
				if stillSkills && !fresh.ServerSupports("resources") {
					findings = append(findings, e.finding(session.Endpoint, "low", "MCP Skills lacks the Resources capability",
						"The server repeatedly declared MCP Skills without the required Resources capability.",
						"server/discover repeated; Skills advertised, Resources absent"))
					tested = true
				}
			}
			if !tested {
				incomplete = append(incomplete, fmt.Errorf("%w: Skills capability changed during verification", attack.ErrInconclusive))
			}
		} else {
			f, n, err := e.checkSkills(ctx, client, session)
			findings = append(findings, f...)
			tested = tested || n > 0
			if err != nil {
				incomplete = append(incomplete, err)
			} else if n == 0 {
				incomplete = append(incomplete, fmt.Errorf("%w: Skills listing had no static entry to verify", attack.ErrInconclusive))
			}
		}
	}
	if session.ServerSupports("tools") {
		f, n, err := e.checkApps(ctx, client, session)
		findings = append(findings, f...)
		tested = tested || n > 0
		if err != nil {
			incomplete = append(incomplete, err)
		} else if _, declared := capabilities[appsExtension]; declared && n == 0 {
			incomplete = append(incomplete, fmt.Errorf("%w: Apps advertised no UI reference to verify", attack.ErrInconclusive))
		}
	}
	if !tested {
		incomplete = append(incomplete, fmt.Errorf("%w: no Skills entry or Apps UI reference was available to verify", attack.ErrInconclusive))
	}
	return findings, errors.Join(incomplete...)
}

func extensionObject(raw []byte) map[string]interface{} {
	parsed, ok := parseResponseBody(raw)
	if !ok {
		return nil
	}
	result, _ := parsed["result"].(map[string]interface{})
	caps, _ := result["capabilities"].(map[string]interface{})
	extensions, _ := caps["extensions"].(map[string]interface{})
	return extensions
}

func appsClientCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"extensions": map[string]interface{}{appsExtension: map[string]interface{}{"mimeTypes": []string{appsMIME}}},
	}
}

func extensionCall(ctx context.Context, client *attack.HTTPClient, session mcpSession, id int, method string,
	params map[string]interface{}, appsClient bool) (map[string]interface{}, error) {
	headers, body := session.request(id, method, params)
	if appsClient {
		requestParams := body["params"].(map[string]interface{})
		meta := requestParams["_meta"].(map[string]interface{})
		meta[metaClientCapabilities] = appsClientCapabilities()
	}
	resp, err := client.POST(ctx, session.Endpoint, headers, body)
	verdict, envelope := classifyProbe(resp, err, id)
	if verdict != probeAnswered || !validRPCResult(envelope) {
		return nil, fmt.Errorf("%w: %s did not return a successful result", attack.ErrInconclusive, method)
	}
	result, ok := envelope["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return nil, fmt.Errorf("%w: %s returned an invalid result", attack.ErrInconclusive, method)
	}
	return result, nil
}

func appsRead(ctx context.Context, client *attack.HTTPClient, session mcpSession, id int, uri string) (bool, bool) {
	headers, body := session.request(id, "resources/read", map[string]interface{}{"uri": uri})
	meta := body["params"].(map[string]interface{})["_meta"].(map[string]interface{})
	meta[metaClientCapabilities] = appsClientCapabilities()
	resp, err := client.POST(ctx, session.Endpoint, headers, body)
	verdict, envelope := classifyProbe(resp, err, id)
	if verdict != probeAnswered {
		return false, false
	}
	if validRPCError(envelope) {
		rpcErr := envelope["error"].(map[string]interface{})
		return false, rpcErrorCode(rpcErr["code"]) == -32602
	}
	if !validRPCResult(envelope) {
		return false, false
	}
	result, ok := envelope["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return false, false
	}
	return appsReadValid(result, uri), true
}

type skillEntry struct {
	uri, digest string
	size        int64
	dynamic     bool
	valid       bool
}

func parseSkill(value interface{}) skillEntry {
	entry, ok := value.(map[string]interface{})
	if !ok {
		return skillEntry{}
	}
	uri, _ := entry["uri"].(string)
	if uri == "" || !strings.HasSuffix(uri, "/SKILL.md") {
		return skillEntry{}
	}
	front, ok := entry["frontmatter"].(map[string]interface{})
	if !ok {
		return skillEntry{}
	}
	name, _ := front["name"].(string)
	description, _ := front["description"].(string)
	if name == "" || description == "" {
		return skillEntry{}
	}
	if entry["resources"] == "dynamic" {
		return skillEntry{uri: uri, dynamic: true, valid: true}
	}
	resources, ok := entry["resources"].([]interface{})
	if !ok {
		return skillEntry{}
	}
	for _, item := range resources {
		resource, ok := item.(map[string]interface{})
		if !ok || resource["uri"] != uri {
			continue
		}
		digest, _ := resource["digest"].(string)
		if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
			return skillEntry{}
		}
		if _, err := hex.DecodeString(digest[len("sha256:"):]); err != nil || strings.ToLower(digest) != digest {
			return skillEntry{}
		}
		sizeNumber, ok := resource["size"].(json.Number)
		if !ok {
			return skillEntry{}
		}
		size, err := sizeNumber.Int64()
		if err != nil || size < 0 {
			return skillEntry{}
		}
		return skillEntry{uri: uri, digest: digest, size: size, valid: true}
	}
	return skillEntry{}
}

func skillReadMatches(result map[string]interface{}, entry skillEntry) bool {
	contents, ok := result["contents"].([]interface{})
	if !ok {
		return false
	}
	for _, value := range contents {
		item, ok := value.(map[string]interface{})
		if !ok || item["uri"] != entry.uri {
			continue
		}
		var content []byte
		if text, ok := item["text"].(string); ok {
			content = []byte(text)
		} else if blob, ok := item["blob"].(string); ok {
			var err error
			content, err = base64.StdEncoding.DecodeString(blob)
			if err != nil {
				return false
			}
		} else {
			return false
		}
		digest := sha256.Sum256(content)
		return int64(len(content)) == entry.size && "sha256:"+hex.EncodeToString(digest[:]) == entry.digest
	}
	return false
}

func (e *ExtensionConsistencyExecutor) checkSkills(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]attack.Finding, int, error) {
	var findings []attack.Finding
	var incomplete []error
	seen := map[string]bool{}
	seenCursors := map[string]bool{}
	cursor := ""
	tested := 0
	for page := 0; page < maxExtensionPages && tested < maxExtensionItems; page++ {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		list, err := extensionCall(ctx, client, session, 100+page, "skills/list", params, false)
		if err != nil {
			return findings, tested, errors.Join(append(incomplete, err)...)
		}
		items, ok := list["skills"].([]interface{})
		if !ok {
			return findings, tested, errors.Join(append(incomplete, fmt.Errorf("%w: skills/list omitted skills", attack.ErrInconclusive))...)
		}
		for _, value := range items {
			if tested == maxExtensionItems {
				break
			}
			entry := parseSkill(value)
			if !entry.valid || entry.dynamic || seen[entry.uri] {
				continue
			}
			seen[entry.uri] = true
			tested++
			fresh, getErr := extensionCall(ctx, client, session, 110+tested, "skills/get", map[string]interface{}{"uri": entry.uri}, false)
			if getErr != nil {
				incomplete = append(incomplete, getErr)
				continue
			}
			current := parseSkill(fresh["skill"])
			if !current.valid || current.dynamic || current.uri != entry.uri {
				incomplete = append(incomplete, fmt.Errorf("%w: skills/get did not return the listed skill", attack.ErrInconclusive))
				continue
			}
			entry = current
			read, readErr := extensionCall(ctx, client, session, 120+tested, "resources/read", map[string]interface{}{"uri": entry.uri}, false)
			if readErr != nil {
				incomplete = append(incomplete, readErr)
				continue
			}
			if skillReadMatches(read, entry) {
				continue
			}
			fresh, getErr = extensionCall(ctx, client, session, 140+tested, "skills/get", map[string]interface{}{"uri": entry.uri}, false)
			if getErr != nil {
				incomplete = append(incomplete, getErr)
				continue
			}
			current = parseSkill(fresh["skill"])
			if !current.valid || current.dynamic || current != entry {
				incomplete = append(incomplete, fmt.Errorf("%w: Skills manifest changed during verification", attack.ErrInconclusive))
				continue
			}
			readAgain, againErr := extensionCall(ctx, client, session, 160+tested, "resources/read", map[string]interface{}{"uri": entry.uri}, false)
			if againErr != nil {
				incomplete = append(incomplete, againErr)
				continue
			}
			if !skillReadMatches(readAgain, entry) {
				findings = append(findings, e.finding(session.Endpoint, "medium", "MCP Skills content differs from its manifest",
					"A listed SKILL.md did not match its declared size or SHA-256 digest on repeated reads after skills/get returned the same manifest.",
					fmt.Sprintf("skills/list page %d, sampled entry %d; URI and content omitted", page+1, tested)))
			}
		}
		next, _ := list["nextCursor"].(string)
		if next == "" || seenCursors[next] {
			break
		}
		seenCursors[next] = true
		cursor = next
	}
	return findings, tested, errors.Join(incomplete...)
}

func (e *ExtensionConsistencyExecutor) checkApps(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]attack.Finding, int, error) {
	var findings []attack.Finding
	var incomplete []error
	seen := map[string]bool{}
	seenCursors := map[string]bool{}
	cursor := ""
	tested := 0
	for page := 0; page < maxExtensionPages && tested < maxExtensionItems; page++ {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		list, err := extensionCall(ctx, client, session, 200+page, "tools/list", params, true)
		if err != nil {
			return findings, tested, errors.Join(append(incomplete, err)...)
		}
		tools, ok := list["tools"].([]interface{})
		if !ok {
			return findings, tested, errors.Join(append(incomplete, fmt.Errorf("%w: tools/list omitted tools", attack.ErrInconclusive))...)
		}
		for _, value := range tools {
			if tested == maxExtensionItems {
				break
			}
			tool, _ := value.(map[string]interface{})
			meta, _ := tool["_meta"].(map[string]interface{})
			ui, _ := meta["ui"].(map[string]interface{})
			uri, _ := ui["resourceUri"].(string)
			if uri == "" || seen[uri] {
				continue
			}
			seen[uri] = true
			tested++
			valid, judged := false, true
			if strings.HasPrefix(uri, "ui://") {
				valid, judged = appsRead(ctx, client, session, 220+tested, uri)
			}
			if valid {
				continue
			}
			if !judged {
				incomplete = append(incomplete, fmt.Errorf("%w: Apps resource read could not be judged", attack.ErrInconclusive))
				continue
			}
			repeated, repeatErr := extensionCall(ctx, client, session, 240+tested, "tools/list", params, true)
			if repeatErr != nil || !appsListHasURI(repeated, uri) {
				incomplete = append(incomplete, fmt.Errorf("%w: Apps tool reference changed during verification", attack.ErrInconclusive))
				continue
			}
			if strings.HasPrefix(uri, "ui://") {
				valid, judged := appsRead(ctx, client, session, 260+tested, uri)
				if !judged {
					incomplete = append(incomplete, fmt.Errorf("%w: Apps resource read could not be repeated", attack.ErrInconclusive))
					continue
				}
				if valid {
					continue
				}
			}
			findings = append(findings, e.finding(session.Endpoint, "low", "MCP Apps tool references an invalid UI resource",
				"A tool kept the same UI resource reference, but its URI scheme or repeated resource response did not meet the Apps resource format.",
				fmt.Sprintf("tools/list page %d, sampled reference %d; URI and HTML omitted", page+1, tested)))
		}
		next, _ := list["nextCursor"].(string)
		if next == "" || seenCursors[next] {
			break
		}
		seenCursors[next] = true
		cursor = next
	}
	return findings, tested, errors.Join(incomplete...)
}

func appsListHasURI(result map[string]interface{}, uri string) bool {
	tools, _ := result["tools"].([]interface{})
	for _, value := range tools {
		tool, _ := value.(map[string]interface{})
		meta, _ := tool["_meta"].(map[string]interface{})
		ui, _ := meta["ui"].(map[string]interface{})
		if ui["resourceUri"] == uri {
			return true
		}
	}
	return false
}

func appsReadValid(result map[string]interface{}, uri string) bool {
	contents, ok := result["contents"].([]interface{})
	if !ok {
		return false
	}
	for _, value := range contents {
		item, ok := value.(map[string]interface{})
		if !ok || item["uri"] != uri {
			continue
		}
		if item["mimeType"] != appsMIME {
			return false
		}
		_, hasText := item["text"].(string)
		blob, hasBlob := item["blob"].(string)
		if hasBlob {
			_, err := base64.StdEncoding.DecodeString(blob)
			return err == nil
		}
		return hasText
	}
	return false
}

func (e *ExtensionConsistencyExecutor) finding(endpoint, severity, title, description, evidence string) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: severity, Confidence: attack.RiskIndicator,
		Title: title, Description: description, Evidence: evidence,
		Remediation: e.rule.Remediation, TargetURL: endpoint,
	}
}
