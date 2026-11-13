package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

const (
	skillsExtension   = "io.modelcontextprotocol/skills"
	appsExtension     = "io.modelcontextprotocol/ui"
	appsMIME          = "text/html;profile=mcp-app"
	maxExtensionPages = 2
	maxExtensionItems = 3
	maxSkillResources = 8
	maxSkillReadBytes = 1 << 20
	maxSkillWireBytes = 2 << 20
	maxSkillFiles     = 512
	maxSkillSize      = 16 << 20
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
	return extensionCallWithLimit(ctx, client, session, id, method, params, appsClient, 0)
}

func extensionCallWithLimit(ctx context.Context, client *attack.HTTPClient, session mcpSession, id int, method string,
	params map[string]interface{}, appsClient bool, limit int64) (map[string]interface{}, error) {
	headers, body := session.request(id, method, params)
	if appsClient {
		requestParams := body["params"].(map[string]interface{})
		meta := requestParams["_meta"].(map[string]interface{})
		meta[metaClientCapabilities] = appsClientCapabilities()
	}
	var resp *attack.Response
	var err error
	if limit > 0 {
		resp, err = client.POSTLimited(ctx, session.Endpoint, headers, body, limit)
	} else {
		resp, err = client.POST(ctx, session.Endpoint, headers, body)
	}
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

type skillResource struct {
	uri, digest string
	size        int64
}

type skillEntry struct {
	uri       string
	resources []skillResource
	manifest  string
	dynamic   bool
	valid     bool
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
	if !ok || len(resources) == 0 || len(resources) > maxSkillFiles {
		return skillEntry{}
	}
	root := strings.TrimSuffix(uri, "SKILL.md")
	seen := make(map[string]bool, len(resources))
	files := make([]skillResource, 0, len(resources))
	var totalSize int64
	for _, item := range resources {
		resource, ok := item.(map[string]interface{})
		if !ok {
			return skillEntry{}
		}
		fileURI, _ := resource["uri"].(string)
		if fileURI == "" || seen[fileURI] || fileURI != uri && !strings.HasPrefix(fileURI, root) {
			return skillEntry{}
		}
		seen[fileURI] = true
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
		if err != nil || size < 0 || size > maxSkillSize-totalSize {
			return skillEntry{}
		}
		totalSize += size
		files = append(files, skillResource{uri: fileURI, digest: digest, size: size})
	}
	if !seen[uri] {
		return skillEntry{}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].uri == uri {
			return true
		}
		if files[j].uri == uri {
			return false
		}
		return files[i].uri < files[j].uri
	})
	raw, err := json.Marshal(entry)
	if err != nil {
		return skillEntry{}
	}
	return skillEntry{uri: uri, resources: files, manifest: string(raw), valid: true}
}

func sameSkillManifest(a, b skillEntry) bool {
	return a.valid && b.valid && !a.dynamic && !b.dynamic && a.manifest == b.manifest && slices.Equal(a.resources, b.resources)
}

func skillReadMatches(result map[string]interface{}, resource skillResource, remaining int64) (bool, int64, error) {
	contents, ok := result["contents"].([]interface{})
	if !ok {
		return false, 0, fmt.Errorf("%w: skill resource read omitted contents", attack.ErrInconclusive)
	}
	for _, value := range contents {
		item, ok := value.(map[string]interface{})
		if !ok || item["uri"] != resource.uri {
			continue
		}
		var content []byte
		if text, ok := item["text"].(string); ok {
			if int64(len(text)) > remaining {
				return false, 0, fmt.Errorf("%w: skill resource exceeded the read budget", attack.ErrInconclusive)
			}
			content = []byte(text)
		} else if blob, ok := item["blob"].(string); ok {
			if int64(base64.StdEncoding.DecodedLen(len(blob))) > remaining+2 {
				return false, 0, fmt.Errorf("%w: skill resource exceeded the read budget", attack.ErrInconclusive)
			}
			var err error
			content, err = base64.StdEncoding.DecodeString(blob)
			if err != nil {
				return false, 0, fmt.Errorf("%w: skill resource returned invalid base64", attack.ErrInconclusive)
			}
		} else {
			return false, 0, fmt.Errorf("%w: skill resource omitted content", attack.ErrInconclusive)
		}
		if int64(len(content)) > remaining {
			return false, 0, fmt.Errorf("%w: skill resource exceeded the read budget", attack.ErrInconclusive)
		}
		digest := sha256.Sum256(content)
		return int64(len(content)) == resource.size && "sha256:"+hex.EncodeToString(digest[:]) == resource.digest,
			int64(len(content)), nil
	}
	return false, 0, fmt.Errorf("%w: skill resource read omitted the requested URI", attack.ErrInconclusive)
}

func (e *ExtensionConsistencyExecutor) checkSkills(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]attack.Finding, int, error) {
	var findings []attack.Finding
	var incomplete []error
	seen := map[string]bool{}
	seenCursors := map[string]bool{}
	cursor := ""
	tested := 0
	for page := 0; page < maxExtensionPages; page++ {
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
				incomplete = append(incomplete, fmt.Errorf("%w: Skills listing exceeded the entry cap", attack.ErrInconclusive))
				return findings, tested, errors.Join(incomplete...)
			}
			entry := parseSkill(value)
			if !entry.valid {
				incomplete = append(incomplete, fmt.Errorf("%w: Skills listing contained an invalid entry", attack.ErrInconclusive))
				continue
			}
			if entry.dynamic {
				incomplete = append(incomplete, fmt.Errorf("%w: dynamic Skills content cannot be verified", attack.ErrInconclusive))
				continue
			}
			if seen[entry.uri] {
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
			limit := min(len(entry.resources), maxSkillResources)
			if len(entry.resources) > limit {
				incomplete = append(incomplete, fmt.Errorf("%w: Skills manifest exceeded the resource entry cap", attack.ErrInconclusive))
			}
			remaining := int64(maxSkillReadBytes)
			for fileIndex, resource := range entry.resources[:limit] {
				if resource.size > remaining {
					incomplete = append(incomplete, fmt.Errorf("%w: Skills manifest exceeded the read budget", attack.ErrInconclusive))
					continue
				}
				id := 300 + (tested-1)*maxSkillResources*3 + fileIndex*3
				finding, used, checkErr := e.checkSkillResource(ctx, client, session, entry, resource, id, remaining, page+1, tested, fileIndex+1)
				remaining -= used
				if finding != nil {
					findings = append(findings, *finding)
				}
				if checkErr != nil {
					incomplete = append(incomplete, checkErr)
				}
			}
		}
		next, _ := list["nextCursor"].(string)
		if next == "" {
			break
		}
		if seenCursors[next] || page+1 == maxExtensionPages || tested == maxExtensionItems {
			incomplete = append(incomplete, fmt.Errorf("%w: Skills listing walk did not finish", attack.ErrInconclusive))
			break
		}
		seenCursors[next] = true
		cursor = next
	}
	return findings, tested, errors.Join(incomplete...)
}

func (e *ExtensionConsistencyExecutor) checkSkillResource(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, entry skillEntry, resource skillResource, id int, remaining int64,
	page, skillIndex, resourceIndex int) (*attack.Finding, int64, error) {
	read, err := extensionCallWithLimit(ctx, client, session, id, "resources/read",
		map[string]interface{}{"uri": resource.uri}, false, maxSkillWireBytes)
	if err != nil {
		return nil, 0, err
	}
	matches, used, err := skillReadMatches(read, resource, remaining)
	if err != nil || matches {
		return nil, used, err
	}
	if resource.size > remaining-used {
		return nil, used, fmt.Errorf("%w: Skills repeat read exceeded the read budget", attack.ErrInconclusive)
	}
	fresh, err := extensionCall(ctx, client, session, id+1, "skills/get", map[string]interface{}{"uri": entry.uri}, false)
	if err != nil {
		return nil, used, err
	}
	if !sameSkillManifest(parseSkill(fresh["skill"]), entry) {
		return nil, used, fmt.Errorf("%w: Skills manifest changed during verification", attack.ErrInconclusive)
	}
	readAgain, err := extensionCallWithLimit(ctx, client, session, id+2, "resources/read",
		map[string]interface{}{"uri": resource.uri}, false, maxSkillWireBytes)
	if err != nil {
		return nil, used, err
	}
	matches, repeatedBytes, err := skillReadMatches(readAgain, resource, remaining-used)
	used += repeatedBytes
	if err != nil || matches {
		return nil, used, err
	}
	finding := e.finding(session.Endpoint, "medium", "MCP Skills content differs from its manifest",
		"A sampled skill resource repeatedly differed from its declared size or SHA-256 digest while the manifest remained stable.",
		fmt.Sprintf("skills/list page %d, sampled skill %d, resource %d; URI and content omitted", page, skillIndex, resourceIndex))
	return &finding, used, nil
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
