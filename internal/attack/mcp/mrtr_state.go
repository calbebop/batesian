package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/calbebop/batesian/internal/attack"
)

const maxMRTRResourceReads = 5
const maxMRTRResourceListPages = 3
const maxMRTRStateBytes = 4096

// MRTRStateExecutor checks whether resource request state crosses principals.
type MRTRStateExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-mrtr-state", func(rc attack.RuleContext) attack.Executor {
		return &MRTRStateExecutor{rule: rc}
	})
}

func NewMRTRStateExecutor(rc attack.RuleContext) *MRTRStateExecutor {
	return &MRTRStateExecutor{rule: rc}
}

type mrtrReply struct {
	result map[string]interface{}
	raw    []byte
	denied bool
}

func (e *MRTRStateExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	a, b, err := mrtrPrincipals(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewUnauthHTTPClient(opts, vars)

	var session mcpSession
	for _, endpoint := range modernDiscoveryEndpoints(vars.BaseURL, "") {
		candidate := mcpSession{Endpoint: endpoint, Era: EraModern}
		reply := mrtrPost(ctx, client, candidate, a, 1, "server/discover", nil)
		if reply.result == nil || reply.result["resultType"] != "complete" || !modernWireAdvertised(reply.raw) {
			continue
		}
		candidate.RawInit = reply.raw
		if candidate.ServerSupports("resources") {
			session = candidate
			break
		}
	}
	if session.Endpoint == "" {
		return nil, fmt.Errorf("%w: principal %s could not discover a modern MCP resource endpoint at %s",
			attack.ErrInconclusive, a.name, vars.BaseURL)
	}
	listed := mrtrPost(ctx, client, session, a, 2, "resources/list", nil)
	uris, listErr := mrtrResourceURIs(ctx, client, session, a, listed.result)
	if len(uris) == 0 {
		return nil, fmt.Errorf("%w: principal %s had no comparable listed resources on the modern wire",
			attack.ErrInconclusive, a.name)
	}

	var incomplete []error
	if listErr != nil {
		incomplete = append(incomplete, listErr)
	}
	tested := false
	for i, uri := range uris {
		id := 100 + 6*i
		params := map[string]interface{}{"uri": uri}
		ownerStart := mrtrPost(ctx, client, session, a, id, "resources/read", params)
		state, ok := mrtrInputState(ownerStart.result)
		if !ok {
			continue
		}
		guestBaseline := mrtrPost(ctx, client, session, b, id+1, "resources/read", params)
		if !guestBaseline.denied {
			incomplete = append(incomplete, fmt.Errorf("%w: resources/read baseline for shared state candidate %d did not deny principal %s",
				attack.ErrInconclusive, i+1, b.name))
			continue
		}
		guestRetry := mrtrPost(ctx, client, session, b, id+2, "resources/read",
			map[string]interface{}{"uri": uri, "requestState": state})
		if guestRetry.denied {
			ownerRetry := mrtrPost(ctx, client, session, a, id+3, "resources/read",
				map[string]interface{}{"uri": uri, "requestState": state})
			if mrtrContents(ownerRetry.result) != nil {
				tested = true
			} else {
				incomplete = append(incomplete, fmt.Errorf("%w: the owner's request state did not complete candidate %d",
					attack.ErrInconclusive, i+1))
			}
			continue
		}
		guestContent := mrtrContents(guestRetry.result)
		if guestContent == nil {
			incomplete = append(incomplete, fmt.Errorf("%w: principal %s's state retry returned no comparable resource for candidate %d",
				attack.ErrInconclusive, b.name, i+1))
			continue
		}
		ownerFresh := mrtrPost(ctx, client, session, a, id+4, "resources/read", params)
		freshState, ok := mrtrInputState(ownerFresh.result)
		if !ok {
			incomplete = append(incomplete, fmt.Errorf("%w: the owner could not repeat the state flow for candidate %d",
				attack.ErrInconclusive, i+1))
			continue
		}
		ownerRetry := mrtrPost(ctx, client, session, a, id+5, "resources/read",
			map[string]interface{}{"uri": uri, "requestState": freshState})
		ownerContent := mrtrContents(ownerRetry.result)
		if ownerContent == nil || !bytes.Equal(guestContent, ownerContent) {
			incomplete = append(incomplete, fmt.Errorf("%w: cross-principal and owner results did not match for candidate %d",
				attack.ErrInconclusive, i+1))
			continue
		}
		return []attack.Finding{{
			RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.RiskIndicator,
			Title:       "MCP resource request state allowed a cross-principal read",
			Description: fmt.Sprintf("%s was denied a resource read without request state, then received the same content as %s after presenting that principal's state. If this handoff is not intended, bind request state to the authenticated principal and request. Declare an expected denial to confirm the policy violation.", b.name, a.name),
			Evidence: fmt.Sprintf("wire: MCP %s\nowner: %s\ncaller: %s\nresource: listed candidate %d of %d (URI omitted)\ncaller baseline: denied\ncaller with owner state: complete resource content matching owner retry\nrequest state and content omitted",
				modernEraVersion, a.name, b.name, i+1, len(uris)),
			Remediation: e.rule.Remediation, TargetURL: session.Endpoint,
			Access: &attack.AccessObservation{Operation: attack.MCPResourcesRead, Caller: b.name,
				CallerTenant: b.tenant, Owner: a.name, OwnerTenant: a.tenant},
		}}, errors.Join(incomplete...)
	}
	if !tested {
		incomplete = append(incomplete, fmt.Errorf("%w: no safe, state-only resource flow established a protected control",
			attack.ErrInconclusive))
	}
	return nil, errors.Join(incomplete...)
}

func mrtrPrincipals(opts attack.Options) (taskPrincipal, taskPrincipal, error) {
	if len(opts.Principals) < 2 {
		return taskPrincipal{}, taskPrincipal{}, fmt.Errorf("%w: request-state comparison requires two configured principals",
			attack.ErrInconclusive)
	}
	a, err := configuredTaskPrincipal(opts.Principals[0])
	if err != nil {
		return a, taskPrincipal{}, err
	}
	b, err := configuredTaskPrincipal(opts.Principals[1])
	if err != nil {
		return a, b, err
	}
	if len(principalIdentityHeaders(a)) == 0 || len(principalIdentityHeaders(b)) == 0 || samePrincipalIdentity(a, b) {
		return a, b, fmt.Errorf("%w: request-state comparison requires two distinct principal identities",
			attack.ErrInconclusive)
	}
	return a, b, nil
}

func mrtrPost(ctx context.Context, client *attack.HTTPClient, session mcpSession, p taskPrincipal,
	id int, method string, params map[string]interface{}) mrtrReply {
	headers, body := session.request(id, method, params)
	identity := map[string]string{}
	attachPrincipal(identity, p)
	for key, value := range headers {
		identity[key] = value
	}
	resp, err := client.POST(ctx, session.Endpoint, identity, body)
	if err != nil || resp == nil {
		return mrtrReply{}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return mrtrReply{denied: true}
	}
	verdict, envelope := classifyProbe(resp, nil, id)
	if verdict != probeAnswered {
		return mrtrReply{}
	}
	if validRPCError(envelope) {
		rpcErr := envelope["error"].(map[string]interface{})
		message, _ := rpcErr["message"].(string)
		return mrtrReply{denied: authFlavoredError(rpcErrorCode(rpcErr["code"]), message)}
	}
	if !validRPCResult(envelope) {
		return mrtrReply{}
	}
	result, _ := envelope["result"].(map[string]interface{})
	return mrtrReply{result: result, raw: resp.Body}
}

func mrtrListedURIs(result map[string]interface{}) ([]string, bool) {
	if result == nil || result["resultType"] != "complete" {
		return nil, false
	}
	items, ok := result["resources"].([]interface{})
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return nil, false
		}
		uri, ok := item["uri"].(string)
		if !ok || uri == "" {
			return nil, false
		}
		seen[uri] = true
	}
	uris := make([]string, 0, len(seen))
	for uri := range seen {
		uris = append(uris, uri)
	}
	sort.Strings(uris)
	return uris, true
}

func mrtrResourceURIs(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	owner taskPrincipal, first map[string]interface{}) ([]string, error) {
	var pages [][]string
	seenCursors := map[string]bool{}
	result := first
	for page := range maxMRTRResourceListPages {
		uris, ok := mrtrListedURIs(result)
		if !ok {
			return mrtrSelectURIs(pages), fmt.Errorf("%w: resource list page %d was malformed or unavailable",
				attack.ErrInconclusive, page+1)
		}
		pages = append(pages, uris)
		cursor, more, valid := resourcesListCursor(result)
		if !valid {
			return mrtrSelectURIs(pages), fmt.Errorf("%w: resource list page %d returned an invalid cursor",
				attack.ErrInconclusive, page+1)
		}
		if !more {
			return mrtrSelectURIs(pages), nil
		}
		if seenCursors[cursor] || page+1 == maxMRTRResourceListPages {
			return mrtrSelectURIs(pages), fmt.Errorf("%w: resource listing stopped before the final page",
				attack.ErrInconclusive)
		}
		seenCursors[cursor] = true
		result = mrtrPost(ctx, client, session, owner, 3+page, "resources/list",
			map[string]interface{}{"cursor": cursor}).result
	}
	return mrtrSelectURIs(pages), nil
}

func mrtrSelectURIs(pages [][]string) []string {
	selected := make([]string, 0, maxMRTRResourceReads)
	seen := map[string]bool{}
	maxLength := 0
	for _, page := range pages {
		if len(page) > maxLength {
			maxLength = len(page)
		}
	}
	for index := 0; index < maxLength && len(selected) < maxMRTRResourceReads; index++ {
		for _, page := range pages {
			if index < len(page) && !seen[page[index]] {
				selected = append(selected, page[index])
				seen[page[index]] = true
				if len(selected) == maxMRTRResourceReads {
					break
				}
			}
		}
	}
	return selected
}

func mrtrInputState(result map[string]interface{}) (string, bool) {
	if result == nil || result["resultType"] != "input_required" {
		return "", false
	}
	if raw, present := result["inputRequests"]; present {
		requests, ok := raw.(map[string]interface{})
		if !ok || len(requests) != 0 {
			return "", false
		}
	}
	state, ok := result["requestState"].(string)
	return state, ok && state != "" && len(state) <= maxMRTRStateBytes
}

func mrtrContents(result map[string]interface{}) []byte {
	if result == nil || result["resultType"] != "complete" {
		return nil
	}
	contents, ok := result["contents"].([]interface{})
	if !ok || len(contents) == 0 {
		return nil
	}
	hasContent := false
	for _, raw := range contents {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return nil
		}
		uri, ok := item["uri"].(string)
		if !ok || uri == "" {
			return nil
		}
		if text, ok := item["text"].(string); ok && text != "" {
			hasContent = true
		}
		if blob, ok := item["blob"].(string); ok && blob != "" {
			decoded, err := base64.StdEncoding.DecodeString(blob)
			if err != nil {
				return nil
			}
			hasContent = hasContent || len(decoded) != 0
		}
	}
	if !hasContent {
		return nil
	}
	canonical, err := json.Marshal(contents)
	if err != nil {
		return nil
	}
	return canonical
}
