package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/sse"
)

const (
	subscriptionMetaKey   = "io.modelcontextprotocol/subscriptionId"
	subscriptionStreamCap = 1 << 20
	subscriptionEventCap  = 64
)

// SubscriptionScopeExecutor checks an opt-in cross-principal resource update.
type SubscriptionScopeExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("mcp-subscription-scope", func(rc attack.RuleContext) attack.Executor {
		return &SubscriptionScopeExecutor{rule: rc}
	})
}

func NewSubscriptionScopeExecutor(rc attack.RuleContext) *SubscriptionScopeExecutor {
	return &SubscriptionScopeExecutor{rule: rc}
}

func (e *SubscriptionScopeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	probe := opts.MCPSubscriptionProbe
	if probe == nil {
		return nil, fmt.Errorf("%w: configure mcp_subscription_probe with a disposable resource and update tool",
			attack.ErrInconclusive)
	}
	owner, caller, err := subscriptionPrincipals(opts.Principals, probe)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	ownerClient := attack.NewUnauthHTTPClient(opts, vars)
	callerClient := attack.NewUnauthHTTPClient(opts, vars)
	var session mcpSession
	for _, endpoint := range modernDiscoveryEndpoints(vars.BaseURL, "") {
		candidate := mcpSession{Endpoint: endpoint, Era: EraModern}
		result := mrtrPost(ctx, ownerClient, candidate, owner, 1, "server/discover", nil)
		if result.result != nil && result.result["resultType"] == "complete" &&
			modernWireAdvertised(result.raw) && subscriptionCapable(result.result) {
			session = candidate
			break
		}
	}
	if session.Endpoint == "" {
		return nil, fmt.Errorf("%w: the owner could not discover a modern MCP endpoint with resource subscriptions",
			attack.ErrInconclusive)
	}
	params := map[string]interface{}{"uri": probe.ResourceURI}
	before := mrtrPost(ctx, ownerClient, session, owner, 10, "resources/read", params)
	ownerContent := subscriptionContent(before.result, probe.ResourceURI)
	if ownerContent == nil || !mrtrPost(ctx, callerClient, session, caller, 11, "resources/read", params).denied {
		return nil, fmt.Errorf("%w: the owner needs readable content and the caller needs an explicit resource-read denial",
			attack.ErrInconclusive)
	}
	schema, err := subscriptionToolSchema(ctx, ownerClient, session, owner, probe.TriggerTool)
	if err != nil {
		return nil, err
	}
	window := 2 * attack.HTTPTimeout(opts)
	if window > 20*time.Second {
		window = 20 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	ownerStreamClient := rawSSEClient(opts)
	ownerStreamClient.Timeout = 0
	defer ownerStreamClient.CloseIdleConnections()
	callerStreamClient := rawSSEClient(opts)
	callerStreamClient.Timeout = 0
	defer callerStreamClient.CloseIdleConnections()
	ownerStream, denied, err := openSubscription(probeCtx, ownerStreamClient, session, owner, 40, probe.ResourceURI)
	if err != nil || denied || ownerStream == nil || !ownerStream.granted {
		return nil, fmt.Errorf("%w: the owner did not establish a resource update subscription",
			attack.ErrInconclusive)
	}
	defer ownerStream.body.Close()
	callerStream, denied, err := openSubscription(probeCtx, callerStreamClient, session, caller, 41, probe.ResourceURI)
	if denied {
		return nil, fmt.Errorf("%w: the caller subscription was denied without a positive caller authentication control",
			attack.ErrInconclusive)
	}
	if err != nil || callerStream == nil {
		return nil, fmt.Errorf("%w: the caller subscription had no readable acknowledgment",
			attack.ErrInconclusive)
	}
	defer callerStream.body.Close()
	if !subscriptionTrigger(probeCtx, ownerClient, session, owner, schema, probe) {
		return nil, fmt.Errorf("%w: the approved update tool did not return a complete success",
			attack.ErrInconclusive)
	}
	if !ownerStream.updated(probe.ResourceURI) {
		return nil, fmt.Errorf("%w: the owner received no matching resource update in the bounded window",
			attack.ErrInconclusive)
	}
	after := mrtrPost(probeCtx, ownerClient, session, owner, 51, "resources/read", params)
	updatedContent := subscriptionContent(after.result, probe.ResourceURI)
	if updatedContent == nil || bytes.Equal(ownerContent, updatedContent) ||
		!mrtrPost(probeCtx, callerClient, session, caller, 52, "resources/read", params).denied {
		return nil, fmt.Errorf("%w: the resource content did not change or the caller's read denial did not persist",
			attack.ErrInconclusive)
	}
	if !callerStream.updated(probe.ResourceURI) {
		return nil, fmt.Errorf("%w: no cross-principal update was observed in the bounded window",
			attack.ErrInconclusive)
	}
	ack := "included the resource"
	if !callerStream.granted {
		ack = "omitted the resource"
	}
	return []attack.Finding{{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "medium", Confidence: attack.RiskIndicator,
		Title:       "MCP resource update reached a principal denied resource read",
		Description: fmt.Sprintf("%s was denied a read of %s's resource before and after an approved update, but received an update notification for that resource. Check whether subscription access is intended for principals without read access.", caller.name, owner.name),
		Evidence: fmt.Sprintf("wire: MCP %s\nowner: %s\ncaller: %s\nowner resource content: changed after approved tool call\ncaller resource reads: denied before and after\nowner and caller: matching update notifications with their own subscription IDs\ncaller acknowledgment: %s\nresource URI, content, and tool arguments omitted",
			modernEraVersion, owner.name, caller.name, ack),
		Remediation: e.rule.Remediation, TargetURL: session.Endpoint,
	}}, nil
}

func subscriptionPrincipals(configured []attack.Principal, probe *attack.MCPSubscriptionProbe) (taskPrincipal, taskPrincipal, error) {
	var owner, caller taskPrincipal
	if probe.Owner == probe.Caller || probe.Owner == "" || probe.Caller == "" {
		return owner, caller, fmt.Errorf("%w: subscription probe needs distinct named principals", attack.ErrInconclusive)
	}
	for _, p := range configured {
		var err error
		switch p.Name {
		case probe.Owner:
			owner, err = configuredTaskPrincipal(p)
		case probe.Caller:
			caller, err = configuredTaskPrincipal(p)
		}
		if err != nil {
			return owner, caller, err
		}
	}
	if owner.name == "" || caller.name == "" || len(principalIdentityHeaders(owner)) == 0 ||
		len(principalIdentityHeaders(caller)) == 0 || samePrincipalIdentity(owner, caller) {
		return owner, caller, fmt.Errorf("%w: subscription probe needs two distinct configured identities",
			attack.ErrInconclusive)
	}
	return owner, caller, nil
}

func subscriptionCapable(result map[string]interface{}) bool {
	caps, _ := result["capabilities"].(map[string]interface{})
	resources, _ := caps["resources"].(map[string]interface{})
	return resources["subscribe"] == true
}

func subscriptionContent(result map[string]interface{}, uri string) []byte {
	content := mrtrContents(result)
	if content == nil {
		return nil
	}
	items, _ := result["contents"].([]interface{})
	for _, raw := range items {
		item, _ := raw.(map[string]interface{})
		if item["uri"] != uri {
			return nil
		}
	}
	return content
}

func subscriptionToolSchema(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	owner taskPrincipal, name string) (map[string]interface{}, error) {
	seen := map[string]bool{}
	var params map[string]interface{}
	for page := 0; page < toolListPageCap; page++ {
		result := mrtrPost(ctx, client, session, owner, 20+page, "tools/list", params).result
		if result == nil || result["resultType"] != "complete" {
			break
		}
		tools, ok := result["tools"].([]interface{})
		if !ok {
			break
		}
		for _, raw := range tools {
			tool, ok := raw.(map[string]interface{})
			if !ok || tool["name"] != name {
				continue
			}
			schema, ok := tool["inputSchema"].(map[string]interface{})
			if ok {
				return schema, nil
			}
			break
		}
		cursor, more, valid := resourcesListCursor(result)
		if !valid || !more || seen[cursor] {
			break
		}
		seen[cursor] = true
		params = map[string]interface{}{"cursor": cursor}
	}
	return nil, fmt.Errorf("%w: the owner could not list the exact approved update tool with an input schema",
		attack.ErrInconclusive)
}

func subscriptionTrigger(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	owner taskPrincipal, schema map[string]interface{}, probe *attack.MCPSubscriptionProbe) bool {
	params := map[string]interface{}{"name": probe.TriggerTool, "arguments": probe.TriggerArguments}
	headers, body, err := session.toolRequest(50, params, schema)
	if err != nil {
		return false
	}
	identity := map[string]string{}
	attachPrincipal(identity, owner)
	for key, value := range headers {
		identity[key] = value
	}
	resp, err := client.POST(ctx, session.Endpoint, identity, body)
	verdict, envelope := classifyProbe(resp, err, 50)
	if verdict != probeAnswered || !validRPCResult(envelope) {
		return false
	}
	result, _ := envelope["result"].(map[string]interface{})
	return result["resultType"] == "complete" && result["isError"] != true
}

type subscriptionStream struct {
	body    io.ReadCloser
	reader  *sse.Reader
	id      int
	granted bool
}

func openSubscription(ctx context.Context, client *http.Client, session mcpSession,
	principal taskPrincipal, id int, uri string) (*subscriptionStream, bool, error) {
	headers, body := session.request(id, "subscriptions/listen", map[string]interface{}{
		"notifications": map[string]interface{}{"resourceSubscriptions": []string{uri}},
	})
	identity := map[string]string{}
	attachPrincipal(identity, principal)
	for key, value := range headers {
		identity[key] = value
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, session.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	for key, value := range identity {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, true, nil
	}
	mediaType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "text/event-stream" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if subscriptionAuthError(body, id) {
			return nil, true, nil
		}
		return nil, false, errors.New("subscription did not return an SSE stream")
	}
	stream := &subscriptionStream{
		body: resp.Body, reader: sse.NewReaderSize(io.LimitReader(resp.Body, subscriptionStreamCap), 64<<10), id: id,
	}
	event, err := stream.reader.Next()
	if err != nil {
		resp.Body.Close()
		return nil, false, err
	}
	if subscriptionAuthError([]byte(event.Data), id) {
		resp.Body.Close()
		return nil, true, nil
	}
	var frame struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Meta          map[string]json.RawMessage `json:"_meta"`
			Notifications struct {
				ResourceSubscriptions []string `json:"resourceSubscriptions"`
			} `json:"notifications"`
		} `json:"params"`
	}
	if json.Unmarshal([]byte(event.Data), &frame) != nil || frame.JSONRPC != "2.0" ||
		frame.Method != "notifications/subscriptions/acknowledged" || !subscriptionIDMatches(frame.Params.Meta, id) {
		resp.Body.Close()
		return nil, false, errors.New("subscription acknowledgment was missing or uncorrelated")
	}
	for _, acknowledged := range frame.Params.Notifications.ResourceSubscriptions {
		if acknowledged == uri {
			stream.granted = true
		}
	}
	return stream, false, nil
}

func (stream *subscriptionStream) updated(uri string) bool {
	for range subscriptionEventCap {
		event, err := stream.reader.Next()
		if err != nil {
			return false
		}
		var frame struct {
			JSONRPC string `json:"jsonrpc"`
			Method  string `json:"method"`
			Params  struct {
				Meta map[string]json.RawMessage `json:"_meta"`
				URI  string                     `json:"uri"`
			} `json:"params"`
		}
		if json.Unmarshal([]byte(event.Data), &frame) == nil && frame.JSONRPC == "2.0" &&
			frame.Method == "notifications/resources/updated" && frame.Params.URI == uri &&
			subscriptionIDMatches(frame.Params.Meta, stream.id) {
			return true
		}
	}
	return false
}

func subscriptionIDMatches(meta map[string]json.RawMessage, id int) bool {
	var actual int
	return json.Unmarshal(meta[subscriptionMetaKey], &actual) == nil && actual == id
}

func subscriptionAuthError(raw []byte, id int) bool {
	body, ok := parseResponseBody(raw)
	if !ok || !matchesRPCID(body, id) || !validRPCError(body) {
		return false
	}
	rpcErr := body["error"].(map[string]interface{})
	message, _ := rpcErr["message"].(string)
	return authFlavoredError(rpcErrorCode(rpcErr["code"]), message)
}
