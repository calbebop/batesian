package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
	protocola2a "github.com/calbebop/batesian/internal/protocol/a2a"
)

// CardSecurityUnenforcedExecutor checks whether an agent enforces the auth
// required by its public Agent Card. Confirmation creates one probe task.
type CardSecurityUnenforcedExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-card-security-unenforced", func(rc attack.RuleContext) attack.Executor {
		return NewCardSecurityUnenforcedExecutor(rc)
	})
}

func NewCardSecurityUnenforcedExecutor(r attack.RuleContext) *CardSecurityUnenforcedExecutor {
	return &CardSecurityUnenforcedExecutor{rule: r}
}

// probeOutcome classifies an unauthenticated core request.
type probeOutcome int

const (
	probeAuthRejected    probeOutcome = iota // HTTP 401/403 or an auth-flavored error: auth enforced
	probeProcessedError                      // reached the handler, returned a non-auth application error
	probeProcessedResult                     // reached the handler, returned a success result envelope
)

type cardSendResult struct {
	taskID    string
	messageID string
}

func (r cardSendResult) accepted() bool { return r.taskID != "" || r.messageID != "" }

func (e *CardSecurityUnenforcedExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Card and task probes must reflect an anonymous caller.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// Fetch the card. Without it there is no declared contract to test against.
	cardBody, ok, cardReadReason := fetchAgentCardBodyWithOutcome(ctx, client, vars.BaseURL)
	withCardReadReason := func(err error) error {
		if cardReadReason == "" {
			return err
		}
		if err == nil {
			err = attack.ErrInconclusive
		}
		return fmt.Errorf("%w: unobserved card read: %s", err, cardReadReason)
	}
	if !ok {
		return nil, withCardReadReason(fmt.Errorf("%w: no agent card was served under %s, and this rule tests the "+
			"card's declared security against what the endpoint actually enforces",
			attack.ErrInconclusive, vars.BaseURL))
	}
	card, ok := parseCard(cardBody)
	if !ok {
		return nil, fmt.Errorf("%w: the agent card served by %s is not parseable JSON, so its "+
			"declared security contract could not be read", attack.ErrInconclusive, vars.BaseURL)
	}
	if err := protocola2a.ValidateSecurityRequirements(cardBody); err != nil {
		return nil, withCardReadReason(fmt.Errorf("%w: invalid Agent Card security metadata: %v", attack.ErrInconclusive, err))
	}

	// Only proceed when the card declares required auth with no anonymous option.
	schemes, required := declaredAuthRequirement(card)
	if !required {
		return nil, withCardReadReason(nil)
	}

	rpcEndpoint, rpcOK := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	var incomplete error
	if rpcOK {
		readOutcome, readErr := e.readTask(ctx, client, rpcEndpoint, "batesian-missing-"+vars.RandID, vars.RandID+"-missing")
		sent, createErr := e.createProbe(ctx, client, rpcEndpoint, vars.RandID)
		if sent.accepted() {
			readBackOutcome := probeAuthRejected
			var readBackErr error
			if sent.taskID != "" {
				readBackOutcome, readBackErr = e.readTask(ctx, client, rpcEndpoint, sent.taskID, vars.RandID+"-created")
			}
			finding := e.finding(rpcEndpoint, schemes, sent, readOutcome != probeAuthRejected,
				readBackOutcome == probeProcessedResult, "SendMessage/message/send", "GetTask/tasks/get")
			if cardReadReason != "" {
				finding.Evidence += "\nunobserved card read: " + cardReadReason
			}
			return []attack.Finding{finding}, withCardReadReason(errors.Join(readErr, createErr, readBackErr))
		}
		incomplete = errors.Join(readErr, createErr)
	} else {
		incomplete = advertisedJSONRPCUnavailable(ctx, client, vars.BaseURL)
	}

	interfaces := resolveHTTPJSONInterfaces(ctx, client, vars.BaseURL)
	for _, iface := range interfaces {
		base := iface.base
		ctx := withHTTPJSONInterface(ctx, iface)
		for _, route := range restPushRoutes {
			sendURL := endpoint.AppendPath(base, route.sendPath)
			missingURL := endpoint.AppendPath(base, route.taskPath+"/batesian-missing-"+vars.RandID)
			readOutcome, readErr := e.readRESTTask(ctx, client, missingURL, "batesian-missing-"+vars.RandID, route.version)
			sent, createErr := e.createRESTProbe(ctx, client, sendURL, vars.RandID, route.version)
			if !sent.accepted() {
				incomplete = errors.Join(incomplete, readErr, createErr)
				continue
			}
			readBackOutcome := probeAuthRejected
			var readBackErr error
			if sent.taskID != "" {
				createdURL := endpoint.AppendPath(base, route.taskPath+"/"+url.PathEscape(sent.taskID))
				readBackOutcome, readBackErr = e.readRESTTask(ctx, client, createdURL, sent.taskID, route.version)
			}
			finding := e.finding(sendURL, schemes, sent, readOutcome != probeAuthRejected,
				readBackOutcome == probeProcessedResult, "POST "+route.sendPath, "GET "+route.taskPath+"/{id}")
			if cardReadReason != "" {
				finding.Evidence += "\nunobserved card read: " + cardReadReason
			}
			return []attack.Finding{finding}, withCardReadReason(errors.Join(incomplete, readErr, createErr, readBackErr))
		}
	}
	if !rpcOK && len(interfaces) == 0 {
		incomplete = errors.Join(incomplete, attack.ErrInconclusive)
	}
	return nil, withCardReadReason(incomplete)
}

func (e *CardSecurityUnenforcedExecutor) createRESTProbe(ctx context.Context, c *attack.HTTPClient,
	sendURL, randID, version string) (cardSendResult, error) {
	headers := restVersionHeaders(version, nil)
	if version == "1.0" {
		headers["Content-Type"] = "application/a2a+json"
	}
	resp, err := c.POST(ctx, sendURL, headers, restTaskSendRequest(randID+"-cardsec-"+version,
		"batesian card-security probe "+randID, version))
	if err != nil || resp == nil {
		return cardSendResult{}, fmt.Errorf("%w: anonymous REST send at %s did not answer", attack.ErrInconclusive, sendURL)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return cardSendResult{}, nil
	}
	if taskID := restPushTaskID(resp); taskID != "" {
		return cardSendResult{taskID: taskID}, nil
	}
	if resp.IsSuccess() && resp.IsJSON() && !isJSONRPCError(resp.Body) {
		if messageID := cardMessageID(resp.Body, true, version, "batesian-"+randID+"-cardsec-"+version); messageID != "" {
			return cardSendResult{messageID: messageID}, nil
		}
	}
	return cardSendResult{}, fmt.Errorf("%w: anonymous REST send at %s returned no valid Task or Message (HTTP %d)",
		attack.ErrInconclusive, sendURL, resp.StatusCode)
}

func (e *CardSecurityUnenforcedExecutor) readRESTTask(ctx context.Context, c *attack.HTTPClient,
	readURL, taskID, version string) (probeOutcome, error) {
	resp, err := c.GET(ctx, readURL, restVersionHeaders(version, nil))
	if err != nil || resp == nil {
		return probeAuthRejected, fmt.Errorf("%w: anonymous REST task read at %s did not answer", attack.ErrInconclusive, readURL)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return probeAuthRejected, nil
	}
	if resp.IsSuccess() && resp.IsJSON() && !isJSONRPCError(resp.Body) {
		if id, _ := taskResultContext(resp.Body); id == taskID {
			return probeProcessedResult, nil
		}
	}
	return probeAuthRejected, fmt.Errorf("%w: anonymous REST task read at %s returned no matching Task (HTTP %d)",
		attack.ErrInconclusive, readURL, resp.StatusCode)
}

// readTask issues an unauthenticated tasks/get for taskID (v1.0 GetTask then v0.3
// tasks/get) and classifies the strongest outcome seen.
func (e *CardSecurityUnenforcedExecutor) readTask(ctx context.Context, c *attack.HTTPClient, endpoint, taskID, randID string) (probeOutcome, error) {
	shapes := []struct {
		method  string
		headers map[string]string
		version string
	}{
		{"GetTask", map[string]string{"A2A-Version": "1.0"}, "v1"},
		{"tasks/get", nil, "v03"},
	}
	outcome := probeAuthRejected
	var incomplete []string
	for _, s := range shapes {
		requestID := "batesian-cardsec-get-" + randID + "-" + s.version
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID, "historyLength": 1},
		})
		if err != nil || resp == nil {
			incomplete = append(incomplete, s.method+" did not answer")
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			continue
		}
		if !resp.IsSuccess() {
			incomplete = append(incomplete, fmt.Sprintf("%s returned HTTP %d", s.method, resp.StatusCode))
			continue
		}
		result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			incomplete = append(incomplete, s.method+" reply did not match its request ID")
			continue
		}
		if hasError {
			if errMessageIsAuth(resp.Body) || code == jsonRPCMethodNotFound || code == a2aUnsupportedOperation {
				continue
			}
			if outcome < probeProcessedError {
				outcome = probeProcessedError
			}
			continue
		}
		var task struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(result, &task) != nil || task.ID != taskID {
			incomplete = append(incomplete, s.method+" returned a different task")
			continue
		}
		outcome = probeProcessedResult
	}
	if len(incomplete) > 0 {
		return outcome, fmt.Errorf("%w: anonymous task read was not judged: %s", attack.ErrInconclusive,
			strings.Join(incomplete, "; "))
	}
	return outcome, nil
}

// createProbe issues an unauthenticated send and accepts a Task or direct Message.
func (e *CardSecurityUnenforcedExecutor) createProbe(ctx context.Context, c *attack.HTTPClient, endpoint, randID string) (cardSendResult, error) {
	shapes := []struct {
		method  string
		headers map[string]string
		message map[string]interface{}
		version string
	}{
		{"SendMessage", map[string]string{"A2A-Version": "1.0"}, map[string]interface{}{
			"role":      1,
			"parts":     []interface{}{map[string]string{"text": "batesian card-security probe " + randID}},
			"messageId": "batesian-cardsec-" + randID,
		}, "v1"},
		{"message/send", nil, map[string]interface{}{
			"role":      "user",
			"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian card-security probe " + randID}},
			"messageId": "batesian-cardsec-" + randID,
		}, "v03"},
	}
	var incomplete []string
	for _, s := range shapes {
		requestID := "batesian-cardsec-send-" + randID + "-" + s.version
		params := map[string]interface{}{"message": s.message}
		if s.method == "SendMessage" {
			params["configuration"] = map[string]interface{}{"returnImmediately": true}
		}
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"method":  s.method,
			"params":  params,
		})
		if err != nil || resp == nil {
			incomplete = append(incomplete, s.method+" did not answer")
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			continue
		}
		if (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) &&
			!json.Valid(resp.Body) {
			continue
		}
		if resp.IsSuccess() || json.Valid(resp.Body) {
			result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
			if !valid {
				incomplete = append(incomplete, s.method+" reply did not match its request ID")
				continue
			}
			if hasError && (errMessageIsAuth(resp.Body) || code == jsonRPCMethodNotFound || code == a2aUnsupportedOperation) {
				continue
			}
			if !hasError && resp.IsSuccess() {
				taskID, _ := extractTaskContext(resp.Body)
				if taskID != "" {
					if len(incomplete) > 0 {
						return cardSendResult{taskID: taskID}, fmt.Errorf("%w: anonymous send was not judged: %s",
							attack.ErrInconclusive, strings.Join(incomplete, "; "))
					}
					return cardSendResult{taskID: taskID}, nil
				}
				version := "0.3.0"
				if s.method == "SendMessage" {
					version = "1.0"
				}
				messageID := cardMessageID(result, version == "1.0", version, "batesian-cardsec-"+randID)
				if messageID != "" {
					if len(incomplete) > 0 {
						return cardSendResult{messageID: messageID}, fmt.Errorf("%w: anonymous send was not judged: %s",
							attack.ErrInconclusive, strings.Join(incomplete, "; "))
					}
					return cardSendResult{messageID: messageID}, nil
				}
				incomplete = append(incomplete, s.method+" returned no valid Task or Message")
				continue
			}
		}
		incomplete = append(incomplete, fmt.Sprintf("%s returned HTTP %d without a task or auth verdict", s.method, resp.StatusCode))
	}
	if len(incomplete) > 0 {
		return cardSendResult{}, fmt.Errorf("%w: anonymous send was not judged: %s", attack.ErrInconclusive, strings.Join(incomplete, "; "))
	}
	return cardSendResult{}, nil
}

func cardMessageID(raw json.RawMessage, wrapped bool, version, sentID string) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return ""
	}
	if wrapped {
		if _, hasTask := fields["task"]; hasTask {
			return ""
		}
		message, ok := fields["message"]
		if !ok || json.Unmarshal(message, &fields) != nil || fields == nil {
			return ""
		}
		raw = message
	} else if _, hasMessage := fields["message"]; hasMessage {
		return ""
	}
	for _, key := range []string{"id", "status", "task"} {
		if _, present := fields[key]; present {
			return ""
		}
	}
	var message struct {
		Kind      string            `json:"kind"`
		MessageID string            `json:"messageId"`
		ContextID string            `json:"contextId"`
		Role      interface{}       `json:"role"`
		Parts     []json.RawMessage `json:"parts"`
		Content   []json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &message) != nil || message.MessageID == "" ||
		message.MessageID == sentID || !cardAgentRole(message.Role, wrapped) {
		return ""
	}
	if version == "1.0" && message.ContextID == "" {
		return ""
	}
	if !wrapped && message.Kind != "message" {
		return ""
	}
	if wrapped && message.Kind != "" {
		return ""
	}
	parts := message.Parts
	if wrapped && version == "0.3.0" {
		parts = message.Content
	}
	if len(parts) == 0 {
		return ""
	}
	for _, part := range parts {
		if !validCardMessagePart(part, version, wrapped) {
			return ""
		}
	}
	return message.MessageID
}

func cardAgentRole(role interface{}, wrapped bool) bool {
	if !wrapped {
		value, ok := role.(string)
		return ok && value == "agent"
	}
	switch value := role.(type) {
	case string:
		return value == "ROLE_AGENT"
	case float64:
		return value == 2
	default:
		return false
	}
}

func validCardMessagePart(raw json.RawMessage, version string, wrapped bool) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	var name string
	for _, key := range []string{"text", "raw", "url", "data", "file"} {
		if value, present := fields[key]; present && string(value) != "null" {
			if name != "" {
				return false
			}
			name = key
		}
	}
	if name == "" {
		return false
	}
	if (version == "1.0" && name == "file") ||
		(version == "0.3.0" && (name == "raw" || name == "url")) {
		return false
	}
	var kind string
	if value, present := fields["kind"]; present {
		if json.Unmarshal(value, &kind) != nil {
			return false
		}
	}
	if version == "0.3.0" && !wrapped && kind != name {
		return false
	}
	if (version == "1.0" || wrapped) && kind != "" {
		return false
	}
	value := fields[name]
	switch name {
	case "text", "raw", "url":
		var s string
		return json.Unmarshal(value, &s) == nil && s != ""
	case "data":
		if version == "1.0" {
			return json.Valid(value)
		}
		var data map[string]json.RawMessage
		return json.Unmarshal(value, &data) == nil && data != nil
	case "file":
		var file map[string]json.RawMessage
		if json.Unmarshal(value, &file) != nil || file == nil {
			return false
		}
		for _, key := range []string{"uri", "bytes", "fileWithUri", "fileWithBytes"} {
			var content string
			if json.Unmarshal(file[key], &content) == nil && content != "" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (e *CardSecurityUnenforcedExecutor) finding(endpoint string, schemes []string, sent cardSendResult,
	readReachable, readBack bool, sendOperation, readOperation string) attack.Finding {
	schemeList := strings.Join(schemes, ", ")
	readLine := "unauthenticated read (" + readOperation + ") of the created task: not confirmed"
	if sent.messageID != "" {
		readLine = "task readback: not applicable to a direct Message response"
	} else if readBack {
		readLine = "unauthenticated read (" + readOperation + ") of the created task: task returned"
	} else if readReachable {
		readLine = "unauthenticated read (" + readOperation + ") path: reachable (not rejected at the auth layer)"
	}
	accepted := fmt.Sprintf("created task %s", sent.taskID)
	evidence := fmt.Sprintf("accepted (created task %s)", sent.taskID)
	if sent.messageID != "" {
		accepted = fmt.Sprintf("returned agent Message %s", sent.messageID)
		evidence = fmt.Sprintf("accepted (agent Message %s)", sent.messageID)
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A agent card declares required authentication but the endpoint serves unauthenticated requests",
		Description: fmt.Sprintf(
			"The agent card declares a security requirement (scheme(s): %s) that a caller MUST satisfy, "+
				"yet an unauthenticated %s at %s %s with no "+
				"credentials presented. The card is the agent's published security contract; the server does "+
				"not enforce it, so any anonymous caller has the access the card says requires "+
				"authentication.", schemeList, sendOperation, endpoint, accepted),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ncard-declared security scheme(s): %s\nunauthenticated %s: %s\n%s",
			endpoint, schemeList, sendOperation, evidence, readLine),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func fetchAgentCardBodyWithOutcome(ctx context.Context, client *attack.HTTPClient, baseURL string) ([]byte, bool, string) {
	primaryURL := endpoint.AppendPath(baseURL, cardPathPrimary)
	primaryBody, _, primaryOK, primaryReason := fetchCardWithOutcome(ctx, client, primaryURL)
	if primaryOK {
		if primaryReason != "" {
			return primaryBody, true, primaryURL + ": " + primaryReason
		}
		return primaryBody, true, ""
	}
	legacyURL := endpoint.AppendPath(baseURL, cardPathLegacy)
	legacyBody, _, legacyOK, legacyReason := fetchCardWithOutcome(ctx, client, legacyURL)
	if legacyOK {
		if primaryReason != "" {
			return legacyBody, true, primaryURL + ": " + primaryReason
		}
		return legacyBody, true, ""
	}
	var reasons []string
	if primaryReason != "" {
		reasons = append(reasons, primaryURL+": "+primaryReason)
	}
	if legacyReason != "" {
		reasons = append(reasons, legacyURL+": "+legacyReason)
	}
	return nil, false, strings.Join(reasons, "; ")
}

// declaredAuthRequirement reports the distinct scheme names a card requires, and
// whether authentication is required with no anonymous alternative. It reads the
// v1.0 securityRequirements list first, then the v0.3 security list. Per OpenAPI
// semantics an empty requirement object ({}) in the list explicitly permits
// anonymous access, so its presence means auth is NOT required.
func declaredAuthRequirement(card map[string]interface{}) (schemes []string, required bool) {
	list := cardSecurityList(card)
	if len(list) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	for _, item := range list {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, false // malformed requirement entry: do not assert a violation
		}
		names, ok := requirementSchemeNames(obj)
		if !ok {
			return nil, false // anonymous access is allowed by this entry
		}
		for _, name := range names {
			if !seen[name] {
				seen[name] = true
				schemes = append(schemes, name)
			}
		}
	}
	sort.Strings(schemes)
	return schemes, true
}

// requirementSchemeNames reads v1.0's nested "schemes" map or v0.3's flat map.
// An empty map permits anonymous access.
func requirementSchemeNames(entry map[string]interface{}) (names []string, ok bool) {
	if len(entry) == 0 {
		return nil, false
	}
	if len(entry) == 1 {
		if inner, isObject := entry["schemes"].(map[string]interface{}); isObject {
			if len(inner) == 0 {
				return nil, false
			}
			for name := range inner {
				names = append(names, name)
			}
			return names, true
		}
	}
	for name := range entry {
		names = append(names, name)
	}
	return names, true
}

// cardSecurityList returns the requirements list, preferring the v1.0
// securityRequirements field and falling back to the v0.3 security field.
func cardSecurityList(card map[string]interface{}) []interface{} {
	if v, ok := card["securityRequirements"].([]interface{}); ok && len(v) > 0 {
		return v
	}
	if v, ok := card["security"].([]interface{}); ok {
		return v
	}
	return nil
}
