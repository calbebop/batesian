package a2a

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
)

func (e *MultiTenantIsolationExecutor) probeCrossBinding(ctx context.Context, vars attack.Vars,
	owner, reader attack.Principal, ownerClient, readerClient, anonClient *attack.HTTPClient) ([]attack.Finding, error) {
	card, found := fetchDiscoveryCard(ctx, ownerClient, vars.BaseURL)
	rpcInterfaces := jsonRPCInterfaces(card)
	if !found || len(rpcInterfaces) == 0 {
		return nil, nil
	}
	restInterfaces := resolveHTTPJSONInterfaces(ctx, ownerClient, vars.BaseURL)
	if len(restInterfaces) == 0 {
		return nil, nil
	}
	var rpcURL string
	for _, iface := range rpcInterfaces {
		if iface.ProtocolVersion == "1.0" && iface.Tenant == nil &&
			!hasScopedJSONRPCAtURL(rpcInterfaces, pinToTargetOrigin(iface.URL, vars.BaseURL), vars.BaseURL) {
			rpcURL = pinToTargetOrigin(iface.URL, vars.BaseURL)
			break
		}
	}
	var rest httpJSONInterface
	for _, iface := range restInterfaces {
		if iface.version == "1.0" && iface.tenant == nil &&
			!sharedHTTPJSONTenants(restInterfaces, iface.base) {
			rest = iface
			break
		}
	}
	if rpcURL == "" || rest.base == "" {
		return nil, fmt.Errorf("%w: advertised JSON-RPC and HTTP+JSON interfaces have no unambiguous v1.0 pair",
			attack.ErrInconclusive)
	}
	if !principalCredentialPresent(ownerClient, rpcURL, owner.Headers) ||
		!principalCredentialPresent(ownerClient, rest.base, owner.Headers) ||
		!principalCredentialPresent(readerClient, rpcURL, reader.Headers) ||
		!principalCredentialPresent(readerClient, rest.base, reader.Headers) {
		return nil, fmt.Errorf("%w: both principals need credentials on both advertised bindings", attack.ErrInconclusive)
	}

	rpcCtx := withTenantRouting(ctx)
	restCtx := withHTTPJSONInterface(rpcCtx, rest)
	type readFunc func(*attack.HTTPClient, attack.Principal, string, string, string) tenantRead
	rpcRead := func(client *attack.HTTPClient, principal attack.Principal, taskID, marker, phase string) tenantRead {
		return readCrossRPC(rpcCtx, client, rpcURL, principal.Headers, taskID, marker, vars.RandID+"-"+phase)
	}
	restRead := func(client *attack.HTTPClient, principal attack.Principal, taskID, marker, _ string) tenantRead {
		return readCrossREST(restCtx, client, rest.base, principal.Headers, taskID, marker)
	}
	var findings []attack.Finding
	var incomplete error
	for _, direction := range []struct {
		name, source, destination string
		create                    func(*attack.HTTPClient, attack.Principal, string, string) (string, error)
		readSource, readDest      readFunc
	}{
		{"JSON-RPC to HTTP+JSON", rpcURL, rest.base,
			func(client *attack.HTTPClient, principal attack.Principal, marker, suffix string) (string, error) {
				return createCrossRPC(rpcCtx, client, rpcURL, principal, marker, vars.RandID+suffix)
			}, rpcRead, restRead},
		{"HTTP+JSON to JSON-RPC", rest.base, rpcURL,
			func(client *attack.HTTPClient, principal attack.Principal, marker, suffix string) (string, error) {
				return createCrossREST(restCtx, client, rest.base, principal, marker, vars.RandID+suffix)
			}, restRead, rpcRead},
	} {
		marker := "batesian cross-binding " + direction.name + " " + vars.RandID
		taskID, err := direction.create(ownerClient, owner, marker, "-owner")
		if err != nil {
			incomplete = errors.Join(incomplete, err)
			continue
		}
		readerMarker := marker + " reader control"
		readerTaskID, err := direction.create(readerClient, reader, readerMarker, "-reader")
		if err != nil {
			incomplete = errors.Join(incomplete, err)
			continue
		}
		read := func(fn readFunc, client *attack.HTTPClient, principal attack.Principal, phase string) tenantRead {
			return fn(client, principal, taskID, marker, direction.name+"-"+phase)
		}
		readerControl := direction.readSource(readerClient, reader, readerTaskID, readerMarker,
			vars.RandID+"-"+direction.name+"-reader-control")
		sourceOwner := read(direction.readSource, ownerClient, owner, "source-owner")
		sourceOther := read(direction.readSource, readerClient, reader, "source-other")
		destOwner := read(direction.readDest, ownerClient, owner, "destination-owner")
		destOther := read(direction.readDest, readerClient, reader, "destination-other")
		destAnon := read(direction.readDest, anonClient, attack.Principal{}, "destination-anonymous")
		if readerControl.location == "" || sourceOwner.location == "" || destOwner.location == "" {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: task %s lacked a reader control or owner reads on both bindings",
				attack.ErrInconclusive, taskID))
			continue
		}
		if sourceOther.location != "" || destAnon.location != "" {
			continue
		}
		if !sourceOther.denied || sourceOther.unknown || !destAnon.denied || destAnon.unknown {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: task %s lacked a reliable source denial or anonymous destination control",
				attack.ErrInconclusive, taskID))
			continue
		}
		if destOther.location != "" {
			findings = append(findings, e.crossBindingFinding(direction.name, direction.source, direction.destination,
				owner, reader, taskID, marker, destOther))
		} else if !destOther.denied || destOther.unknown {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: cross-binding read of task %s was not judged",
				attack.ErrInconclusive, taskID))
		}
	}
	return findings, incomplete
}

func hasScopedJSONRPCAtURL(interfaces []a2aDiscoveryInterface, selectedURL, baseURL string) bool {
	for _, iface := range interfaces {
		if iface.Tenant != nil && pinToTargetOrigin(iface.URL, baseURL) == selectedURL {
			return true
		}
	}
	return false
}

func createCrossRPC(ctx context.Context, client *attack.HTTPClient, rpcURL string,
	owner attack.Principal, marker, randID string) (string, error) {
	requestID := "batesian-binding-create-rpc-" + randID
	resp, err := client.POST(ctx, rpcURL, restVersionHeaders("1.0", owner.Headers), map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID, "method": "SendMessage",
		"params": map[string]interface{}{
			"configuration": map[string]interface{}{"returnImmediately": true},
			"message": map[string]interface{}{
				"role": 1, "parts": []interface{}{map[string]string{"text": marker}},
				"messageId": requestID,
			},
		},
	})
	if err != nil || !taskSetupReplyAccepted(resp, requestID) {
		return "", fmt.Errorf("%w: JSON-RPC task creation at %s did not return a correlated task", attack.ErrInconclusive, rpcURL)
	}
	taskID, _ := extractTaskContext(resp.Body)
	if taskID == "" {
		return "", fmt.Errorf("%w: JSON-RPC task creation at %s returned no task ID", attack.ErrInconclusive, rpcURL)
	}
	return taskID, nil
}

func createCrossREST(ctx context.Context, client *attack.HTTPClient, base string,
	owner attack.Principal, marker, randID string) (string, error) {
	sendURL := endpoint.AppendPath(base, "/message:send")
	headers := restVersionHeaders("1.0", owner.Headers)
	headers["Content-Type"] = "application/a2a+json"
	resp, err := client.POST(ctx, sendURL, headers, restTaskSendRequest(randID+"-binding-rest", marker, "1.0"))
	if err != nil || resp == nil || !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return "", fmt.Errorf("%w: HTTP+JSON task creation at %s did not return a task", attack.ErrInconclusive, sendURL)
	}
	taskID := restPushTaskID(resp)
	if taskID == "" {
		return "", fmt.Errorf("%w: HTTP+JSON task creation at %s returned no task ID", attack.ErrInconclusive, sendURL)
	}
	return taskID, nil
}

func readCrossRPC(ctx context.Context, client *attack.HTTPClient, rpcURL string, headers map[string]string,
	taskID, marker, phase string) tenantRead {
	requestID := "batesian-binding-get-" + phase
	resp, err := client.POST(ctx, rpcURL, restVersionHeaders("1.0", headers), map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID, "method": "GetTask",
		"params": map[string]interface{}{"id": taskID, "historyLength": 10},
	})
	if err != nil || resp == nil {
		return tenantRead{unknown: true}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound {
		return tenantRead{denied: true}
	}
	if !resp.IsSuccess() {
		return tenantRead{unknown: true}
	}
	_, code, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid {
		return tenantRead{unknown: true}
	}
	if hasError {
		if code == -32001 || errMessageIsAuth(resp.Body) {
			return tenantRead{denied: true}
		}
		return tenantRead{unknown: true}
	}
	location, matched := taskReadMarkerLocation(resp.Body, taskID, marker)
	return tenantRead{method: "GetTask", location: location, response: snippet(resp.Body, 500),
		matched: matched, unknown: location == ""}
}

func readCrossREST(ctx context.Context, client *attack.HTTPClient, base string, headers map[string]string,
	taskID, marker string) tenantRead {
	readURL := endpoint.AppendPath(base, "/tasks/"+url.PathEscape(taskID))
	u, err := url.Parse(readURL)
	if err != nil {
		return tenantRead{unknown: true}
	}
	query := u.Query()
	query.Set("historyLength", "10")
	u.RawQuery = query.Encode()
	resp, err := client.GET(ctx, u.String(), restVersionHeaders("1.0", headers))
	if err != nil || resp == nil {
		return tenantRead{unknown: true}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound {
		return tenantRead{denied: true}
	}
	if !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return tenantRead{unknown: true}
	}
	location, matched := taskMarkerLocation(resp.Body, taskID, marker)
	return tenantRead{method: "GET /tasks/{id}", location: location, response: snippet(resp.Body, 500),
		matched: matched, unknown: location == ""}
}

func (e *MultiTenantIsolationExecutor) crossBindingFinding(direction, source, destination string,
	owner, reader attack.Principal, taskID, marker string, read tenantRead) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.ConfirmedExploit,
		Title: "A2A task content crosses a tenant boundary on another advertised binding",
		Description: fmt.Sprintf("Principal %q (tenant %q) received principal %q's (tenant %q) probe text from task %s through %s. The same principal was denied on the creation binding; the owner read the content on both bindings, and an anonymous destination read was denied.",
			reader.Name, reader.Tenant, owner.Name, owner.Tenant, taskID, read.method),
		Evidence: fmt.Sprintf("direction: %s\nsource: %s\ndestination: %s\nowner: %s (tenant %s)\nreader: %s (tenant %s)\ntask: %s\nowner marker: %s\nsource reader: denied\ndestination anonymous: denied\ndestination response: %s",
			direction, source, destination, owner.Name, owner.Tenant, reader.Name, reader.Tenant,
			taskID, marker, read.response),
		Remediation: e.rule.Remediation, TargetURL: destination,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create task on " + source, Outcome: "owner read probe text on both bindings"},
			{Hop: 2, Principal: reader.Name, Action: "read task on source binding", Outcome: "denied"},
			{Hop: 3, Principal: reader.Name, Action: "read task on destination binding", Outcome: "GRANTED - read owner's probe text"},
		},
	}
}
