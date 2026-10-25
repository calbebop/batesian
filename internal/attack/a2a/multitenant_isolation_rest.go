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

func (e *MultiTenantIsolationExecutor) probeREST(ctx context.Context, target, randID string,
	a, b attack.Principal, clientA, clientB, unauthClient *attack.HTTPClient) ([]attack.Finding, error, bool) {
	bases := resolveHTTPJSONBases(ctx, clientA, target)
	if len(bases) == 0 {
		return nil, nil, false
	}
	var findings []attack.Finding
	var incomplete error
	for baseIndex, base := range bases {
		baseTested := false
		for _, route := range restPushRoutes {
			routeFindings, routeErr, tested := e.probeRESTRoute(ctx, base, route,
				fmt.Sprintf("%s-%d-%s", randID, baseIndex, route.version), a, b,
				clientA, clientB, unauthClient)
			findings = append(findings, routeFindings...)
			incomplete = errors.Join(incomplete, routeErr)
			baseTested = baseTested || tested
		}
		if !baseTested {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: advertised HTTP+JSON interface at %s yielded no testable owner tasks",
				attack.ErrInconclusive, base))
		}
	}
	return findings, incomplete, true
}

func (e *MultiTenantIsolationExecutor) probeRESTRoute(ctx context.Context, base string, route restPushRoute,
	randID string, a, b attack.Principal, clientA, clientB, unauthClient *attack.HTTPClient) ([]attack.Finding, error, bool) {
	sendURL := endpoint.AppendPath(base, route.sendPath)
	markers := [2]string{
		"batesian mt probe " + a.Name + " " + randID,
		"batesian mt probe " + b.Name + " " + randID,
	}
	owners := [2]attack.Principal{a, b}
	clients := [2]*attack.HTTPClient{clientA, clientB}
	var tasks [2]string
	for i := range owners {
		headers := restVersionHeaders(route.version, owners[i].Headers)
		if route.version == "1.0" {
			headers["Content-Type"] = "application/a2a+json"
		}
		resp, err := clients[i].POST(ctx, sendURL, headers,
			restTaskSendRequest(randID+"-"+owners[i].Name, markers[i], route.version))
		if err != nil || resp == nil {
			return nil, fmt.Errorf("%w: REST task creation for %s did not answer", attack.ErrInconclusive, owners[i].Name), false
		}
		if i == 0 && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
			return nil, nil, false
		}
		tasks[i] = restPushTaskID(resp)
		if tasks[i] == "" {
			return nil, classifyTaskSetup("creating a REST task as principal "+owners[i].Name,
				sendURL, principalCredentialPresent(clients[i], sendURL, owners[i].Headers), resp).err(), false
		}
		if !principalCredentialPresent(clients[i], sendURL, owners[i].Headers) {
			return nil, fmt.Errorf("%w: REST task creation for %s used no credential", attack.ErrInconclusive, owners[i].Name), false
		}
	}
	if tasks[0] == tasks[1] {
		return nil, fmt.Errorf("%w: two principals received the same REST task ID", attack.ErrInconclusive), false
	}
	tasksURL := endpoint.AppendPath(base, route.taskPath)
	read := func(client *attack.HTTPClient, headers map[string]string, taskID, marker, _ string) tenantRead {
		readURL := endpoint.AppendPath(tasksURL, "/"+url.PathEscape(taskID))
		u, parseErr := url.Parse(readURL)
		if parseErr != nil {
			return tenantRead{unknown: true}
		}
		query := u.Query()
		query.Set("historyLength", "10")
		u.RawQuery = query.Encode()
		resp, err := client.GET(ctx, u.String(), restVersionHeaders(route.version, headers))
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
		return tenantRead{
			method:   "GET " + route.taskPath + "/{id}",
			location: location,
			response: snippet(resp.Body, 500),
			matched:  matched,
			unknown:  !matched,
		}
	}
	findings, err := e.compareTaskReads(tasksURL, tasks[0], tasks[1], markers[0], markers[1], a, b,
		clientA, clientB, unauthClient, read)
	return findings, err, true
}
