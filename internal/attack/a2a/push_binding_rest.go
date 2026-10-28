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

func (e *PushBindingExecutor) probeREST(ctx context.Context, target string, opts attack.Options, randID string) ([]attack.Finding, error, bool) {
	owner := opts.Principals[0]
	vars := attack.NewVars(target, opts.OOBListenerURL)
	clientA := principalClient(opts, vars, owner)
	interfaces := resolveHTTPJSONInterfaces(ctx, clientA, target)
	if len(interfaces) == 0 {
		return nil, nil, false
	}
	var findings []attack.Finding
	var partial error
	taskReached := false
	for baseIndex, iface := range interfaces {
		base := iface.base
		ctx := withHTTPJSONInterface(ctx, iface)
		for _, route := range restPushRoutes {
			routeFindings, routeErr := e.probeRESTRoute(ctx, base, route, opts,
				fmt.Sprintf("%s-%d-%s", randID, baseIndex, route.version), owner, clientA, &taskReached)
			findings = append(findings, routeFindings...)
			partial = errors.Join(partial, routeErr)
		}
	}
	if !taskReached {
		partial = errors.Join(partial, fmt.Errorf("%w: advertised HTTP+JSON task routes were unavailable", attack.ErrInconclusive))
	}
	return findings, partial, true
}

func (e *PushBindingExecutor) probeRESTRoute(ctx context.Context, base string, route restPushRoute,
	opts attack.Options, randID string, owner attack.Principal, clientA *attack.HTTPClient,
	taskReached *bool) (findings []attack.Finding, err error) {
	vars := attack.NewVars(base, opts.OOBListenerURL)
	reader := &PushLifecycleExecutor{}
	ownerHeaders := restVersionHeaders(route.version, owner.Headers)
	if route.version == "1.0" {
		ownerHeaders["Content-Type"] = "application/a2a+json"
	}
	sendURL := endpoint.AppendPath(base, route.sendPath)
	sendResp, sendErr := clientA.POST(ctx, sendURL, ownerHeaders,
		restTaskSendRequest(randID, "batesian push binding probe "+randID, route.version))
	if sendErr != nil || sendResp == nil {
		return nil, fmt.Errorf("%w: REST task creation did not answer", attack.ErrInconclusive)
	}
	if sendResp.StatusCode == http.StatusNotFound || sendResp.StatusCode == http.StatusMethodNotAllowed {
		return nil, nil
	}
	taskID := restPushTaskID(sendResp)
	if taskID == "" {
		return nil, classifyTaskSetup("creating a REST push binding task", sendURL,
			principalCredentialPresent(clientA, sendURL, owner.Headers), sendResp).err()
	}
	*taskReached = true
	if !principalCredentialPresent(clientA, sendURL, owner.Headers) {
		return nil, fmt.Errorf("%w: REST task creation used no owner credential", attack.ErrInconclusive)
	}
	configURL := endpoint.AppendPath(base, route.configPath(taskID))
	if !principalCredentialPresent(clientA, configURL, owner.Headers) {
		return nil, fmt.Errorf("%w: owner REST push registration used no owner credential", attack.ErrInconclusive)
	}
	taskURL := endpoint.AppendPath(base, route.taskPath+"/"+url.PathEscape(taskID))
	markerURL := "https://batesian-victim-" + randID + ".example/cb"
	ownerResp, ownerErr := clientA.POST(ctx, configURL, ownerHeaders,
		restPushConfigRequest(taskID, markerURL, "victim-"+randID, "", randID+"-owner", route.version))
	if ownerErr != nil || ownerResp == nil {
		return nil, fmt.Errorf("%w: owner REST push registration did not answer", attack.ErrInconclusive)
	}
	if ownerResp.StatusCode == http.StatusNotFound || ownerResp.StatusCode == http.StatusMethodNotAllowed {
		return nil, nil
	}
	if !restPushRegistrationReplyAccepted(ownerResp, taskID, markerURL, route.version) {
		return nil, restPushRegistrationOutcome("creating an owner REST push configuration", ownerResp,
			taskID, markerURL, route.version).err()
	}
	registrations := []*pushRegistration{}
	addRegistration := func(reg *pushRegistration) {
		reg.authHeaders = owner.Headers
		registrations = append(registrations, reg)
	}
	defer func() {
		for i := len(registrations) - 1; i >= 0; i-- {
			line := registrations[i].finish(ctx, clientA, opts.TargetState, false)
			for j := range findings {
				findings[j].Evidence += "\n" + line
			}
		}
	}()
	ownerReg := newPushRegistration(configURL, taskID, route.version, markerURL, ownerResp, true)
	addRegistration(ownerReg)
	if !safePushConfigPathID(ownerReg.configID) {
		return nil, fmt.Errorf("%w: owner REST push registration returned no safe configuration ID", attack.ErrInconclusive)
	}
	ownerItemURL := endpoint.AppendPath(configURL, "/"+url.PathEscape(ownerReg.configID))
	if reader.readRESTConfig(ctx, clientA, ownerItemURL, ownerHeaders, taskID, ownerReg.configID,
		markerURL, route.version) != configPresent ||
		reader.readRESTTask(ctx, clientA, taskURL, ownerHeaders, taskID) != taskPresent {
		return nil, fmt.Errorf("%w: owner could not read back the REST task and push config", attack.ErrInconclusive)
	}

	var partial error
	defer func() { err = errors.Join(err, partial) }()
	unauth := attack.NewUnauthHTTPClient(opts, vars)
	if reader.readRESTTask(ctx, unauth, taskURL, restVersionHeaders(route.version, nil), taskID) == taskDenied {
		openURL := "https://batesian-open-" + randID + ".example/cb"
		openReg, judged, writeErr := restBindingWrite(ctx, unauth, configURL, route.version, taskID,
			openURL, "open-"+randID, randID+"-open", nil)
		partial = errors.Join(partial, writeErr)
		if openReg != nil {
			addRegistration(openReg)
			if safePushConfigPathID(openReg.configID) {
				itemURL := endpoint.AppendPath(configURL, "/"+url.PathEscape(openReg.configID))
				if reader.readRESTConfig(ctx, clientA, itemURL, ownerHeaders, taskID, openReg.configID,
					openURL, route.version) == configPresent {
					finding := e.anonymousWriteFinding(configURL, owner, taskID, openURL, false, "GET task")
					finding.Evidence += "\nbinding: HTTP+JSON/" + route.version
					findings = append(findings, finding)
				} else {
					partial = errors.Join(partial, fmt.Errorf("%w: anonymous REST push write was not confirmed by owner readback", attack.ErrInconclusive))
				}
			}
		} else if !judged {
			partial = errors.Join(partial, fmt.Errorf("%w: anonymous REST push write was unjudged", attack.ErrInconclusive))
		}
	} else {
		partial = errors.Join(partial, fmt.Errorf("%w: anonymous REST task-read scope was not confirmed", attack.ErrInconclusive))
	}
	if reader.readRESTConfig(ctx, clientA, ownerItemURL, ownerHeaders, taskID, ownerReg.configID,
		markerURL, route.version) != configPresent {
		return findings, fmt.Errorf("%w: owner REST push marker disappeared before cross-principal checks", attack.ErrInconclusive)
	}
	if len(opts.Principals) < 2 {
		if len(findings) > 0 {
			return findings, nil
		}
		return nil, fmt.Errorf("%w: a second principal is required to test cross-principal access", attack.ErrInconclusive)
	}
	_, other, principalsErr := twoPrincipals(opts)
	if principalsErr != nil {
		return findings, principalsErr
	}
	clientB := principalClient(opts, vars, other)
	otherHeaders := restVersionHeaders(route.version, other.Headers)
	if !principalCredentialPresent(clientB, configURL, other.Headers) {
		return findings, fmt.Errorf("%w: second principal's REST push requests used no credential", attack.ErrInconclusive)
	}
	if reader.readRESTTask(ctx, clientB, taskURL, otherHeaders, taskID) != taskDenied {
		return findings, fmt.Errorf("%w: second principal was not confirmed outside REST task-read scope", attack.ErrInconclusive)
	}
	otherRead, readJudged := restBindingRead(ctx, clientB, ownerItemURL, otherHeaders, taskID,
		ownerReg.configID, markerURL, route.version)
	if otherRead {
		finding := e.readFinding(configURL, owner, other, taskID, markerURL, false, "GET task")
		finding.Evidence += "\nbinding: HTTP+JSON/" + route.version
		findings = append(findings, finding)
	} else if !readJudged {
		partial = errors.Join(partial, fmt.Errorf("%w: cross-principal REST push read was unjudged", attack.ErrInconclusive))
	}
	attackerURL := "https://batesian-attacker-" + randID + ".example/cb"
	attackerReg, judged, writeErr := restBindingWrite(ctx, clientB, configURL, route.version, taskID,
		attackerURL, "attacker-"+randID, randID+"-attacker", other.Headers)
	partial = errors.Join(partial, writeErr)
	if attackerReg != nil {
		addRegistration(attackerReg)
		if safePushConfigPathID(attackerReg.configID) {
			itemURL := endpoint.AppendPath(configURL, "/"+url.PathEscape(attackerReg.configID))
			if reader.readRESTConfig(ctx, clientA, itemURL, ownerHeaders, taskID, attackerReg.configID,
				attackerURL, route.version) == configPresent {
				finding := e.writeFinding(configURL, owner, other, taskID, attackerURL, false, "GET task")
				finding.Evidence += "\nbinding: HTTP+JSON/" + route.version
				findings = append(findings, finding)
			} else {
				partial = errors.Join(partial, fmt.Errorf("%w: cross-principal REST push write was not confirmed by owner readback", attack.ErrInconclusive))
			}
		}
	} else if !judged {
		partial = errors.Join(partial, fmt.Errorf("%w: cross-principal REST push write was unjudged", attack.ErrInconclusive))
	}
	return findings, nil
}

func restBindingWrite(ctx context.Context, client *attack.HTTPClient, configURL, version, taskID,
	callbackURL, token, randID string, headers map[string]string) (*pushRegistration, bool, error) {
	requestHeaders := restVersionHeaders(version, headers)
	if version == "1.0" {
		requestHeaders["Content-Type"] = "application/a2a+json"
	}
	resp, err := client.POST(ctx, configURL, requestHeaders,
		restPushConfigRequest(taskID, callbackURL, token, "", randID, version))
	if err != nil || resp == nil {
		return nil, false, fmt.Errorf("%w: REST push write did not answer", attack.ErrInconclusive)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, true, nil
	}
	if !restPushRegistrationReplyAccepted(resp, taskID, callbackURL, version) {
		return nil, false, fmt.Errorf("%w: REST push write reply did not confirm the callback", attack.ErrInconclusive)
	}
	reg := newPushRegistration(configURL, taskID, version, callbackURL, resp, true)
	if !safePushConfigPathID(reg.configID) {
		return reg, false, fmt.Errorf("%w: REST push write returned no safe configuration ID", attack.ErrInconclusive)
	}
	return reg, true, nil
}

func restBindingRead(ctx context.Context, client *attack.HTTPClient, itemURL string, headers map[string]string,
	taskID, configID, markerURL, version string) (present, judged bool) {
	resp, err := client.GET(ctx, itemURL, headers)
	if err != nil || resp == nil {
		return false, false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound {
		return false, true
	}
	if !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return false, false
	}
	if restLifecycleConfigMatches(resp.Body, taskID, configID, markerURL, version) {
		return true, true
	}
	return false, false
}
