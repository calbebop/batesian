package mcp

import (
	"context"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

// originResponseVerdict distinguishes an Origin rejection from an unanswered probe.
func originResponseVerdict(resp *attack.Response, err error, session mcpSession, modernID string) probeVerdict {
	if err != nil || resp == nil {
		return probeInconclusive
	}
	if resp.StatusCode == http.StatusForbidden {
		return probeRejected
	}
	if !resp.IsSuccess() {
		return probeInconclusive
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok || !validRPCResult(body) {
		return probeInconclusive
	}
	if session.Era == EraModern {
		if body["id"] == modernID && modernWireAdvertised(resp.Body) {
			return probeAnswered
		}
		return probeInconclusive
	}
	if matchesRPCID(body, 1) && initializeSucceeded(resp.Body) {
		return probeAnswered
	}
	return probeInconclusive
}

func closeLegacyOriginProbe(ctx context.Context, client *attack.HTTPClient, endpoint string,
	resp *attack.Response, origin string) {
	if resp == nil || !resp.IsSuccess() || !initializeSucceeded(resp.Body) {
		return
	}
	probe := mcpSession{Endpoint: endpoint, Era: EraLegacy,
		SessionID: resp.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(resp.Body)}
	closeLegacySessionsWith(ctx, client, []mcpSession{probe},
		func(headers map[string]string) { headers["Origin"] = origin })
}
