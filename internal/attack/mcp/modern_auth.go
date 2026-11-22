package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

type modernAuthGate struct {
	method string
	ready  bool
}

var modernAuthMethods = []string{"tools/list", "resources/list", "prompts/list", "ping"}

func probeModernAuthGate(ctx context.Context, anon *attack.HTTPClient, ep string) modernAuthGate {
	session := mcpSession{Endpoint: ep, Era: EraModern}
	resp, err := session.post(ctx, anon, 1, "server/discover", nil)
	if err != nil || resp == nil {
		return modernAuthGate{}
	}
	verdict := classifyAccess(resp, err, 1)
	if verdict == accessRefused && authRefusal(resp) && hasBearerChallenge(resp) {
		return modernAuthGate{method: "server/discover", ready: true}
	}
	if verdict != accessGranted || !modernAuthResult(resp.Body, "server/discover") {
		return modernAuthGate{}
	}
	for _, method := range modernAuthMethods {
		resp, err := session.post(ctx, anon, 2, method, nil)
		if classifyAccess(resp, err, 2) == accessRefused && authRefusal(resp) {
			return modernAuthGate{method: method, ready: true}
		}
	}
	return modernAuthGate{}
}

func hasBearerChallenge(resp *attack.Response) bool {
	if resp == nil {
		return false
	}
	for _, challenge := range authChallenges(resp.Headers) {
		if strings.EqualFold(challenge.scheme, "Bearer") {
			return true
		}
	}
	return false
}

func probeModernBearer(ctx context.Context, anon *attack.HTTPClient, ep, method, token string) (*attack.Response, accessVerdict) {
	session := mcpSession{Endpoint: ep, Era: EraModern}
	resp, err := session.postShaping(ctx, anon, 3, method, nil, func(headers map[string]string) {
		headers["Authorization"] = "Bearer " + token
	})
	switch classifyAccess(resp, err, 3) {
	case accessGranted:
		if modernAuthResult(resp.Body, method) {
			return resp, accessGranted
		}
		return resp, accessUndetermined
	case accessRefused:
		if authRefusal(resp) {
			return resp, accessRefused
		}
	}
	return resp, accessUndetermined
}

func modernAuthResult(raw []byte, method string) bool {
	body, ok := parseResponseBody(raw)
	if !ok {
		return false
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return false
	}
	switch method {
	case "server/discover":
		_, ok = result["capabilities"].(map[string]interface{})
		return ok && modernWireAdvertised(raw)
	case "tools/list":
		_, ok = result["tools"].([]interface{})
	case "resources/list":
		_, ok = result["resources"].([]interface{})
	case "prompts/list":
		_, ok = result["prompts"].([]interface{})
	case "ping":
		return true
	default:
		return false
	}
	return ok
}

func authRefusal(resp *attack.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return true
	}
	if !isJSONRPCError(resp.BodyString()) {
		return false
	}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &envelope) != nil {
		return false
	}
	message := strings.ToLower(envelope.Error.Message)
	return strings.Contains(message, "unauthorized") ||
		strings.Contains(message, "invalid_token") ||
		strings.Contains(message, "forbidden") ||
		strings.Contains(message, "authentication required")
}
